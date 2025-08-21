
"""
고급 L7 룰 기반 방화벽 (가중치 + 즉시 차단 혼합)
──────────────────────────────────────────────
Stages
  0.   경량 즉시 차단 (Content‑Length, 의심 path, REST 스키마 위반)
  1.   브라우저 헤더 프로파일 / UA블랙리스트 → 기본 점수
  2.   IP빈도 (분당 N회)
  3.   GeoIP 국가 차단
  4.   TLS Fingerprint (JA4 > JA3) 블랙리스트·불일치
  5.   GraphQL Depth / Complexity / Introspection
  6.   추가 휴리스틱 점수 (쿠키·리퍼러·언어/국가 등)
최종   누적 점수 ≥ THRESHOLD or 즉시 차단 룰 중 하나라도 True ⇒ anomaly
"""

from __future__ import annotations
import time, json, re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional

# ───────────── 설정 상수 ─────────────
# IP 기반 요청 제한 설정
WINDOW_SEC          = 60        # 시간 윈도우 (초)
IP_THRESHOLD        = 100       # 분당 허용 요청 수
MAX_IP_TRACK        = 500_000   # 추적할 최대 IP 수

# 본문 및 헤더 관련 설정
MAX_BODY_BYTES      = 64 * 1024    # 최대 본문 크기 (64KB)
MIN_HEADER_COUNT    = 6            # 최소 헤더 수
SUSPECT_PATH_TOKENS = ("/wp-", "/phpmyadmin", "/.env", "/etc/passwd", "/manager/html") # 의심스러운 경로 토큰

# GeoIP 설정
GEOIP_DB_PATH       = "data/GeoLite2-Country.mmdb" # GeoIP 데이터베이스 경로
BLOCKED_COUNTRIES   = {"RU", "CN"}                 # 차단할 국가 코드

# TLS 핑거프린트 블랙리스트 (JA3/JA4)
SUSPECT_FP = {
    "cd08e31494f04d93a41a9e1dc943e07b",  # curl
    "5d74ab0f9d9e3f4d1c6e89de2a78f638",  # ZGrab
}

# User-Agent 관련 설정
UA_BLACKLIST        = ("curl", "python-requests", "wget", "zgrab", "nikto", "sqlmap") # 차단할 User-Agent 목록
BROWSER_UA_TOKENS   = ("mozilla", "chrome", "safari", "edge", "firefox") # 브라우저 식별 토큰

# 브라우저별 필수 헤더 프로필
BROWSER_HEADER_PROFILE = {
    "chrome":  {"must": {"sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-ch-ua"}},
    "edge":    {"must": {"sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-ch-ua"}},
    "safari":  {"must": {"sec-fetch-site","sec-fetch-mode","sec-fetch-dest"}},  # ch-ua 제외
    "firefox": {"must": {"accept-language","accept"}},  # sec-fetch-* 없음
}

# GraphQL 관련 설정
GRAPHQL_DEPTH_LIMIT      = 8      # 최대 쿼리 깊이
GRAPHQL_COMPLEXITY_LIMIT = 1000 # 최대 쿼리 복잡도
GRAPHQL_FIELD_WEIGHT_DEF = 5    # 기본 필드 가중치
GRAPHQL_FIELD_WEIGHT_OVR = {"id": 1, "name": 2} # 특정 필드 가중치 재정의

# 점수 가중치 설정
SCORES = {
    # 높음
    "ua_blacklist":            90, # User-Agent 블랙리스트
    "tls_fp_blacklist":        75, # TLS 핑거프린트 블랙리스트
    "ua_tls_mismatch":         55, # User-Agent와 TLS 핑거프린트 불일치
    "method_path_mismatch":    65, # 메소드와 경로 불일치
    # 중간
    "missing_sec_fetch":       30, # Sec-Fetch 헤더 누락
    "too_few_headers":         28, # 헤더 수가 너무 적음
    "no_cookie_same_site":     20, # 동일 사이트에서 쿠키 없음
    "no_referer_same_site":    15, # 동일 사이트에서 리퍼러 없음
    "client_hints_missing":    18, # 클라이언트 힌트 누락
    "lang_geo_mismatch":       15, # 언어와 지역 불일치
    "no_content_type":         25, # Content-Type 헤더 없음
    # 낮음
    "no_accept_browser":       12, # 브라우저에서 Accept 헤더 없음
    "header_order_anomaly":    12, # 헤더 순서 이상
    # 음수 (정상 트래픽으로 간주)
    "has_sec_fetch_all":      -10, # 모든 Sec-Fetch 헤더 존재
    "has_client_hints":       -8,  # 클라이언트 힌트 존재
    "has_cookie_same_site":   -10, # 동일 사이트에서 쿠키 존재
}
FINAL_SCORE_THRESHOLD = 77   # 최종 점수 임계값
MAX_NEGATIVE_BONUS = 20      # 최대 음수 보너스 점수

# ───────────── 내부 상태 변수 ─────────────
_ip_stats: "OrderedDict[str, Dict[str, float|int]]" = OrderedDict() # IP별 요청 통계
_geo_reader = None # GeoIP 판독기
REST_TABLE: list[tuple[re.Pattern,set[str]]] = [] # REST API 스키마 테이블

# ───────────── 유틸리티 함수 ─────────────
def _headers_lower(h: dict) -> dict:
    # 헤더의 키를 소문자로 변환
    return {k.lower(): v for k, v in h.items()}

def _trim_ip_stats():
    # IP 통계 딕셔너리가 최대 크기를 초과하면 가장 오래된 항목 제거
    while len(_ip_stats) > MAX_IP_TRACK:
        _ip_stats.popitem(last=False)

def _load_geo() :
    # GeoIP 데이터베이스 로드
    global _geo_reader
    if _geo_reader is None:
        import geoip2.database
        _geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    return _geo_reader

def _country(ip: str) -> Optional[str]:
    # IP 주소를 국가 코드로 변환
    try:
        return _load_geo().country(ip).country.iso_code
    except Exception:
        return None

def _load_openapi(path="openapi.json"):
    # OpenAPI 스펙을 로드하여 REST API 스키마 생성
    if REST_TABLE: return
    try:
        spec = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return
    param = re.compile(r'{([^/]+)}')
    for p, item in spec["paths"].items():
        REST_TABLE.append((re.compile('^'+param.sub('[^/]+', p)+'$'),
                           {m.lower() for m in item}))
_load_openapi()

# ───────────── Stage 0: 경량 즉시 차단 ─────────────
def stage_light(h, method, path, body_len) -> bool:
    # 가벼운 규칙으로 즉시 차단 여부 결정
    # - 본문 크기 초과
    if body_len > MAX_BODY_BYTES:
        return True
    # - 의심스러운 경로 포함
    if any(tok in path.lower() for tok in SUSPECT_PATH_TOKENS):
        return True
    # - REST 스키마 위반
    if REST_TABLE:
        for rex, methods in REST_TABLE:
            if rex.match(path):
                if method not in methods:
                    return True         # 정의되지 않은 메소드
                break
        else:
            return True               # 정의되지 않은 경로
    return False

# ───────────── Stage 1: 브라우저 헤더/UA 점수 ─────────────
def score_browser(h, score):
    # 브라우저 헤더와 User-Agent를 분석하여 점수 계산
    ua = h.get("user-agent","").lower()
    if not ua:
        return score + 30 # User-Agent가 없는 경우
    if any(b in ua for b in UA_BLACKLIST):
        return score + SCORES["ua_blacklist"] # 블랙리스트에 포함된 경우
    is_browser = any(tok in ua for tok in BROWSER_UA_TOKENS)
    if is_browser and "accept" not in h:
        score += SCORES["no_accept_browser"] # 브라우저인데 Accept 헤더가 없는 경우

    # 브라우저별 필수 헤더 검사
    key = ("chrome" if ("chrome" in ua or "crios" in ua) else
           "edge" if "edg" in ua else
           "safari" if ("safari" in ua and "chrome" not in ua) else
           "firefox" if "firefox" in ua else None)
    if key:
        must = BROWSER_HEADER_PROFILE[key]["must"]
        missing = must - h.keys()
        if missing:
            score += SCORES["missing_sec_fetch"] # 필수 헤더가 누락된 경우
        else:
            score += SCORES["has_sec_fetch_all"] # 필수 헤더가 모두 있는 경우

    # Client-Hints 검사
    if key in ("chrome","edge"):
        if "sec-ch-ua" not in h:
            score += SCORES["client_hints_missing"] # Client-Hints 헤더가 없는 경우
        else:
            score += SCORES["has_client_hints"] # Client-Hints 헤더가 있는 경우
    return score

# ───────────── Stage 2: IP 빈도 검사 ─────────────
def stage_ip(ip, now) -> bool:
    # IP별 요청 빈도를 검사하여 임계값 초과 시 차단
    if not ip: return False
    st = _ip_stats.get(ip)
    if st is None or now - st["start"] > WINDOW_SEC:
        _ip_stats[ip] = {"count":1,"start":now} # 새로운 IP 또는 윈도우 초기화
    else:
        st["count"] += 1 # 요청 수 증가
    _ip_stats.move_to_end(ip)
    if len(_ip_stats) > MAX_IP_TRACK:
        _trim_ip_stats() # IP 통계 정리
    return _ip_stats[ip]["count"] > IP_THRESHOLD # 임계값 초과 여부 반환

# ───────────── Stage 3: GeoIP 검사 ─────────────
def stage_geo(ip) -> bool:
    # IP의 국가를 확인하여 차단 국가 목록에 있는지 검사
    c = _country(ip)
    return c in BLOCKED_COUNTRIES if c else False

# ───────────── Stage 4: TLS 핑거프린트 검사 ─────────────
def stage_tls(h, score):
    # TLS 핑거프린트를 확인하여 블랙리스트에 있거나 비정상적인 경우 점수 부여
    fp = (h.get("x-ja4") or h.get("cloudfront-viewer-ja4-fingerprint") or
          h.get("x-ja3") or h.get("cloudfront-viewer-ja3-fingerprint"))
    if not fp:
        return False, score # 핑거프린트가 없는 경우
    if fp in SUSPECT_FP:
        return True, score + SCORES["tls_fp_blacklist"] # 블랙리스트에 포함된 경우
    ua = h.get("user-agent","").lower()
    if "mozilla" in ua and fp.startswith("cd08e3"):
        score += SCORES["ua_tls_mismatch"] # 브라우저와 핑거프린트가 불일치하는 경우
    return False, score

# ───────────── Stage 5: GraphQL 검사 ─────────────
def _gql_depth_score(node, depth=1):
    # GraphQL 쿼리의 깊이와 복잡도 계산
    d, s = depth, 0
    sel = getattr(node,"selection_set",None)
    if not sel: return d, s
    for child in sel.selections:
        cd, cs = _gql_depth_score(child, depth+1)
        d = max(d, cd)
        s += GRAPHQL_FIELD_WEIGHT_OVR.get(child.name.value, GRAPHQL_FIELD_WEIGHT_DEF) + cs
    return d, s

def stage_graphql(query:str) -> bool:
    # GraphQL 쿼리를 분석하여 비정상적인 요청 차단
    if not query: return False
    if len(query) > MAX_BODY_BYTES:
        return True # 쿼리 크기 초과
    try:
        from graphql import parse
        ast = parse(query)
    except Exception:
        return True # 파싱 실패
    depth, comp = _gql_depth_score(ast)
    if "__schema" in query or "__type" in query:
        return True # Introspection 쿼리 차단
    return depth > GRAPHQL_DEPTH_LIMIT or comp > GRAPHQL_COMPLEXITY_LIMIT # 깊이 또는 복잡도 초과

# ───────────── Stage 6: 추가 점수 계산 ─────────────
def score_extra(h, score, country, same_site, method, body_len):
    # 추가적인 휴리스틱 규칙으로 점수 계산
    if method in ("post","put","patch") and body_len>0 and "content-type" not in h:
        score += SCORES["no_content_type"] # Content-Type 헤더 없음
    if same_site:
        if "cookie" in h:
            score += SCORES["has_cookie_same_site"] # 동일 사이트 쿠키 존재
        else:
            score += SCORES["no_cookie_same_site"] # 동일 사이트 쿠키 없음
        if "referer" not in h:
            score += SCORES["no_referer_same_site"] # 동일 사이트 리퍼러 없음
    if country and "accept-language" in h:
        al = h["accept-language"].lower()
        if (country=="KR" and "ko" not in al) or (country=="JP" and "ja" not in al) or (country=="US" and "en" not in al):
            score += SCORES["lang_geo_mismatch"] # 언어와 지역 불일치
    if len(h) < MIN_HEADER_COUNT:
        score += SCORES["too_few_headers"] # 헤더 수가 너무 적음
    return score

# ───────────── 메인 탐지 함수 ─────────────
def rule_detect(data: dict) -> bool:
    # 입력 데이터를 기반으로 여러 단계를 거쳐 비정상 트래픽 탐지
    now       = float(data.get("timestamp", time.time()))
    ip        = data.get("ip","")
    h_raw     = data.get("headers") or {}
    h         = _headers_lower(h_raw)
    path      = data.get("path","/")
    method    = data.get("method","GET").lower()
    gql_query = data.get("graphql")
    same_site = bool(data.get("same_site", False))
    body_len  = int(data.get("body_length", h.get("content-length",0) or 0))

    # 0) 경량 즉시 차단
    if stage_light(h, method, path, body_len):
        return True

    # 1) 브라우저 프로파일 점수
    score = score_browser(h, 0)

    # 2) IP 빈도 검사
    if stage_ip(ip, now):
        return True

    # 3) GeoIP 검사
    if stage_geo(ip):
        return True
    cn = _country(ip)

    # 4) TLS 핑거프린트 검사
    tls_block, score = stage_tls(h, score)
    if tls_block:
        return True

    # 5) GraphQL 검사
    if gql_query and stage_graphql(gql_query):
        return True

    # 6) 추가 점수 계산
    score_before = score
    score = score_extra(h, score, cn, same_site, method, body_len)
    neg = min(0, score - score_before)
    if neg < -MAX_NEGATIVE_BONUS:
        score = score_before - MAX_NEGATIVE_BONUS

    # 최종 점수가 임계값을 넘는지 확인
    return score >= FINAL_SCORE_THRESHOLD