# multi_stage_detection.py
"""
고급 L7 룰 기반 방화벽 (가중치 + 즉시 차단 혼합)
──────────────────────────────────────────────
Stages
  0.   경량 즉시 차단 (Content‑Length, 의심 path, REST 스키마 위반)
  1.   브라우저 헤더 프로파일 / UA 블랙리스트 → 기본 점수
  2.   IP 빈도 (분당 N회)
  3.   GeoIP 국가 차단
  4.   TLS Fingerprint (JA4 > JA3) 블랙리스트·불일치
  5.   GraphQL Depth / Complexity / Introspection
  6.   추가 휴리스틱 점수 (쿠키·리퍼러·언어/국가 등)
최종   누적 점수 ≥ THRESHOLD  or  즉시 차단 룰 중 하나라도 True ⇒ anomaly
"""

from __future__ import annotations
import time, json, re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional

# ───────────── 설정 상수 ─────────────
# IP Rate limit
WINDOW_SEC          = 60
IP_THRESHOLD        = 100       # 분당 허용 수
MAX_IP_TRACK        = 500_000   # 딕셔너리 상한

# 본문/헤더
MAX_BODY_BYTES      = 64 * 1024    # 64 KB
MIN_HEADER_COUNT    = 6
SUSPECT_PATH_TOKENS = ("/wp-", "/phpmyadmin", "/.env", "/etc/passwd", "/manager/html")

# GeoIP
GEOIP_DB_PATH       = "data/GeoLite2-Country.mmdb"
BLOCKED_COUNTRIES   = {"RU", "CN"}

# TLS FP 블랙리스트 (JA3/JA4)
SUSPECT_FP = {
    "cd08e31494f04d93a41a9e1dc943e07b",  # curl
    "5d74ab0f9d9e3f4d1c6e89de2a78f638",  # ZGrab
}

# User‑Agent
UA_BLACKLIST        = ("curl", "python-requests", "wget", "zgrab", "nikto", "sqlmap")
BROWSER_UA_TOKENS   = ("mozilla", "chrome", "safari", "edge", "firefox")

# 브라우저별 필수 헤더
BROWSER_HEADER_PROFILE = {
    "chrome":  {"must": {"sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-ch-ua"}},
    "edge":    {"must": {"sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-ch-ua"}},
    "safari":  {"must": {"sec-fetch-site","sec-fetch-mode","sec-fetch-dest"}},  # ch-ua 제외
    "firefox": {"must": {"accept-language","accept"}},  # sec-fetch-* 없음
}

# GraphQL
GRAPHQL_DEPTH_LIMIT      = 8
GRAPHQL_COMPLEXITY_LIMIT = 1000
GRAPHQL_FIELD_WEIGHT_DEF = 5
GRAPHQL_FIELD_WEIGHT_OVR = {"id": 1, "name": 2}

# 점수 가중치
SCORES = {
    # High
    "ua_blacklist":            90,
    "tls_fp_blacklist":        75,
    "ua_tls_mismatch":         55,
    "method_path_mismatch":    65,
    # Medium
    "missing_sec_fetch":       30,
    "too_few_headers":         28,
    "no_cookie_same_site":     20,
    "no_referer_same_site":    15,
    "client_hints_missing":    18,
    "lang_geo_mismatch":       15,
    "no_content_type":         25,
    # Low
    "no_accept_browser":       12,
    "header_order_anomaly":    12,
    # Negative (브라우저다움)
    "has_sec_fetch_all":      -10,
    "has_client_hints":       -8,
    "has_cookie_same_site":   -10,
}
FINAL_SCORE_THRESHOLD = 40
MAX_NEGATIVE_BONUS = 20   # 음수 가중치 한계

# ───────────── 내부 상태 ─────────────
_ip_stats: "OrderedDict[str, Dict[str, float|int]]" = OrderedDict()
_geo_reader = None
REST_TABLE: list[tuple[re.Pattern,set[str]]] = []

# ───────────── 유틸 ─────────────
def _headers_lower(h: dict) -> dict:
    return {k.lower(): v for k, v in h.items()}

def _trim_ip_stats():
    while len(_ip_stats) > MAX_IP_TRACK:
        _ip_stats.popitem(last=False)

def _load_geo() :
    global _geo_reader
    if _geo_reader is None:
        import geoip2.database
        _geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    return _geo_reader

def _country(ip: str) -> Optional[str]:
    try:
        return _load_geo().country(ip).country.iso_code
    except Exception:
        return None

def _load_openapi(path="openapi.json"):
    if REST_TABLE: return
    try:
        spec = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return
    param = re.compile(r'{[^/]+}')
    for p, item in spec["paths"].items():
        REST_TABLE.append((re.compile('^'+param.sub('[^/]+', p)+'$'),
                           {m.lower() for m in item}))
_load_openapi()

# ───────────── Stage 0: 경량 즉시 차단 ─────────────
def stage_light(h, method, path, body_len) -> bool:
    if body_len > MAX_BODY_BYTES:
        return True
    if any(tok in path.lower() for tok in SUSPECT_PATH_TOKENS):
        return True
    # REST 스키마 화이트리스트
    if REST_TABLE:
        for rex, methods in REST_TABLE:
            if rex.match(path):
                if method not in methods:
                    return True         # 메서드 불일치
                break
        else:
            return True                 # 정의되지 않은 경로
    return False

# ───────────── Stage 1: 브라우저 헤더/UA ─────────────
def score_browser(h, score):
    ua = h.get("user-agent","").lower()
    if not ua:
        return score + 30
    if any(b in ua for b in UA_BLACKLIST):
        return score + SCORES["ua_blacklist"]
    is_browser = any(tok in ua for tok in BROWSER_UA_TOKENS)
    if is_browser and "accept" not in h:
        score += SCORES["no_accept_browser"]

    # 브라우저별 필수 헤더 검사
    key = ("chrome" if ("chrome" in ua or "crios" in ua) else
           "edge" if "edg" in ua else
           "safari" if ("safari" in ua and "chrome" not in ua) else
           "firefox" if "firefox" in ua else None)
    if key:
        must = BROWSER_HEADER_PROFILE[key]["must"]
        missing = must - h.keys()
        if missing:
            score += SCORES["missing_sec_fetch"]
        else:
            score += SCORES["has_sec_fetch_all"]

    # Client‑Hints
    if key in ("chrome","edge"):
        if "sec-ch-ua" not in h:
            score += SCORES["client_hints_missing"]
        else:
            score += SCORES["has_client_hints"]
    return score

# ───────────── Stage 2: IP 빈도 ─────────────
def stage_ip(ip, now) -> bool:
    if not ip: return False
    st = _ip_stats.get(ip)
    if st is None or now - st["start"] > WINDOW_SEC:
        _ip_stats[ip] = {"count":1,"start":now}
    else:
        st["count"] += 1
    _ip_stats.move_to_end(ip)
    if len(_ip_stats) > MAX_IP_TRACK:
        _trim_ip_stats()
    return _ip_stats[ip]["count"] > IP_THRESHOLD

# ───────────── Stage 3: GeoIP ─────────────
def stage_geo(ip) -> bool:
    c = _country(ip)
    return c in BLOCKED_COUNTRIES if c else False

# ───────────── Stage 4: TLS FP ─────────────
def stage_tls(h, score):
    fp = (h.get("x-ja4") or h.get("cloudfront-viewer-ja4-fingerprint") or
          h.get("x-ja3") or h.get("cloudfront-viewer-ja3-fingerprint"))
    if not fp:
        return False, score
    if fp in SUSPECT_FP:
        return True, score + SCORES["tls_fp_blacklist"]
    ua = h.get("user-agent","").lower()
    if "mozilla" in ua and fp.startswith("cd08e3"):
        score += SCORES["ua_tls_mismatch"]
    return False, score

# ───────────── Stage 5: GraphQL ─────────────
def _gql_depth_score(node, depth=1):
    d, s = depth, 0
    sel = getattr(node,"selection_set",None)
    if not sel: return d, s
    for child in sel.selections:
        cd, cs = _gql_depth_score(child, depth+1)
        d = max(d, cd)
        s += GRAPHQL_FIELD_WEIGHT_OVR.get(child.name.value, GRAPHQL_FIELD_WEIGHT_DEF) + cs
    return d, s

def stage_graphql(query:str) -> bool:
    if not query: return False
    if len(query) > MAX_BODY_BYTES:
        return True
    try:
        from graphql import parse
        ast = parse(query)
    except Exception:
        return True
    depth, comp = _gql_depth_score(ast)
    if "__schema" in query or "__type" in query:
        return True
    return depth > GRAPHQL_DEPTH_LIMIT or comp > GRAPHQL_COMPLEXITY_LIMIT

# ───────────── Stage 6: 추가 점수 ─────────────
def score_extra(h, score, country, same_site, method, body_len):
    if method in ("post","put","patch") and body_len>0 and "content-type" not in h:
        score += SCORES["no_content_type"]
    if same_site:
        if "cookie" in h:
            score += SCORES["has_cookie_same_site"]
        else:
            score += SCORES["no_cookie_same_site"]
        if "referer" not in h:
            score += SCORES["no_referer_same_site"]
    if country and "accept-language" in h:
        al = h["accept-language"].lower()
        if (country=="KR" and "ko" not in al) or (country=="JP" and "ja" not in al) or (country=="US" and "en" not in al):
            score += SCORES["lang_geo_mismatch"]
    if len(h) < MIN_HEADER_COUNT:
        score += SCORES["too_few_headers"]
    return score

# ───────────── detect_anomaly ─────────────
def rule_detect(data: dict) -> bool:
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

    # 2) IP 빈도
    if stage_ip(ip, now):
        return True

    # 3) GeoIP
    if stage_geo(ip):
        return True
    cn = _country(ip)

    # 4) TLS FP
    tls_block, score = stage_tls(h, score)
    if tls_block:
        return True

    # 5) GraphQL
    if gql_query and stage_graphql(gql_query):
        return True

    # 6) 추가 점수
    score_before = score
    score = score_extra(h, score, cn, same_site, method, body_len)
    neg = min(0, score - score_before)
    if neg < -MAX_NEGATIVE_BONUS:
        score = score_before - MAX_NEGATIVE_BONUS

    return score >= FINAL_SCORE_THRESHOLD
