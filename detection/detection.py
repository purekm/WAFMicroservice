"""
multi_stage_detection.py
────────────────────────
다단계 룰 기반 L7 파이어월 (FastAPI · Flask · Lambda 호환)

Stages
  1. User‑Agent / Accept 정합성 + UA 블랙리스트
  2. IP별 분당 요청 수 초과
  3. GeoIP 국가 차단 (MaxMind GeoLite2‑Country.mmdb 필요)
  4. TLS JA3 블랙리스트 & UA‑JA3 불일치
  5. REST 화이트리스트 (경로·메서드 스키마)
  6. GraphQL Depth / Complexity 한도
"""
from __future__ import annotations
import time, json, re
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict
import geoip2.database
from graphql import parse, visit       # pip install graphql-core

# ───────────── Stage‑1: UA/Accept ─────────────
UA_BLACKLIST      = ("curl", "python-requests", "wget")
BROWSER_UA_TOKENS = ("mozilla", "chrome", "safari", "edge", "firefox")

def stage1_check_ua(h: dict) -> bool:
    ua = h.get("user-agent", "").lower()
    if any(b in ua for b in UA_BLACKLIST):
        return True
    if any(tok in ua for tok in BROWSER_UA_TOKENS) and "accept" not in h:
        return True
    return False

# ───────────── Stage‑2: IP 빈도 ─────────────
WINDOW_SEC, IP_THRESHOLD = 60, 100
_ip_stats: Dict[str, Dict[str, float | int]] = defaultdict(lambda: {"count": 0, "start": 0.0})
def stage2_check_ip(ip: str, now: float) -> bool:
    s = _ip_stats[ip]
    if now - s["start"] > WINDOW_SEC:
        s.update(count=0, start=now)
    s["count"] += 1
    return s["count"] > IP_THRESHOLD

# ───────────── Stage‑3: 국가 차단 ─────────────
GEOIP_DB_PATH, BLOCKED = "data/GeoLite2-Country.mmdb", {"RU", "CN"}
_geo = None
def stage3_country(ip: str) -> bool:
    global _geo
    try:
        _geo = _geo or geoip2.database.Reader(GEOIP_DB_PATH)
        return _geo.country(ip).country.iso_code in BLOCKED
    except Exception:
        return False

# ───────────── Stage‑4: TLS JA3 ─────────────
SUSPECT_JA3 = {
    "cd08e31494f04d93a41a9e1dc943e07b",      # curl
    "5d74ab0f9d9e3f4d1c6e89de2a78f638",      # ZGrab
}
def stage4_ja3(h: dict) -> bool:
    ja3 = h.get("x-ja3") or h.get("cloudfront-viewer-ja3-fingerprint")
    if not ja3:
        return False
    if ja3 in SUSPECT_JA3:
        return True
    if "mozilla" in h.get("user-agent", "").lower() and ja3.startswith("cd08e3"):
        return True
    return False

# ───────────── Stage‑5: REST 스키마 ─────────────
# OpenAPI JSON → 경로/메서드 화이트리스트 로딩
REST_TABLE: list[tuple[re.Pattern, set[str]]] = []
def _load_openapi(path="openapi.json"):
    if REST_TABLE: return
    spec = json.loads(Path(path).read_text())
    pat = re.compile(r'{[^/]+}')
    for p, item in spec["paths"].items():
        REST_TABLE.append((re.compile('^'+pat.sub('[^/]+', p)+'$'),
                           {m.lower() for m in item}))
try: _load_openapi()
except FileNotFoundError: pass          # 스키마 없으면 Stage‑5 생략

def stage5_rest(method: str, url_path: str) -> bool:
    for rex, methods in REST_TABLE:
        if rex.match(url_path):
            return method not in methods
    return bool(REST_TABLE)             # 스키마가 있으면 정의 외 경로 차단

# ───────────── Stage‑6: GraphQL 복잡도 ─────────────
DEPTH_LIMIT, COMPLEX_LIMIT = 8, 1_000
FIELD_WEIGHT = defaultdict(lambda: 5, id=1, name=2)

def _depth_score(node, depth=1):
    md, sc = depth, 0
    sel_set = getattr(node, "selection_set", None)
    if not sel_set: return md, sc
    for sel in sel_set.selections:
        cd, cs = _depth_score(sel, depth+1)
        md = max(md, cd)
        sc += FIELD_WEIGHT[sel.name.value] + cs
    return md, sc

def stage6_graphql(query: str) -> bool:
    try:
        ast = parse(query)
    except Exception:
        return True
    depth, score = _depth_score(ast)
    if "__schema" in query or "__type" in query:
        return True
    return depth > DEPTH_LIMIT or score > COMPLEX_LIMIT

# ───────────── 메인 ─────────────
def rule_detect(data: dict) -> bool:
    ip   = data.get("ip", "")
    h    = {k.lower(): v for k, v in (data.get("headers") or {}).items()}
    now  = float(data.get("timestamp", time.time()))
    path = data.get("path", "/")
    mtd  = data.get("method", "get").lower()
    gql  = data.get("graphql")          # GraphQL 요청이라면 스트링

    if stage1_check_ua(h):       return True
    if stage2_check_ip(ip, now): return True
    if stage3_country(ip):       return True
    if stage4_ja3(h):            return True
    if REST_TABLE and stage5_rest(mtd, path): return True
    if gql and stage6_graphql(gql):      return True
    return False
