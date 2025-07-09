"""
multi_stage_detection.py
────────────────────────
FastAPI·Flask · Lambda 등 어디서든 import-해서 사용할 수 있는
다단계(3-Stage) 룰 기반 이상 트래픽 탐지 모듈.

Stages
  1. User-Agent / Accept 헤더 정합성 + UA 블랙리스트
  2. IP별 요청 빈도(분당) 초과
  3. GeoIP 국가 차단  (MaxMind GeoLite2-Country.mmdb 필요)

사용 예
  from multi_stage_detection import detect_anomaly
  if detect_anomaly(event):  # event = dict(ip=..., headers=...)
      block_request()
"""

from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Dict
import geoip2.database

# ───────────────── 설정(상수) ────────────────────
# Stage-1
UA_BLACKLIST        = ("curl", "python-requests", "wget")
BROWSER_UA_TOKENS   = ("mozilla", "chrome", "safari", "edge", "firefox")

# Stage-2
WINDOW_SEC          = 60        # IP 관찰 창(초)
IP_THRESHOLD        = 100       # IP 당 60초 허용 요청 수

# Stage-3
GEOIP_DB_PATH       = "data/GeoLite2-Country.mmdb"
BLOCKED_COUNTRIES   = {"RU", "CN"}    # ISO-3166 Alpha-2 코드

SUSPECT_JA3 = {
    "5d74ab0f9d9e3f4d1c6e89d…",  # ZGrab
    "cd08e31494f04d93a41a29…",  # curl 7.x
}

# ───────────────── 내부 상태 ─────────────────────
_ip_stats: Dict[str, Dict[str, float | int]] = defaultdict(  # IP 카운터
    lambda: {"count": 0, "start": 0.0}
)

# GeoIP 리더(지연 로딩)
_geoip_reader = None


# ───────────────── Stage-1: UA 검사 ───────────────
def stage1_check_ua(headers: dict) -> bool:
    """
    블랙리스트 UA, 또는 브라우저 UA 같지만 Accept 헤더가 없는 경우 탐지.
    """
    # 헤더 키를 소문자로 정규화
    h = {k.lower(): v for k, v in headers.items()}
    ua = h.get("user-agent", "").lower()

    # 1-A. 블랙리스트
    if any(bad in ua for bad in UA_BLACKLIST):
        return True

    # 1-B. 브라우저 UA + Accept 없음 → 위조 의심
    if any(tok in ua for tok in BROWSER_UA_TOKENS) and "accept" not in h:
        return True

    return False


# ───────────────── Stage-2: IP 빈도 ───────────────
def stage2_check_ip(ip: str, now: float) -> bool:
    """
    WINDOW_SEC 동안 IP별 요청 카운트가 IP_THRESHOLD 초과 시 탐지.
    """
    stat = _ip_stats[ip]
    if now - stat["start"] > WINDOW_SEC:        # 새 윈도()
        stat["count"] = 0
        stat["start"] = now
    stat["count"] += 1
    return stat["count"] > IP_THRESHOLD


# ───────────────── Stage-3: 국가 차단 ────────────
def _load_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:                  # 처음 호출 시 한 번만 로딩
        import geoip2.database
        _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    return _geoip_reader


def stage3_check_country(ip: str) -> bool:
    """
    차단 목록 국가에서 온 IP면 True.
    (DB 없거나 조회 실패 시 False = 통과)
    """
    try:
        reader = _load_geoip_reader()
        country = reader.country(ip).country.iso_code  # 예: "KR"
    except Exception:
        return False
    return country in BLOCKED_COUNTRIES

def stage4_check_ja3(headers: dict) -> bool:
    ja3 = headers.get("x-ja3") or headers.get("cloudfront-viewer-ja3-fingerprint")
    if not ja3:
        return False                      # TLS 없는 HTTP → 통과
    if ja3 in SUSPECT_JA3:                # 블랙리스트
        return True
    # 브라우저 UA인데 JA3가 curl 패턴?  → 위조 가능성
    ua = headers.get("user-agent", "").lower()
    if "mozilla" in ua and ja3.startswith("cd08e3"):
        return True
    return False


# ───────────────── 메인 탐지 함수 ────────────────
def detect_anomaly(data: dict) -> bool:
    """
    Parameters
    ----------
    data : {
        "ip": "1.2.3.4",                     # 필수
        "headers": {...},                    # 필수 (User-Agent, Accept, X-JA3 …)
        "timestamp": 1720140000.0 (opt)      # epoch, 기본 time.time()
    }

    Returns
    -------
    bool  True  → 이상 트래픽
          False → 정상
    """
    # ───────────── 입력 파싱 ─────────────
    ip        = data.get("ip", "")
    raw_h     = data.get("headers") or {}
    headers   = {k.lower(): v for k, v in raw_h.items()}   # ✅ 키 전부 소문자
    now       = float(data.get("timestamp", time.time()))

    # ───────────── 스테이지 호출 ─────────────
    if stage1_check_ua(headers):          # ① UA / Accept 정합성
        return True

    if stage2_check_ip(ip, now):          # ② IP 빈도 초과
        return True

    if stage3_check_country(ip):          # ③ 국가 차단
        return True

    if stage4_check_ja3(headers):         # ④ TLS JA3 블랙리스트 & 불일치
        return True

    # (추가 스테이지가 있으면 이어서 ...)
    return False

