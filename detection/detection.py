import time
from collections import defaultdict
from typing import Dict


# 탐지 파라미터 (쉽게 조정할 수 있도록 상수화)
WINDOW_SEC      = 60          # 관찰 창(초)
IP_THRESHOLD    = 100         # 분당 허용 요청 수
UA_BLACKLIST    = ("curl", "python-requests", "wget")

# 내부 상태: IP별 카운터
_ip_stats: Dict[str, Dict[str, float | int]] = {}   # {ip: {"count": int, "start": float}}

# 탐지 함수
def detect_anomaly(data: dict) -> bool:
    """
    룰 기반 이상 여부 판단.

    Parameters
    ----------
    data : dict
        • ip (str)            : 요청 IP (필수)
        • user_agent (str, opt): UA 문자열
        • timestamp (float, opt): epoch time (기본: time.time())

    Returns
    -------
    bool
        True  → 이상 트래픽
        False → 정상 트래픽
    """
    ip          = data.get("ip")
    ua          = str(data.get("user_agent", "")).lower()
    now         = float(data.get("timestamp", time.time()))

    # (1) IP별 카운터 갱신
    stat = _ip_stats.get(ip)
    if stat is None or now - stat["start"] > WINDOW_SEC:
        stat = {"count": 0, "start": now}
        _ip_stats[ip] = stat

    stat["count"] += 1

    # (1-a) 분당 요청 수 초과
    if stat["count"] > IP_THRESHOLD:
        return True

    # (2) 블랙리스트 UA
    if any(bad in ua for bad in UA_BLACKLIST):
        return True

    return False