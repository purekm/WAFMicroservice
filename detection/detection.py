"""
detection.py
────────────
• rule_detect(data)  →  bool
    True  = 이상(차단 대상)   False = 정상
• data 예시
    {
        "ip": "1.2.3.4",
        "user_agent": "curl/7.88.1",
        "uri": "/checkout",
        "timestamp": 1720400000.0   # 선택(미지정 시 time.time())
    }
"""

import time
from collections import defaultdict, deque
from typing import Dict

# ───────── 룰 파라미터 ─────────
WINDOW_SEC       = 60
IP_THRESHOLD     = 100               # 분당 허용 요청 수
UA_BLACKLIST     = ("curl", "python-requests", "wget")
SUSPICIOUS_URIS  = {"/checkout", "/cart", "/api/search", "/expensive-endpoint"} #리소스 소모가 큰 엔드포인트
URI_REPEAT_LIMIT = 30                # 동일 URI 반복 허용 횟수

# ───────── 상태 보존용 캐시 ─────────
_ip_timestamps: Dict[str, deque] = defaultdict(deque)        # IP별 요청 시각
_ip_uri_hits: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque)) # 특정 IP 반복 여부 확인

def _prune(q: deque, now: float) -> None:
    """관찰 창 밖의 타임스탬프 제거"""
    while q and now - q[0] > WINDOW_SEC:
        q.popleft()

def rule_detect(data: dict) -> bool:
    """룰 기반 이상 탐지"""
    ip   = data.get("ip")
    ua   = str(data.get("user_agent", "")).lower()
    uri  = data.get("uri", "/")
    now  = float(data.get("timestamp", time.time()))

    # 조건을 순차적으로 탐색하고, 앞 조건에서 이상 요청으로 탐지시 종료
    # 1) IP별 요청 수 제한
    dq = _ip_timestamps[ip]
    dq.append(now)
    _prune(dq, now)
    print(f"[DEBUG] IP={ip}, 요청 수={len(dq)}, UA={ua}")
    
    if len(dq) > IP_THRESHOLD:
        print(f"[RULE] IP 폭주 탐지됨: {ip}")
        return True         

    # 2) 블랙리스트 UA
    if any(bad in ua for bad in UA_BLACKLIST):
        print(f"[RULE] 블랙리스트 UA 탐지됨: {ua}")
        return True

    # 3) 의심 URI 반복
    uri_q = _ip_uri_hits[ip][uri]
    uri_q.append(now)
    _prune(uri_q, now)
    if (uri in SUSPICIOUS_URIS and len(uri_q) > URI_REPEAT_LIMIT) \
       or (len(uri_q) > URI_REPEAT_LIMIT and '?' not in uri):
           print(f"[RULE] URI 반복 탐지됨: {uri}")
           return True

    return False

# 같은 IP 반복 요청
# 이상 UA 탐지
# URI 집중 공격 탐지