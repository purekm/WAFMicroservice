import requests
import time
from detection import _ip_timestamps, _ip_uri_hits
import random
import numpy as np

## 이전 요청으로 인한 오탐 방지용
def clear_rule_cache(): 
    _ip_timestamps.clear()
    _ip_uri_hits.clear()
    print("✅ Rule 캐시 초기화됨:", len(_ip_timestamps))
    
API_URL = "http://127.0.0.1:8000/detect"


def send_request(
    ip: str,
    ua: str,
    accept: str | None = None,
    ja3: str | None = None,
    *,
    extra: dict | None = None,            # ✅ 추가
) -> None:
    """
    단일 요청 전송 후 탐지 결과 출력
      · 필수: ip, ua
      · 선택: accept, ja3
      · extra: req_count / interval / uri / timestamp … 자유롭게 추가
    """
    headers = {"User-Agent": ua}
    if accept:
        headers["Accept"] = accept
    if ja3:
        headers["X-JA3"] = ja3

    # 기본값 세트 — extra가 있으면 덮어쓴다
    payload: dict = {
        "ip"        : ip,
        "headers"   : headers,
        "req_count" : 20,
        "interval"  : 3.0,
        "uri"       : "/index.html",
        "timestamp" : time.time(),
    }
    if extra:
        payload.update(extra)             # ⚡️ 사용자가 넘긴 값으로 override

    resp = requests.post(API_URL, json=payload, timeout=3)
    body = resp.json() if resp.ok else {"anomaly": "HTTP error"}

    print(f"[{ip:<15}] anomaly={body['anomaly']}  ({body.get('method','-')})")


def test_cases() -> None:
    clear_rule_cache()
    now = time.time()           # 공통 타임스탬프

    print("✅ 정상 요청")
    send_request(
        ip="9.9.9.9",
        ua="Mozilla/5.0",
        accept="text/html",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )

    print("\n❗ UA 블랙리스트 (curl)")
    send_request(
        ip="8.8.8.8",
        ua="curl/7.88.1",
        accept="*/*",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )

    print("\n❗ 브라우저 UA + Accept 없음")
    send_request(
        ip="6.6.6.6",
        ua="Mozilla/5.0",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )

    print("\n❗ 국가 차단 테스트 (RU)")
    send_request(
        ip="95.173.136.70",
        ua="Mozilla/5.0",
        accept="text/html",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )

    print("\n❗ 국가 차단 테스트 (CN)")
    send_request(
        ip="1.12.1.1",
        ua="Mozilla/5.0",
        accept="text/html",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )

    print("\n❗ TLS JA3 불일치 (브라우저 UA + curl JA3)")
    send_request(
        ip="5.5.5.5",
        ua="Mozilla/5.0",
        accept="text/html",
        ja3="cd08e31494f04d93a41a9e1dc943e07b",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )

    print("\n❗ TLS JA3 블랙리스트 전용 (ZGrab 해시)")
    send_request(
        ip="4.4.4.4",
        ua="ZGrab/1.x",
        accept="*/*",
        ja3="5d74ab0f9d9e3f4d1c6e89de2a78f638",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/index.html",
            "timestamp": now,
        },
    )


def generate_random_test_cases(n: int = 50):
    clear_rule_cache()
    print(f"\n🧪 랜덤 테스트 케이스 {n}개 생성")

    stats = {"rule": 0, "ml": 0, "normal": 0, "total": 0}

    for _ in range(n):
        # IP는 무작위 (rule 탐지 여부에는 크게 영향 없음)
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

        # ▒ User-Agent 구성
        ua = random.choices(
            population=[
                "Mozilla/5.0",                  # 정상
                "curl/7.88.1",                  # Rule 블랙리스트
                "python-requests/2.25",
                "wget/1.20",
            ],
            weights=[0.5, 0.2, 0.2, 0.1],
            k=1,
        )[0]

        # ▒ Accept 헤더
        accept = random.choices(
            ["text/html", "*/*", None],
            weights=[0.6, 0.2, 0.2],  # 정상 60%
            k=1,
        )[0]

        # ▒ JA3 (일부는 정상)
        ja3 = random.choices(
            [
                None,
                "cd08e31494f04d93a41a29e1dc943e07b",  # curl
                "5d74ab0f9d9e3f4d1c6e89de2a78f638",  # ZGrab
            ],
            weights=[0.7, 0.2, 0.1],
            k=1,
        )[0]

        # ▒ URI
        uri = random.choice(["/", "/checkout", "/cart", "/index.html"])

        # ▒ 트래픽 패턴 (정상 vs 공격) 섞기
        if random.random() < 0.7:
            # 정상 트래픽 분포
            req_count = int(np.clip(np.random.normal(20, 10), 1, 60))
            interval = round(np.clip(np.random.normal(3, 1), 0.2, 10), 2)
        else:
            # 공격 트래픽 분포
            req_count = int(np.clip(np.random.normal(120, 30), 50, 200))
            interval = round(np.clip(np.random.normal(0.5, 0.2), 0.05, 1.5), 2)

        timestamp = time.time()

        # 헤더 구성
        # headers = {"User-Agent": ua}
        # if accept:
        #     headers["Accept"] = accept
        # if ja3:
        #     headers["X-JA3"] = ja3

        payload = {
            "ip": ip,
            # "headers": headers,
            "timestamp": timestamp,
            "req_count": req_count,
            "interval": interval,
            "uri": uri,
        }

        response = requests.post(API_URL, json=payload)
        result = response.json()
        method = result.get("method", "normal")
        stats[method] += 1
        stats["total"] += 1

        print(
            f"[{ip}] UA: {ua} Accept: {accept or '-'} JA3: {ja3 or '-'} "
            f"→ anomaly: {result['anomaly']} ({method})"
        )
        time.sleep(0.05)

    print_summary(stats)



def print_summary(stats):
    print("\n랜덤 테스트 탐지 요약")
    print("-" * 30)
    print(f"총 요청 수        : {stats['total']}")
    print(f"Rule 기반 탐지    : {stats['rule']}")
    print(f"ML 기반 탐지      : {stats['ml']}")
    print(f"정상 요청 (미탐지) : {stats['normal']}")
    print("-" * 30)

if __name__ == "__main__":
    test_cases()
    generate_random_test_cases(30)
