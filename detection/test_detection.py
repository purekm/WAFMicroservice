import requests
import time
from detection import _ip_timestamps, _ip_uri_hits
import random

## 이전 요청으로 인한 오탐 방지용
def clear_rule_cache(): 
    _ip_timestamps.clear()
    _ip_uri_hits.clear()
    print("✅ Rule 캐시 초기화됨:", len(_ip_timestamps))
    
API_URL = "http://127.0.0.1:8000/detect"

def send_request(ip, ua, extra=None):
    if extra is None:
        extra = {}

    payload = {
        "ip": ip,
        "user_agent": ua,
    }
    payload.update(extra)

    response = requests.post(API_URL, json=payload)
    result = response.json()
    print(f"[{ip}] UA: {ua} → anomaly: {result['anomaly']} ({result['method']})")


def test_cases():
    clear_rule_cache()

    print("✅ 정상 요청")
    send_request(
        ip="1.1.1.1",
        ua="Mozilla/5.0",
        extra={
            "req_count": 20,
            "interval": 3.0,
            "uri": "/home",
            "timestamp": time.time()
        }
    )

    print("\n❗ 비정상 UA 요청")
    send_request(
        ip="8.8.8.8",
        ua="curl/7.88.1",
        extra={
            "req_count": 10,
            "interval": 2.5,
            "uri": "/home",
            "timestamp": time.time()
        }
    )

    print("\n❗ 동일 IP 반복 요청 → IP 폭주 테스트")
    for i in range(101):
        send_request(
            ip="7.7.7.7",
            ua="Mozilla/5.0",
            extra={
                "req_count": i + 1,
                "interval": 0.1,
                "uri": "/",
                "timestamp": time.time()
            }
        )
        time.sleep(0.01)
        
def generate_random_test_cases(n: int = 50):
    clear_rule_cache()
    print(f"\n🧪 랜덤 테스트 케이스 {n}개 생성")

    stats = {"rule": 0, "ml": 0, "normal": 0, "total": 0}

    for _ in range(n):
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        ua = random.choice([
            "Mozilla/5.0", "curl/7.88.1", "python-requests/2.25", "wget/1.20"
        ])
        uri = random.choice(["/", "/checkout", "/cart", "/index.html"])
        req_count = random.randint(1, 150)
        interval = round(random.expovariate(1/2), 2)
        timestamp = time.time()

        payload = {
            "ip": ip,
            "user_agent": ua,
            "uri": uri,
            "req_count": req_count,
            "interval": interval,
            "timestamp": timestamp
        }

        response = requests.post(API_URL, json=payload)
        result = response.json()
        method = result.get("method", "normal")
        stats[method] += 1
        stats["total"] += 1

        print(f"[{ip}] UA: {ua} → anomaly: {result['anomaly']} ({method})")
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
