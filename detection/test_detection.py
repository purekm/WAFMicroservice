# test_detection.py (종합 테스트용 API Endpoint Tester)
import requests
import time
import random
import string

# 테스트할 API 엔드포인트 URL
API_URL = "https://dr43t8f59om7c.cloudfront.net/wafinputlambda"

def send_request(payload: dict) -> dict:
    """요청을 전송하고 JSON 응답을 반환합니다."""
    try:
        # 지정된 URL에 POST 요청을 보냄
        resp = requests.post(API_URL, json=payload, timeout=3)
        resp.raise_for_status() # HTTP 오류 발생 시 예외 발생
        return resp.json()
    except requests.exceptions.RequestException as e:
        # 요청 실패 시 에러 정보를 포함한 응답 반환
        return {"anomaly": True, "method": "error", "detail": str(e)}

def print_result(ip: str, test_name: str, result: dict, payload: dict):
    """테스트 결과를 포맷에 맞춰 출력합니다."""
    status = "탐지됨" if result.get("anomaly") else "정상"
    method = result.get("method", "-")
    print(f"[{ip:<15}] {test_name:<30} -> {status:<5} (탐지 방식: {method}, 경로: {payload.get('path', '/')})")

# --- 테스트 케이스 정의 ---

def test_normal_case():
    """정상적인 단일 요청 테스트"""
    print("--- 일반 단일 요청 테스트 ---")
    payload = {
        "ip": "8.8.8.8", # 구글 DNS IP (정상)
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Referer": "https://google.com",
            "Authorization": ""
        },
        "path": "/index.html",
        "method": "GET",
        "cookies": {"session_id": "abc123xyz"}
    }
    result = send_request(payload)
    print_result(payload["ip"], "정상 단일 요청", result, payload)

def test_rule_based_cases():
    """규칙 기반으로 탐지되어야 하는 케이스들"""
    print("\n--- 규칙 기반 탐지 테스트 ---")
    # 1. User-Agent 블랙리스트 (sqlmap)
    payload_ua = {"ip": "1.1.1.1", "headers": {"User-Agent": "sqlmap"}, "path": "/", "method": "GET"}
    result_ua = send_request(payload_ua)
    print_result(payload_ua["ip"], "UA 블랙리스트 (sqlmap)", result_ua, payload_ua)

    # 2. 차단 국가 (중국 IP)
    payload_geo = {"ip": "1.12.1.1", "headers": {"User-Agent": "Mozilla/5.0"}, "path": "/", "method": "GET"}
    result_geo = send_request(payload_geo)
    print_result(payload_geo["ip"], "차단 국가 (CN)", result_geo, payload_geo)

def test_stateful_ml_cases():
    """상태 기반 ML 탐지 테스트 (연속적인 요청)"""
    print("\n--- 상태 기반 ML 탐지 테스트 ---")
    test_ip = "10.10.10.10"

    # Case 1: 짧은 시간 내에 많은 요청 (req_count_in_last_10s 특징)
    print("  (1) 짧은 시간 내 대량 요청 테스트")
    for i in range(15):
        payload = {
            "ip": test_ip,
            "headers": {"User-Agent": "Mozilla/5.0"},
            "path": f"/api/v1/data/{i}",
            "method": "GET",
            "cookies": {"session_id": "abc123xyz"}
        }
        result = send_request(payload)
        if result.get("anomaly"):
            print_result(test_ip, f"대량 요청 (요청 #{i+1})", result, payload)
            break
        time.sleep(0.1) # 0.1초 간격으로 요청
    else:
        print_result(test_ip, "대량 요청 (탐지 실패)", {"anomaly": False}, payload)

    # Case 2: 짧은 시간 내에 다양한 경로 요청 (unique_paths_in_last_60s 특징)
    time.sleep(1) # 테스트 케이스 간 구분을 위한 대기
    print("\n  (2) 짧은 시간 내 다양한 경로 스캔 테스트")
    test_ip_2 = "20.20.20.20"
    for i in range(20):
        path = "/" + ''.join(random.choices(string.ascii_lowercase, k=10))
        payload = {
            "ip": test_ip_2,
            "headers": {"User-Agent": "Mozilla/5.0"},
            "path": path,
            "method": "GET",
            "cookies": {"session_id": "abc123xyz"}
        }
        result = send_request(payload)
        if result.get("anomaly"):
            print_result(test_ip_2, f"경로 스캔 (요청 #{i+1})", result, payload)
            break
        time.sleep(0.5)
    else:
        print_result(test_ip_2, "경로 스캔 (탐지 실패)", {"anomaly": False}, payload)

def generate_public_ip():
    """사설/예약 대역을 피해서 대략적인 퍼블릭 IP를 생성합니다."""
    while True:
        a = random.randint(1, 223)     # A, B, C 클래스 범위
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)     # 브로드캐스트 주소(.0, .255) 회피

        # 사설 IP, 예약된 IP 대역 제외
        if a == 10: continue                       # 10.0.0.0/8
        if a == 127: continue                      # 127.0.0.0/8 (루프백)
        if a == 172 and 16 <= b <= 31: continue    # 172.16.0.0/12
        if a == 192 and b == 168: continue         # 192.168.0.0/16
        if a == 169 and b == 254: continue         # 169.254.0.0/16 (링크-로컬)
        # ... 기타 예약 대역
        return f"{a}.{b}.{c}.{d}"

def run_random_tests(n: int = 50):
    """무작위 요청을 생성하여 시스템을 테스트합니다."""
    print(f"\n--- 무작위 테스트 ({n}회) ---")
    stats = {"rule": 0, "ml": 0, "normal": 0, "error": 0, "total": n}

    # 상태 기반 ML 탐지를 테스트하기 위해 IP 주소 풀을 미리 생성
    stateful_ips = [generate_public_ip() for _ in range(40)]

    for i in range(n):
        # 50% 정상, 25% 룰 공격, 25% ML 공격 트래픽 생성
        traffic_type = random.choices(['normal', 'rule_attack', 'ml_attack'], [0.5, 0.25, 0.25])[0]

        payload = {
            "ip": generate_public_ip(), # 기본적으로 매번 새로운 랜덤 IP 사용
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            "path": random.choice(["/home", "/products", "/login"]),
            "method": "GET",
            "cookies": {"user_id": "123"}
        }

        if traffic_type == 'rule_attack':
            # 룰 기반 공격: User-Agent를 'sqlmap'으로 설정
            payload["headers"]["User-Agent"] = "sqlmap"

        elif traffic_type == 'ml_attack':
            # ML 기반 공격: 미리 만들어둔 IP 풀에서 랜덤하게 선택하여 상태 유지
            payload["ip"] = random.choice(stateful_ips)

            # 다양한 ML 공격 유형 시뮬레이션
            attack_subtype = random.choice(['path_scan', 'long_path', 'weird_header'])
            if attack_subtype == 'path_scan':
                payload["path"] = "/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
            elif attack_subtype == 'long_path':
                payload["path"] = "/api/v1/data/" + ''.join(random.choices(string.ascii_lowercase, k=100))
            elif attack_subtype == 'weird_header':
                payload["headers"]["Referer"] = f"http://unusual-site-{random.randint(1,100)}.com/entry"
                payload["headers"]["Accept"] = "application/x-shockwave-flash, */*"
                payload["method"] = "POST"

        result = send_request(payload)
        method = result.get("method", "normal")

        # 결과 통계 집계
        if result.get("anomaly"):
            if method in stats:
                stats[method] += 1
        else:
            stats["normal"] += 1

        if (i + 1) % 10 == 0:
            print(f"  ... {i+1}/{n} 요청 처리 완료")

        time.sleep(random.uniform(0.1, 0.5))

    print_summary(stats)

def print_summary(stats):
    """테스트 결과 요약 출력"""
    print("\n--- 테스트 결과 요약 ---")
    for key, value in stats.items():
        print(f"{key.capitalize():<10}: {value}")
    print("-" * 25)

if __name__ == "__main__":
    print("WAF 탐지 시스템 테스트를 시작합니다.")
    print(f"API Endpoint: {API_URL}\n")

    # 정의된 케이스 테스트 실행
    test_normal_case()
    test_rule_based_cases()
    test_stateful_ml_cases()

    # 무작위 케이스 테스트 실행
    run_random_tests(50)
