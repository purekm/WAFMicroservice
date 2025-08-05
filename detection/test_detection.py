# test_detection.py (API Endpoint Tester)
import requests
import time
import random
import string

API_URL = "http://127.0.0.1:5000/detect"

def send_request(payload: dict) -> dict:
    """요청을 전송하고 JSON 응답을 반환합니다."""
    try:
        resp = requests.post(API_URL, json=payload, timeout=3)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
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
        "ip": "8.8.8.8",
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
    # 1. User-Agent 블랙리스트
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

    # Case 1: 짧은 시간 내에 많은 요청 (req_count_in_last_10s)
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

    # Case 2: 짧은 시간 내에 다양한 경로 요청 (unique_paths_in_last_60s)
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


def run_random_tests(n: int = 50):
    """무작위 요청을 생성하여 시스템을 테스트합니다."""
    print(f"\n--- 무작위 테스트 ({n}회) ---")
    stats = {"rule": 0, "ml": 0, "normal": 0, "error": 0, "total": n}
    
    # 상태를 유지할 IP 풀
    stateful_ips = [f"172.16.1.{i}" for i in range(5)] 

    for i in range(n):
        traffic_type = random.choices(['normal', 'rule_attack', 'ml_attack'], [0.5, 0.25, 0.25])[0]

        # 기본 페이로드
        payload = {
            "ip": f"192.168.1.{random.randint(1, 254)}",
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            "path": random.choice(["/home", "/products", "/login"]),
            "method": "GET",
            "cookies": {"user_id": "123"}
        }

        if traffic_type == 'rule_attack':
            payload["headers"]["User-Agent"] = "sqlmap"
            payload["ip"] = "1.12.1.1" # 차단 국가
        
        elif traffic_type == 'ml_attack':
            # ML 공격은 상태 유지가 필요하므로, 지정된 IP 중 하나를 사용
            payload["ip"] = random.choice(stateful_ips)
            
            # 다양한 ML 공격 유형을 시뮬레이션
            attack_subtype = random.choice(['path_scan', 'long_path', 'weird_header'])

            if attack_subtype == 'path_scan':
                # 유니크한 경로를 빠르게 스캔하는 행위
                payload["path"] = "/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
            
            elif attack_subtype == 'long_path':
                # 비정상적으로 긴 경로 요청
                payload["path"] = "/api/v1/data/" + ''.join(random.choices(string.ascii_lowercase, k=100))

            elif attack_subtype == 'weird_header':
                # 학습 데이터에 없을 가능성이 높은 비정상적인 헤더 값
                payload["headers"]["Referer"] = f"http://unusual-site-{random.randint(1,100)}.com/entry"
                payload["headers"]["Accept"] = "application/x-shockwave-flash, */*"
                payload["method"] = "POST"

            # app.py의 상태 관리 로직이 짧은 시간 내의 연속적인 요청을 탐지할 것임
        
        result = send_request(payload)
        method = result.get("method", "normal")
        
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
    print("\n--- 테스트 결과 요약 ---")
    for key, value in stats.items():
        print(f"{key.capitalize():<10}: {value}")
    print("-" * 25)

if __name__ == "__main__":
    print("WAF 탐지 시스템 테스트를 시작합니다.")
    print(f"API Endpoint: {API_URL}\n")

    # 정의된 케이스 테스트
    test_normal_case()
    test_rule_based_cases()
    test_stateful_ml_cases()

    # 무작위 케이스 테스트
    run_random_tests(50)