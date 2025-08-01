
'''
# test_detection.py (API Endpoint Tester)
'''
import requests
import time
import random
import numpy as np
import string

API_URL = "http://127.0.0.1:8000/detect" # FastAPI 기본 포트는 5000입니다.

def send_request(payload: dict) -> dict:
    """요청을 전송하고 JSON 응답을 반환합니다."""
    try:
        resp = requests.post(API_URL, json=payload, timeout=3)
        resp.raise_for_status() # HTTP 에러 발생 시 예외 발생
        return resp.json()
    except requests.exceptions.RequestException as e:
        return {"anomaly": "error", "detail": str(e)}

def print_result(ip: str, test_name: str, result: dict):
    """테스트 결과를 포맷에 맞춰 출력합니다."""
    status = "탐지됨" if result.get("anomaly") else "정상"
    method = result.get("method", "-")
    print(f"[{ip:<15}] {test_name:<25} -> {status} (Method: {method})")

# --- 테스트 케이스 정의 ---

def test_normal_case():
    """정상적인 요청 테스트"""
    payload = {
        "ip": "8.8.8.8",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Referer": "https://google.com",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "sec-ch-ua": '''"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"'''
        },
        "path": "/index.html",
        "method": "GET",
        "req_count": 10,
        "interval": 5.0,
        "uri": "/index.html"
    }
    result = send_request(payload)
    print_result(payload["ip"], "정상 요청", result)

def test_rule_based_cases():
    """규칙 기반으로 탐지되어야 하는 케이스들"""
    print("\n--- 규칙 기반 탐지 테스트 ---")
    # 1. User-Agent 블랙리스트
    payload_ua = {
        "ip": "1.1.1.1", "headers": {"User-Agent": "sqlmap"}, "path": "/", "method": "GET"
    }
    result_ua = send_request(payload_ua)
    print_result(payload_ua["ip"], "UA 블랙리스트 (sqlmap)", result_ua)

    # 2. 차단 국가 (중국 IP)
    payload_geo = {
        "ip": "1.12.1.1", "headers": {"User-Agent": "Mozilla/5.0"}, "path": "/", "method": "GET"
    }
    result_geo = send_request(payload_geo)
    print_result(payload_geo["ip"], "차단 국가 (CN)", result_geo)

    # 3. TLS 핑거프린트 블랙리스트 (curl)
    payload_tls = {
        "ip": "2.2.2.2", "headers": {"User-Agent": "curl/7.88.1", "X-JA4": "cd08e31494f04d93a41a9e1dc943e07b"}, "path": "/", "method": "GET"
    }
    result_tls = send_request(payload_tls)
    print_result(payload_tls["ip"], "TLS FP 블랙리스트 (curl)", result_tls)

def test_ml_based_cases():
    """ML 기반으로 탐지되어야 하는 케이스들"""
    print("\n--- ML 기반 탐지 테스트 ---")
    # 규칙은 통과하지만, 행위 패턴이 비정상적인 경우 (높은 요청 빈도, 높은 URI 엔트로피)
    payload = {
        "ip": "3.3.3.3",
        "headers": { # 규칙을 통과할 만한 정상적인 헤더
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html",
            "Referer": "https://some-normal-site.com"
        },
        "path": "/products/item/12345/reviews",
        "method": "CREATE",
        # ML이 탐지할 만한 비정상적인 행위 지표
        "req_count": 3000,       # 분당 요청 수 150회
        "interval": 0.2,        # 요청 간격 0.2초
        "uri": "/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=50)), # URI 복잡도 높임
    }
    result = send_request(payload)
    print_result(payload["ip"], "높은 요청 빈도/엔트로피", result)

def run_random_tests(n: int = 50):
    """무작위 요청을 생성하여 시스템을 테스트합니다."""
    print(f"\n--- 무작위 테스트 ({n}회) ---")
    stats = {"rule": 0, "ml": 0, "normal": 0, "error": 0, "total": n}

    for i in range(n):
        # 1. 트래픽 유형 결정 (정상, 규칙 기반 공격, ML 기반 공격)
        traffic_type = random.choices(
            population=['normal', 'rule_attack', 'ml_attack'],
            weights=[0.5, 0.25, 0.25],  # 정상 50%, 규칙 공격 25%, ML 공격 25%
            k=1
        )[0]

        # 2. 기본 정상 요청 값 설정
        ip = f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml",
        }
        req_count = random.randint(5, 1000)
        interval = round(random.uniform(1.0, 10.0), 2)
        uri = random.choice(["/index.html", "/cart", "/login", "/products"])

        # 3. 트래픽 유형에 따라 값 변조
        if traffic_type == 'rule_attack':
            # 명백한 규칙 위반 특징 주입
            if random.random() < 0.5:
                headers["User-Agent"] = random.choice(["sqlmap", "python-requests", "wget", "curl/7.88.1"])
            else:
                ip = random.choice(["1.12.1.1", "95.173.136.70"]) # 차단 국가 IP
        
        elif traffic_type == 'ml_attack':
            # 규칙은 통과시키되, 행위 특징을 비정상적으로 만듦
            req_count = random.randint(100, 250)
            interval = round(random.uniform(0.01, 0.4), 2)
            uri = "/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(20, 60)))

        # 4. 페이로드 구성 및 전송
        payload = {
            "ip": ip,
            "headers": headers,
            "path": uri,
            "method": "CREATE",
            "req_count": req_count,
            "interval": interval,
            "uri": uri
        }

        result = send_request(payload)
        method = result.get("method", "normal")
        if result.get("anomaly") == "error":
            stats["error"] += 1
        else:
            stats[method] += 1
        
        if (i + 1) % 10 == 0:
            print(f"  ... {i+1}/{n} 요청 처리 완료")

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
    test_ml_based_cases()

    # 무작위 케이스 테스트
    run_random_tests(50)
