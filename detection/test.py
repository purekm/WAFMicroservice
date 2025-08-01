# test_detection.py
import time
from detection import rule_detect

def make_headers(**kwargs):
    """기본 브라우저 헤더 템플릿을 만들고 원하는 값을 덮어쓰기."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Accept": "application/json",
        "Accept-Language": "ko-KR,ko;q=0.9",
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Sec-CH-UA": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"120\"",
        "Cookie": "sessionid=abc123"
    }
    headers.update(kwargs)
    return headers

def run_tests():
    tests = [
        # --- 정상 트래픽 ---
        {"name": "정상 브라우저 요청", "ip": "1.1.1.1", "headers": make_headers(), "path": "/api/data", "method": "GET", "body_length": 0},
        {"name": "정상 POST 요청", "ip": "1.1.1.2", "headers": make_headers(), "path": "/api/data", "method": "POST", "body_length": 50},
        {"name": "정상 GraphQL", "ip": "1.1.1.3", "headers": make_headers(), "path": "/graphql", "method": "POST", "graphql": "{ user { id name } }", "body_length": 40},

        # --- UA 블랙리스트 ---
        {"name": "curl UA", "ip": "2.2.2.1", "headers": make_headers(**{"User-Agent": "curl/8.1"}), "path": "/api/data", "method": "GET"},
        {"name": "python-requests UA", "ip": "2.2.2.2", "headers": make_headers(**{"User-Agent": "python-requests/2.31"}), "path": "/api/data", "method": "GET"},

        # --- 헤더 부족 ---
        {"name": "헤더 2개만 있음", "ip": "3.3.3.1", "headers": {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}, "path": "/", "method": "GET"},

        # --- Content-Length 폭탄 ---
        {"name": "대용량 본문", "ip": "3.3.3.2", "headers": make_headers(), "path": "/api/data", "method": "POST", "body_length": 200_000},

        # --- GeoIP 국가 차단 ---
        {"name": "차단 국가 (CN)", "ip": "101.6.6.6", "headers": make_headers(), "path": "/", "method": "GET"},  # GeoIP에서 CN으로 나올 것으로 가정

        # --- TLS JA3/JA4 블랙리스트 ---
        {"name": "JA3 블랙리스트 값", "ip": "4.4.4.4", "headers": make_headers(**{"X-JA3": "cd08e31494f04d93a41a9e1dc943e07b"}), "path": "/api/data", "method": "GET"},

        # --- same-site인데 쿠키 없음 ---
        {"name": "쿠키 없음", "ip": "5.5.5.5", "headers": make_headers(**{"Cookie": ""}), "path": "/", "method": "GET"},

        # --- Accept-Language와 GeoIP 불일치 ---
        {"name": "언어-국가 불일치", "ip": "6.6.6.6", "headers": make_headers(**{"Accept-Language": "ko-KR"}), "path": "/", "method": "GET"},  # GeoIP는 JP 가정

        # --- GraphQL Introspection ---
        {"name": "GraphQL Introspection", "ip": "7.7.7.7", "headers": make_headers(), "path": "/graphql", "method": "POST", "graphql": "{ __schema { types { name } } }", "body_length": 90},

        # --- IP 폭주 (같은 IP 반복) ---
        *[
            {"name": f"IP 폭주 {i}", "ip": "8.8.8.8", "headers": make_headers(), "path": "/", "method": "GET"}
            for i in range(5)
        ],

        # --- 의심 path ---
        {"name": "의심 path .env", "ip": "9.9.9.9", "headers": make_headers(), "path": "/.env", "method": "GET"},

        # --- Method-Path 불일치 (예: GET 허용 path에 POST) ---
        {"name": "Method-Path 불일치", "ip": "9.9.9.10", "headers": make_headers(), "path": "/health", "method": "POST"},

        # --- Accept 없음 (브라우저 UA) ---
        {"name": "Accept 없음", "ip": "10.10.10.1", "headers": make_headers(**{"Accept": ""}), "path": "/", "method": "GET"},

        # --- Referer 없음 same-site ---
        {"name": "Referer 없음", "ip": "10.10.10.2", "headers": make_headers(**{"Referer": ""}), "path": "/", "method": "GET"},

        # --- UA 위장 (브라우저 UA + JA3 curl) ---
        {"name": "UA 위장 + JA3 curl", "ip": "11.11.11.1", "headers": make_headers(**{"X-JA3": "cd08e31494f04d93a41a9e1dc943e07b"}), "path": "/", "method": "GET"},

        # --- GraphQL Depth/Complexity 초과 ---
        {"name": "GraphQL 깊이 초과", "ip": "12.12.12.1", "headers": make_headers(), "path": "/graphql", "method": "POST", "graphql": "{ user { posts { comments { author { name } } } } }", "body_length": 120},

        # --- 헤더 순서 이상 (헤더 재정렬된 케이스 가정) ---
        {"name": "헤더 순서 이상", "ip": "13.13.13.1", "headers": dict(reversed(list(make_headers().items()))), "path": "/", "method": "GET"},

        # --- 브라우저다움 강한 케이스 (음수 가중치 테스트) ---
        {"name": "강한 브라우저 케이스", "ip": "14.14.14.1", "headers": make_headers(), "path": "/", "method": "GET"},
    ]

    print(f"[+] 총 테스트 케이스: {len(tests)} 개\n")

    for i, t in enumerate(tests, 1):
        anomaly = rule_detect({
            "ip": t["ip"],
            "headers": t["headers"],
            "timestamp": time.time(),
            "path": t.get("path", "/"),
            "method": t.get("method", "GET"),
            "graphql": t.get("graphql"),
            "same_site": True,  # 테스트는 same_site=True로 가정
            "body_length": t.get("body_length", 0),
        })
        print(f"[{i:02d}] {t['name']:<30} → anomaly={anomaly}")

if __name__ == "__main__":
    run_tests()
