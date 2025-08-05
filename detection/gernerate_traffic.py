import requests, random, time, csv
from datetime import datetime

# --- 정상 트래픽 데이터 풀 ---
normal_referers = [
    "https://www.google.com/search?q=fastapi",
    "https://search.naver.com/search.naver?query=fastapi",
    "https://www.facebook.com/share.php?u=https://example.com",
    "https://t.co/shortlink",
    "https://blog.tistory.com/entry/fastapi-intro",
    "https://news.ycombinator.com/item?id=123456",
    "https://example.com/product/1",
]

normal_authorizations = [
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "Basic YWxhZGRpbjpvcGVuc2VzYW1l",
    "",  # No authorization
]

normal_paths = [
    "/", "/home", "/about", "/contact", "/login", "/logout", "/signup",
    "/terms", "/privacy", "/help",
    "/product/1", "/product/123", "/category/electronics", "/category/fashion",
    "/cart", "/cart/checkout", "/checkout/complete",
    "/search?q=shoes", "/search?q=fastapi&page=2",
    "/mypage", "/mypage/orders", "/mypage/orders/42", "/mypage/wishlist", "/mypage/settings",
    "/user/profile", "/user/profile/edit",
    "/api/ping", "/api/v1/user", "/api/v1/user/42",
]

normal_ua_list = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36 Edg/118.0.2088.76",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.134 Mobile Safari/537.36",
]

normal_accept_type = [
    "text/html", "application/json", "application/xml", "application/xhtml+xml",
    "application/javascript", "text/plain", "*/*",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

normal_method_type = ['GET', 'POST', 'PUT', 'DELETE']


# --- 비정상 트래픽 데이터 풀 ---
abnormal_ips = [f"10.0.0.{random.randint(100, 200)}" for _ in range(10)]
abnormal_methods = ["MAKE", "INVALID", "TRACE", "OPTIONS"]
abnormal_referers = ["", "localhost", "http://evil.site", "http://malicious.co"]
abnormal_authorizations = [
    "Bearer invalidtoken",                  # 유효하지 않은 토큰
    "Basic invalid-credentials",            # 유효하지 않은 Basic Auth
    "Bearer",                               # 토큰 내용 없음
    "Bearer x.y",                           # JWT 형식 오류 (점이 하나만 있음)
    "SomeOtherScheme completely_random_string", # 비표준 인증 스킴
    "null",                                 # "null" 문자열
]
abnormal_uas = ["curl/7.68.0", "python-requests/2.31.0", "Nmap scripting engine"]
abnormal_accepts = ["", "text/Google", "application/zzz", "*/*;q=0.1"]

# 공격 유형별 URI
attack_paths = {
    "sql_injection": ["/search?q=' OR '1'='1", "/login?user=' OR 1=1 --"],
    "xss": ["/comment?text=<script>alert('XSS')</script>", "/profile?name=<img src=x onerror=alert(1)>"],
    "path_traversal": ["/static?file=../../../../etc/passwd", "/download?path=..%2F..%2Fboot.ini"],
    "long_uri": ["/" + "a" * 2048],
    "deep_path": ["/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t"],
}


with open("traffic_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["ip", "timestamp", "method", "path", "ua", "referer", "authorization", "accept_type", "cookie_count"])

    # --- 현실적인 정상 트래픽 생성 ---
    public_paths = [p for p in normal_paths if "mypage" not in p and "cart" not in p and "user" not in p and "checkout" not in p]
    member_paths = [p for p in normal_paths if "mypage" in p or "cart" in p or "user" in p or "checkout" in p]
    valid_auth_tokens = [auth for auth in normal_authorizations if auth != ""]

    for i in range(800):
        is_member = random.random() < 0.6 # 60%는 회원 트래픽
        ip = f"192.168.0.{random.randint(1, 100)}"
        auth = ""
        path = "/"

        if is_member:
            path = random.choice(member_paths)
            auth = random.choice(valid_auth_tokens)
        else:
            path = random.choice(public_paths)
        
        writer.writerow([
            ip,
            time.time() - random.uniform(1, 3600), # 최근 1시간 내 랜덤 시간
            random.choice(normal_method_type),
            path,
            random.choice(normal_ua_list),
            random.choice(normal_referers),
            auth,
            random.choice(normal_accept_type),
            random.randint(1, 5)
        ])
        time.sleep(random.uniform(0.1, 0.5))

    # --- 비정상 트래픽 생성 ---
    for i in range(200):
        attack_type = random.choice(list(attack_paths.keys()))
        
        writer.writerow([
            random.choice(abnormal_ips),
            time.time(),
            random.choice(abnormal_methods),
            random.choice(attack_paths[attack_type]),
            random.choice(abnormal_uas),
            random.choice(abnormal_referers),
            random.choice(abnormal_authorizations),
            random.choice(abnormal_accepts),
            random.randint(0, 1)
        ])
        time.sleep(random.uniform(0.01, 0.1))
