import requests, random, time, csv
from datetime import datetime

referers = [
    "https://www.google.com/search?q=fastapi",
    "https://search.naver.com/search.naver?query=fastapi",
    "https://www.facebook.com/share.php?u=https://example.com",
    "https://t.co/shortlink",
    "https://blog.tistory.com/entry/fastapi-intro",
    "https://news.ycombinator.com/item?id=123456",
    "https://ad.example.com/?utm_source=naver",
    "https://shopping.example.com/deals",
    "https://partner.site.com/ref?id=xyz",
    "https://example.com/product/1"
]

cookies = [
    "sessionid=abc123; logged_in=true",
    "uid=42; token=xyz123; cart=3",
    "auth_token=eyJhbGciOiJIUzI1NiIs...; exp=1720000000",
    "ga=GA1.2.123456789.1700000000; _gid=GA1.2.987654321.1700000001",
    "experiment=A; ab_group=3; recommendation=true",
    "cart=1,2,3; viewed=5,7,10",
    "theme=dark; language=ko-KR",
    "ref=affiliate123; campaign=spring_sale"
]
paths = [
    "/", "/home", "/about", "/contact", "/login", "/logout", "/signup",
    "/terms", "/privacy", "/help",
    "/product/1", "/product/123", "/category/electronics", "/category/fashion",
    "/cart", "/cart/checkout", "/checkout/complete",
    "/search?q=shoes", "/search?q=fastapi&page=2",
    "/mypage", "/mypage/orders", "/mypage/orders/42", "/mypage/wishlist", "/mypage/settings",
    "/user/profile", "/user/profile/edit",
    "/admin", "/admin/users", "/admin/users/123", "/admin/settings", "/admin/logs/errors",
    "/api/ping", "/api/v1/user", "/api/v1/user/42", "/api/v1/user/42/profile", "/api/v1/user/42/orders",
    "/api/v1/product/10/review", "/api/v1/cart/items", "/api/v1/cart/items/remove",
    "/api/v1/order/88/confirm", "/api/v2/notification/mark-read",
    "/event/summer-sale", "/event/black-friday", "/review/product/15", "/recommend/products",
    "/recommend/user/42", "/review/product/1/page/2"
]

ua_list = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36 Edg/118.0.2088.76",

    # Firefox
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",

    # iOS Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari",

    # Android Chrome
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.134 Mobile Safari/537.36",

    # # GitHub Actions, curl, etc.
    # "curl/7.68.0",
    # "python-requests/2.28.1",
    # "PostmanRuntime/7.32.0"
]

accept_type = [
    "text/html",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "text/plain",
    "*/*",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json;q=0.9,*/*;q=0.8",
    "text/html;q=0.8,application/json;q=0.2"
]


with open("traffic_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["ip", "timestamp", "method", "path", "ua", "referer", "cookie","accept_type"])
    for i in range(300):
        ip = f"192.168.0.{random.randint(1, 200)}"
        ua = random.choice(ua_list)
        data = {
            "ip": ip,
            "user_agent": ua,
            "referer": random.choice(referers),
            "cookie": random.choice(cookies),
            "method": random.choice(["GET", "POST"]),
            "uri": random.choice(paths),
            "accept_type" : random.choice(accept_type),
            "timestamp": time.time()  # 추후 time_diff 계산 가능
        }
        writer.writerow([
            data["ip"],
            data["timestamp"],
            data["method"],
            data["uri"],
            data["user_agent"],
            data["referer"],
            data["cookie"],
            data["accept_type"]
        ])
        # res = requests.post("http://127.0.0.1:8000/detect", json=data)
        # print(f"[{i}] {ip} {ua} =>", res.json())
        time.sleep(random.uniform(0.3, 2.5))