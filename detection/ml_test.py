import requests
import time
import random
import pandas as pd
import numpy as np
import joblib

API_URL = "http://localhost:8000/detect"

# ─── 학습 때 사용한 인코더 불러오기 ───
enc_accept = joblib.load("enc_accept.pkl")
enc_referer = joblib.load("enc_referer.pkl")
enc_method = joblib.load("enc_method.pkl")

# ─── 동적 URI 생성 함수 ───
def generate_uri(depth):
    segments = [f"section{i}" for i in range(1, depth + 1)]
    return "/" + "/".join(segments) if segments else "/"
# ─── 라벨 인코딩 예외처리 ───
def safe_label_encode(encoder, value, unknown_value=-999):
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return unknown_value
    
# ─── 요청 전송 함수 (정적/랜덤 테스트용) ───
def send_request_ml(row, ip="192.168.0.100"):
    uri = generate_uri(int(row["path_depth"]))
    cookie = "; ".join([f"key{i}=val{i}" for i in range(int(row["cookie_count"]))])

    # 인코딩 적용
    encoded_accept = safe_label_encode(enc_accept, row["accept_type"])
    encoded_referer = safe_label_encode(enc_referer, row["referer_domain"])
    encoded_method = safe_label_encode(enc_method, row["method"])

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": row["accept_type"],
        "Referer": f"https://{row['referer_domain']}/search" if row["referer_domain"] else "",
        "Cookie": cookie
    }

    payload = {
        "ip": ip,
        "timestamp": float(time.time()),
        "headers": headers,
        "req_count": int(row["req_count"]),
        "interval": float(np.log1p(float(row["interval"]))),
        "uri": uri,
        "accept_type": int(encoded_accept),
        "referer_domain": int(encoded_referer),
        "method": int(encoded_method)
    }


    try:
        resp = requests.post(API_URL, json=payload, timeout=3)
        body = resp.json() if resp.ok else {"anomaly": "HTTP error"}
        print(f"[{ip:<15}] anomaly={body['anomaly']}  ({body.get('method', '-')})")
    except Exception as e:
        print(f"[{ip:<15}] error={e}")

# ─── 테스트 케이스 (정적) ───
test_cases = pd.DataFrame([
    { # TC1 : 높은 빈도로 요청하는 봇 탐지하기 위한 케이스
        "req_count": 100000,
        "interval": 0.0001,
        "path_depth": 1,
        "cookie_count": 1,
        "referer_domain": "google.com",
        "method": "POST",
        "accept_type": "application/json"
    },
    { # TC2 : 내부 요청처럼 위장한거 탐지하기 위한 케이스
        "req_count": 5,
        "interval": 1.2,
        "path_depth": 2,
        "cookie_count": 2,
        "referer_domain": "localhost",
        "method": "DELETE",
        "accept_type": "*/*"
    },
    { # TC3 : path_depth가 긴 deep url 탐지하기 위한 케이스
        "req_count": 80,
        "interval": 0.5,
        "path_depth": 6,
        "cookie_count": 3,
        "referer_domain": "ad.example.com",
        "method": "POST",
        "accept_type": "application/xml"
    },
    { # TC 4 : 쿠기도 없고, referer도 없고, accept type도 없는 케이스 
        "req_count": 10,
        "interval": 1.0,
        "path_depth": 2,
        "cookie_count": 0,
        "referer_domain": "",
        "method": "GET",
        "accept_type": ""
    },
    { # TC5 : 비정상적으로 많은 쿠키 
        "req_count": 70,
        "interval": 0.3,
        "path_depth": 3,
        "cookie_count": 20,
        "referer_domain": "ad.example.com",
        "method": "POST",
        "accept_type": "application/json"
    }
])
## referer 이 localhost이고 나머지가 정상이면, 정상요청이라고 함

print("📦 [정적 테스트 케이스 실행]")
for _, row in test_cases.iterrows():
    send_request_ml(row)


# ─── 랜덤 테스트 케이스 생성 ───
def generate_random_test_data(n=10):
    domains_normal = ["google.com", "naver.com", "example.com", "tistory.com", "facebook.com"]
    domains_suspicious = ["", "localhost", "ad.example.com", "malicious.site"]
    accept_pool = enc_accept.classes_.tolist()
    method_pool = enc_method.classes_.tolist()

    data = []
    for _ in range(n):
        is_abnormal = random.random() < 0.2
        data.append({
            "req_count": random.randint(50, 150) if is_abnormal else random.randint(1, 20),
            "interval": round(random.uniform(0.01, 0.1), 3) if is_abnormal else round(random.uniform(0.5, 2.5), 2),
            "path_depth": random.randint(5, 10) if is_abnormal else random.randint(1, 3),
            "cookie_count": random.randint(6, 20) if is_abnormal else random.randint(1, 4),
            "referer_domain": random.choice(domains_suspicious if is_abnormal else domains_normal),
            "method": random.choice(method_pool),
            "accept_type": random.choice(accept_pool)
        })
    return pd.DataFrame(data)

print("\n🎲 [랜덤 트래픽 테스트 실행]")
for _, row in generate_random_test_data(10).iterrows():
    send_request_ml(row)
