import requests
import time
import random
import pandas as pd
import numpy as np
import joblib

API_URL = "http://localhost:5000/detect"

# ─── 학습 때 사용한 인코더 불러오기 ───
enc_accept = joblib.load("enc_accept.pkl")
enc_referer = joblib.load("enc_referer.pkl")
enc_method = joblib.load("enc_method.pkl")

# ─── 동적 URI 생성 함수 ───
def generate_uri(depth):
    segments = [f"section{i}" for i in range(1, depth + 1)]
    return "/" + "/".join(segments) if segments else "/"

# ─── 요청 전송 함수 ───
def send_request_ml(row, ip="192.168.0.100"):
    # row의 NaN 값을 None으로 변환
    row = row.where(pd.notna(row), None)

    uri = generate_uri(int(row["path_depth"]))
    authorization = row["authorization"] if row["authorization"] else ""

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": row["accept_type"],
        "Referer": f"https://{row['referer_domain']}/search" if row["referer_domain"] else "",
        "Authorization": authorization
    }

    payload = {
        "ip": ip,
        "timestamp": float(time.time()),
        "headers": headers,
        "uri": uri,
        "accept_type": row["accept_type"],
        "referer_domain": row["referer_domain"],
        "method": row["method"]
    }

    try:
        resp = requests.post(API_URL, json=payload, timeout=3)
        body = resp.json() if resp.ok else {"anomaly": "HTTP error"}
        print(f"[{ip:<15}] anomaly={body['anomaly']}  ({body.get('method', '-')})")
    except Exception as e:
        print(f"[{ip:<15}] error={e}")

# ─── 테스트 케이스 (정적) ───
test_cases = pd.DataFrame([
    { # TC1 : 비정상적으로 깊은 경로 + 유효하지 않은 토큰
        "path_depth": 15,
        "authorization": "Bearer invalid-token",
        "referer_domain": "dsldam.com",
        "method": "POST",
        "accept_type": "application/json"
    },
    { # TC2 : 내부 요청처럼 위장 + 비정상 메소드 + 정상 토큰
        "path_depth": 2,
        "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "referer_domain": "localhost",
        "method": "MAKE",
        "accept_type": "*/*"
    },
    { # TC3 : path_depth가 긴 deep url + 정상 토큰
        "path_depth": 6,
        "authorization": "Basic dXNlcjpwYXNz",
        "referer_domain": "ad.example.com",
        "method": "POST",
        "accept_type": "application/xml"
    },
    { # TC 4 : 인증 헤더 없고, method도 없고, referer도 없고, accept type도 없는 케이스 
        "path_depth": 2,
        "authorization": "",
        "referer_domain": "",
        "method": "",
        "accept_type": ""
    },
    { # TC5 : 비정상적인 토큰 (ML은 토큰 유효성 검증은 안하지만, 다른 패턴으로 탐지 가능)
        "path_depth": 3,
        "has_authorization": 1,
        "authorization": "Bearer invalid-token-string",
        "referer_domain": "ad.example.com",
        "method": "POST",
        "accept_type": "application/json"
    }
])
## referer 이 localhost이고 나머지가 정상이면, 정상요청이라고 함

print("[정적 테스트 케이스 실행]")
for _, row in test_cases.iterrows():
    send_request_ml(row)


# ─── 랜덤 테스트 케이스 생성 ───
def generate_random_test_data(n=10):
    domains_normal = ["google.com", "naver.com", "example.com", "tistory.com", "facebook.com"]
    domains_suspicious = ["", "localhost", "ad.example.com", "malicious.site"]
    accept_pool = enc_accept.classes_.tolist()
    method_pool = enc_method.classes_.tolist()
    auth_pool = ["Bearer valid-token", "", "Basic dXNlcjpwYXNz"]

    data = []
    for _ in range(n):
        is_abnormal = random.random() < 0.2
        data.append({
            "path_depth": random.randint(5, 10) if is_abnormal else random.randint(1, 3),
            "authorization": random.choice(auth_pool),
            "referer_domain": random.choice(domains_suspicious if is_abnormal else domains_normal),
            "method": random.choice(method_pool),
            "accept_type": random.choice(accept_pool)
        })
    return pd.DataFrame(data)

print("\n[랜덤 트래픽 테스트 실행]")
for _, row in generate_random_test_data(10).iterrows():
    send_request_ml(row)
