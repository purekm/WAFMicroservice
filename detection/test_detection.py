import requests
import time

API_URL = "http://127.0.0.1:8000/detect"

def send_request(ip, ua):
    payload = {
        "ip": ip,
        "user_agent": ua
    }
    response = requests.post(API_URL, json=payload)
    result = response.json()
    print(f"[{ip}] UA: {ua} → anomaly: {result['anomaly']}")

def test_cases():
    print("✅ 정상 요청")
    send_request("9.9.9.9", "Mozilla/5.0")

    print("\n❗ 비정상 UA 요청")
    send_request("8.8.8.8", "curl/7.88.1")

    print("\n❗ 동일 IP 반복 요청 → IP 폭주 테스트")
    for i in range(101):
        send_request("7.7.7.7", "Mozilla/5.0")
        time.sleep(0.01)  # 빠르게 반복 요청

if __name__ == "__main__":
    test_cases()
