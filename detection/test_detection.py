import requests
import time

API_URL = "http://127.0.0.1:8000/detect"


def send_request(
    ip: str,
    ua: str,
    accept: str | None = None,
    ja3: str | None = None,
) -> None:
    """단일 요청 전송 후 탐지 결과 출력"""
    headers = {"User-Agent": ua}
    if accept:
        headers["Accept"] = accept
    if ja3:
        headers["X-JA3"] = ja3

    payload = {"ip": ip, "headers": headers}
    resp = requests.post(API_URL, json=payload, timeout=3)
    body = resp.json() if resp.ok else {"anomaly": "HTTP error"}

    print(
        f"[{ip:<15}] "
        f"UA={ua!r:18} "
        f"Accept={accept or '-':9} "
        f"JA3={ja3 or '-':34} "
        f"→ anomaly={body['anomaly']}"
    )


def test_cases() -> None:
    # Stage-1: 정상·UA 블랙리스트·Accept 누락
    print("✅ 정상 요청")
    send_request("9.9.9.9", "Mozilla/5.0", "text/html")

    print("\n❗ UA 블랙리스트 (curl)")
    send_request("8.8.8.8", "curl/7.88.1", "*/*")

    print("\n❗ 브라우저 UA + Accept 없음")
    send_request("6.6.6.6", "Mozilla/5.0")       # Accept 헤더 미포함

    # Stage-2: IP 폭주
    print("\n❗ 동일 IP 반복 요청 (빈도 초과)")
    for _ in range(101):                         # 100 + 1회 → 탐지
        send_request("7.7.7.7", "Mozilla/5.0", "text/html")
        time.sleep(0.01)

    # Stage-3: 국가 차단
    print("\n❗ 국가 차단 테스트 (RU)")
    send_request("95.173.136.70", "Mozilla/5.0", "text/html")   # 러시아 IP 예시

    print("\n❗ 국가 차단 테스트 (CN)")
    send_request("1.12.1.1", "Mozilla/5.0", "text/html")        # 중국 IP 예시

    print("\n❗ TLS JA3 불일치 (브라우저 UA + curl JA3)")
    send_request("5.5.5.5",
                "Mozilla/5.0",
                "text/html",
                "cd08e31494f04d93a41a9e1dc943e07b")     # curl 해시

    print("\n❗ TLS JA3 블랙리스트 전용 (ZGrab 해시)")
    send_request("4.4.4.4",
                 "ZGrab/1.x",
                 "*/*",
                 "5d74ab0f9d9e3f4d1c6e89de2a78f638")


if __name__ == "__main__":
    test_cases()
