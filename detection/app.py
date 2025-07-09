from fastapi import FastAPI, Request
from detection import detect_anomaly


app = FastAPI()

@app.post("/detect")
async def detect(request: Request):
    data = await request.json()
    is_anomaly = detect_anomaly(data)

    if is_anomaly:
        ip = data.get("ip")
        print(f"[🚨 탐지] 이상 트래픽 감지! IP: {ip}, UA: {data.get('user_agent')}")

    else:
        ip = data.get("ip")
        print(f"[✅ 정상] IP: {ip}")

    return {
        "ip": data.get("ip"),
        "anomaly": is_anomaly
    }

@app.get("/")
async def root():
    return {"message": "FastAPI is running!"}
