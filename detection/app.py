import uvicorn
from fastapi import FastAPI, Request
from detection import rule_detect
from ml_detection import ml_detect
import httpx

app = FastAPI()

import os

# ECS에 환경변수 설정이 가능하다고 함. 일단은 환경변수 설정은 안했을 땐 오른쪽의 url로 보내기 때문에 제대로 갈 것 같음.
RESPONDER_URL = os.getenv("RESPONDER_URL", "http://WAFMicroservice-ALB-633895454.ap-northeast-2.elb.amazonaws.com/block")

from fastapi.responses import JSONResponse

@app.post("/detect")
async def detect(request: Request):
    try:
        data = await request.json()
        # 테스트 데이터에 명시된 IP를 우선 사용하고, 없으면 요청을 보낸 클라이언트의 IP를 사용
        client_ip = data.get("ip", request.client.host)

        # 1단계: 룰 기반 탐지
        if rule_detect(data):
            print(f"[RULE] 탐지됨! IP: {client_ip}")
            # Responder에 차단 요청
            async with httpx.AsyncClient() as client:
                await client.post(RESPONDER_URL, json={
                    "ip": client_ip,
                    "reason": "Rule-based detection"
                })
            return {"anomaly": True, "method": "rule"}

        # 2단계: ML 기반 탐지
        if ml_detect(data):
            print(f"[ML] 탐지됨! IP: {client_ip}")
            # Responder에 차단 요청
            async with httpx.AsyncClient() as client:
                await client.post(RESPONDER_URL, json={
                    "ip": client_ip,
                    "reason": "ML-based detection"
                })
            return {"anomaly": True, "method": "ml"}

        return {"anomaly": False, "method": "normal"}
    

    except Exception as e:
        print(f"[ERROR] {e}")
        return JSONResponse(
            status_code=400,
            content={"anomaly": "error", "detail": str(e)}
        )

@app.get("/")
def root():
    return {"message": "WAF Microservice is running"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
