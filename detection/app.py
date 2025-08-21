import uvicorn
from fastapi import FastAPI, Request
from detection import rule_detect
from ml_detection import ml_detect
import httpx

# FastAPI 앱 생성
app = FastAPI()

import os

# 응답기 URL 설정, 환경 변수가 없으면 기본 URL 사용
# ECS 환경 변수를 사용해 URL을 설정할 수 있음
RESPONDER_URL = os.getenv("RESPONDER_URL", "http://WAFMicroservice-ALB-633895454.ap-northeast-2.elb.amazonaws.com/block")

from fastapi.responses import JSONResponse

# "/detect" 엔드포인트, POST 요청 처리
@app.post("/detect")
async def detect(request: Request):
    """
    - 클라이언트로부터 받은 요청 데이터를 분석하여 비정상적인 트래픽을 탐지
    - 룰 기반 탐지와 머신러닝 기반 탐지를 순차적으로 수행
    - 탐지된 경우, Responder 서비스에 차단 요청을 보냄
    """
    try:
        data = await request.json()
        # 요청 데이터에 IP가 있으면 사용, 없으면 클라이언트 IP 사용
        client_ip = data.get("ip", request.client.host)

        # 1단계: 룰 기반 탐지
        if rule_detect(data):
            print(f"[RULE] 탐지됨! IP: {client_ip}")
            # Responder에 차단 요청 전송
            async with httpx.AsyncClient() as client:
                await client.post(RESPONDER_URL, json={
                    "ip": client_ip,
                    "reason": "Rule-based detection"
                })
            return {"anomaly": True, "method": "rule"}

        # 2단계: ML 기반 탐지
        if ml_detect(data):
            print(f"[ML] 탐지됨! IP: {client_ip}")
            # Responder에 차단 요청 전송
            async with httpx.AsyncClient() as client:
                await client.post(RESPONDER_URL, json={
                    "ip": client_ip,
                    "reason": "ML-based detection"
                })
            return {"anomaly": True, "method": "ml"}

        # 정상 트래픽으로 판단
        return {"anomaly": False, "method": "normal"}
    

    except Exception as e:
        # 오류 발생 시 로그 출력 및 에러 응답 반환
        print(f"[ERROR] {e}")
        return JSONResponse(
            status_code=400,
            content={"anomaly": "error", "detail": str(e)}
        )

# 루트 엔드포인트, GET 요청 처리(서버 접속한 경우)
@app.get("/")
def root():
    # 서비스 상태 확인용 메시지 반환
    return {"message": "WAF Microservice is running"}

# 메인 실행 부분
if __name__ == "__main__":
    # uvicorn을 사용하여 FastAPI 앱 실행
    uvicorn.run(app, host="0.0.0.0", port=5000)