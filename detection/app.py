from fastapi import FastAPI, Request
from .detection import rule_detect
from .ml_detection import ml_detect  # ML 탐지기 (예: IsolationForest 등)

app = FastAPI()

@app.post("/detect")
async def detect(request: Request):
    data = await request.json()

    # 1단계: 룰 기반 탐지
    if rule_detect(data):
        print("[RULE] 탐지됨!")
        return {"anomaly": True, "method": "rule"}

    # 2단계: ML 기반 탐지
    if ml_detect(data):
        print("[ML] 탐지됨!")
        return {"anomaly": True, "method": "ml"}

    return {"anomaly": False, "method": "normal"}
