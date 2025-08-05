import uvicorn
from fastapi import FastAPI, Request
from detection import rule_detect
from ml_detection import ml_detect  # ML 탐지기 (예: IsolationForest 등)

app = FastAPI()

from fastapi.responses import JSONResponse

@app.post("/detect")
async def detect(request: Request):
    try:
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
