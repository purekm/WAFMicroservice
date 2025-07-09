"""
ml_detection.py
───────────────
• 사전 학습된 모델(model.pkl) 로드 → ml_detect(data) 로 이상 여부 반환
• 기본 예시는 IsolationForest (비지도)  ➜ 모델 파일이 없으면 항상 False 반환
• feature_vector(data) 함수에서 필요한 특징 벡터를 정의해 주세요.
"""

import os, joblib, numpy as np
import pandas as pd

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

try:
    _model = joblib.load(_MODEL_PATH)
    _model_loaded = True
except FileNotFoundError:
    _model_loaded = False
    _model = None
    print("[ML-DETECT] 모델 파일이 없습니다(model.pkl). 모든 요청을 정상으로 간주합니다.")


def _feature_vector(data: dict) -> pd.DataFrame:
    """
    특징 벡터를 DataFrame으로 반환 → Sklearn 경고 제거용
    """
    req_count   = data.get("req_count", 0)
    interval    = data.get("interval", 0.0)
    uri_len     = len(data.get("uri", "/"))
    ua_len      = len(data.get("user_agent", ""))

    return pd.DataFrame([{
        "req_count": req_count,
        "interval": interval,
        "uri_len": uri_len,
        "ua_len": ua_len
    }])

def ml_detect(data: dict) -> bool:
    """ML 기반 이상 탐지 (모델이 없으면 False)"""
    if not _model_loaded:
        return False

    vec = _feature_vector(data)
    pred = _model.predict(vec)      # IsolationForest  →  -1:이상 / 1:정상
    return bool(pred[0] == -1)
