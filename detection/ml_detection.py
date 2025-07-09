"""
ml_detection.py
────────────────
· model.pkl( Isolation-Forest + LabelEncoder 번들 ) 로드
· ml_detect(data) → 이상 여부(bool) 반환
"""

import os, joblib, pandas as pd

#────────────────── 모델 로드 ──────────────────#
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
try:
    bundle      = joblib.load(MODEL_PATH)
    _model      = bundle["model"]
    _enc        = bundle["encoder"]
    _model_none = False
except FileNotFoundError:
    _model_none = True           # 모델이 없으면 항상 정상(True → 미탐지)

#────────────────── 전처리 ─────────────────────#
def _norm_accept(raw: str | None) -> str:
    """Accept 헤더를 4가지 카테고리(html|json|wildcard|none)로 정규화"""
    if not raw:
        return "none"
    raw = raw.lower()
    if "*/*" in raw:
        return "wildcard"
    if "json" in raw:
        return "json"
    if "html" in raw:
        return "html"
    return "none"

_FEATURES = ["req_count", "interval", "uri_len", "ua_len", "accept_type"]

def _feature_vector(data: dict) -> pd.DataFrame:
    hdr = {k.lower(): v for k, v in (data.get("headers") or {}).items()}

    accept_enc = 0
    if not _model_none:                       # encoder가 로드된 경우에만 변환
        accept_enc = _enc.transform([_norm_accept(hdr.get("accept"))])[0]

    vec = pd.DataFrame([{
        "req_count"  : data.get("req_count", 0),
        "interval"   : data.get("interval", 0.0),
        "uri_len"    : len(data.get("uri", "/")),
        "ua_len"     : len(hdr.get("user-agent", "")),
        "accept_type": accept_enc,
    }])

    return vec.loc[:, _FEATURES]              # 학습 시 열 순서 고정

#────────────────── 추론 API ───────────────────#
def ml_detect(data: dict) -> bool:
    """
    True  → 이상 트래픽
    False → 정상
    (model.pkl 이 없으면 항상 False)
    """
    if _model_none:
        return False

    vec  = _feature_vector(data)
    pred = _model.predict(vec)                # -1:이상, 1:정상
    return bool(pred[0] == -1)
