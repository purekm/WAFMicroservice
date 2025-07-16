import os, joblib, pandas as pd
import math

#────────────────── 모델 로드 ──────────────────#
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

try:
    _model = joblib.load(MODEL_PATH)  # pipeline 그대로 로드
    _model_none = False
except FileNotFoundError:
    _model_none = True

#────────────────── 특징 목록 정의 ──────────────────#
_FEATURES = [
    "req_count",
    "interval",
    "path_depth",
    "path_token_count",
    "path_token_numeric_ratio",
    "uri_entropy",
    "cookie_count",
    "referer_domain",
    "method",
    "accept_type"
]

#────────────────── 엔트로피 계산 ──────────────────#
def _calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

#────────────────── 특징 벡터 구성 ──────────────────#
def _feature_vector(data: dict) -> pd.DataFrame:
    uri = data.get("uri", "/")
    tokens = [t for t in uri.strip("/").split("/") if t]
    cookie_header = data.get("headers", {}).get("Cookie", "")
    cookie_count = len(cookie_header.split(";")) if cookie_header else 0

    vec = pd.DataFrame([{
        "req_count"                 : float(data.get("req_count", 0)),
        "interval"                  : float(data.get("interval", 0.0)),
        "path_depth"                : uri.count("/"),
        "path_token_count"          : len(tokens),
        "path_token_numeric_ratio"  : sum(t.isnumeric() for t in tokens) / len(tokens) if tokens else 0.0,
        "uri_entropy"               : _calc_entropy(uri),
        "cookie_count"              : cookie_count,
        "referer_domain"            : int(data.get("referer_domain", 0)),
        "method"                    : int(data.get("method", 0)),
        "accept_type"               : int(data.get("accept_type", 0))
    }])

    return vec.loc[:, _FEATURES]

#────────────────── 추론 API ───────────────────#
def ml_detect(data: dict) -> bool:
    if _model_none:
        return False
    try:
        vec = _feature_vector(data)
        pred = _model.predict(vec)  # -1: 이상치
        return bool(pred[0] == -1)
    except Exception as e:
        print(f"[ML DETECT ERROR] {e}")
        return False
