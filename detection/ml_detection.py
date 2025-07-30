import os, joblib, pandas as pd
import math

#────────────────── 모델 로드 ──────────────────#
BASE_DIR = os.path.dirname(__file__)
MODEL_PATH      = os.path.join(BASE_DIR, "model.pkl")
ENC_METHOD_PATH = os.path.join(BASE_DIR, "enc_method.pkl")
ENC_ACCEPT_PATH = os.path.join(BASE_DIR, "enc_accept.pkl")
ENC_REF_PATH    = os.path.join(BASE_DIR, "enc_referer.pkl")

try:
    _model = joblib.load(MODEL_PATH)  # pipeline 그대로 로드
    _model_none = False
except FileNotFoundError:
    _model_none = True
    
enc_method  = joblib.load(ENC_METHOD_PATH)
enc_accept  = joblib.load(ENC_ACCEPT_PATH)
enc_referer = joblib.load(ENC_REF_PATH)


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

# ─── 인코딩 헬퍼 ───────────────────
def _encode_method(v: str) -> int:
    try:
        return enc_method.transform([v])[0]
    except ValueError:
        return -999

def _encode_accept(v: str) -> int:
    try:
        return enc_accept.transform([v])[0]
    except ValueError:
        return len(enc_accept.classes_)

def _encode_referer(v: str) -> int:
    val = v if v in enc_referer.classes_ else "__OTHER__"
    return enc_referer.transform([val])[0]

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
        # ✏️ 문자열 → 내부 인코딩
        "referer_domain": _encode_referer(data.get("referer_domain", "")),
        "method":         _encode_method(data.get("method", "")),
        "accept_type":    _encode_accept(data.get("accept_type", ""))
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
