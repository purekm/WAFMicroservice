import os, joblib, pandas as pd
import math, time
from collections import deque
from urllib.parse import urlparse

# IP별 상태 저장을 위한 딕셔너리
ip_states = {}

#────────────────── 모델 로드 ──────────────────#
BASE_DIR = os.path.dirname(__file__)
MODEL_PATH      = os.path.join(BASE_DIR, "model.pkl")
LOF_MODEL_PATH  = os.path.join(BASE_DIR, "lof_model.pkl")
ENC_METHOD_PATH = os.path.join(BASE_DIR, "enc_method.pkl")
ENC_ACCEPT_PATH = os.path.join(BASE_DIR, "enc_accept.pkl")
ENC_REF_PATH    = os.path.join(BASE_DIR, "enc_referer.pkl")

_model = None
_lof_model = None
_model_none = True

try:
    # 이제 두 모델 모두 스케일러가 포함된 파이프라인입니다.
    _model = joblib.load(MODEL_PATH)
    _lof_model = joblib.load(LOF_MODEL_PATH)
    _model_none = False
except FileNotFoundError as e:
    print(f"[MODEL LOAD ERROR] {e}")
    _model_none = True
    
enc_method  = joblib.load(ENC_METHOD_PATH)
enc_accept  = joblib.load(ENC_ACCEPT_PATH)
enc_referer = joblib.load(ENC_REF_PATH)


#────────────────── 특징 목록 정의 ──────────────────#
_FEATURES = [
    "path_depth",
    "path_token_count",
    "path_token_numeric_ratio",
    "uri_entropy",
    "auth_validity",
    "referer_domain",
    "method",
    "accept_type",
    "cookie_count",
    "req_count",
    "interval",
    "req_count_in_last_10s",
    "unique_paths_in_last_60s"
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
        # 학습 시와 동일하게, 첫 번째 MIME 타입만 사용
        main_type = v.split(',')[0].strip()
        return enc_accept.transform([main_type])[0]
    except (ValueError, IndexError):
        # 처음 보는 타입이 들어오면, 가장 가능성이 높은 '기타'(*/*) 값으로 처리
        try:
            return enc_accept.transform(["*/*"])[0]
        except ValueError:
            return -1 # 만약 학습 데이터에 */* 조차 없다면 -1 반환

def _encode_referer(v: str) -> int:
    try:
        domain = urlparse(v).netloc
        val = domain if domain in enc_referer.classes_ else "__OTHER__"
        return enc_referer.transform([val])[0]
    except:
        return enc_referer.transform(["__OTHER__"])[0]

def _feature_vector(data: dict) -> pd.DataFrame:
    def get_auth_validity(auth: str) -> int:
        auth = str(auth)
        if not auth or auth.lower() == 'nan':
            return 0  # 헤더 없음
        
        parts = auth.split()
        if len(parts) != 2:
            return -1 # 형식 오류

        scheme, token = parts
        if scheme.lower() == 'bearer':
            return 1 if token.count('.') == 2 else -1
        elif scheme.lower() == 'basic':
            return 1
        
        return -1

    # ─── 상태 관리 ───
    ip = data.get("ip", "127.0.0.1")
    current_time = time.time()
    if ip not in ip_states:
        ip_states[ip] = {'requests': deque()}
    
    state = ip_states[ip]['requests']
    while state and state[0][0] < current_time - 60:
        state.popleft()

    # ─── 데이터 추출 ───
    headers = data.get("headers", {})
    path = data.get("path", "/")
    method = data.get("method", "GET")
    accept_header = headers.get("Accept", "")
    referer_header = headers.get("Referer", "")
    authorization_header = headers.get("Authorization", "")
    
    # ─── 시간 윈도우 특징 계산 ───
    state.append((current_time, path))
    req_count_in_last_10s = sum(1 for ts, _ in state if ts > current_time - 10)
    paths_in_last_60s = {p for ts, p in state if ts > current_time - 60}
    unique_paths_in_last_60s = len(paths_in_last_60s)

    # ─── 특징 벡터 생성 ───
    tokens = [t for t in path.strip("/").split("/") if t]

    vec = pd.DataFrame([{
        "path_depth"                : path.count("/"),
        "path_token_count"          : len(tokens),
        "path_token_numeric_ratio"  : sum(t.isnumeric() for t in tokens) / len(tokens) if tokens else 0.0,
        "uri_entropy"               : _calc_entropy(path),
        "auth_validity"             : get_auth_validity(authorization_header),
        "referer_domain"            : _encode_referer(referer_header),
        "method"                    : _encode_method(method),
        "accept_type"               : _encode_accept(accept_header),
        "cookie_count"              : len(data.get("cookies", {})),
        "req_count"                 : len(state),
        "interval"                  : current_time - state[-2][0] if len(state) > 1 else 0,
        "req_count_in_last_10s"     : req_count_in_last_10s,
        "unique_paths_in_last_60s": unique_paths_in_last_60s
    }])

    return vec.loc[:, _FEATURES]


#────────────────── 추론 API ───────────────────#
def ml_detect(data: dict) -> bool:
    if _model_none:
        return False
    try:
        vec = _feature_vector(data)
        
        # 디버깅을 위해 피처 벡터 출력
        print("\n[DEBUG] Feature Vector:")
        print(vec.to_string())

        # 두 파이프라인 모델이 알아서 스케일링 후 예측
        pred_if = _model.predict(vec)[0]
        pred_lof = _lof_model.predict(vec)[0]

        # 디버그 출력
        print(f"[ML DETECT DEBUG] IF: {pred_if}, LOF: {pred_lof}")

        # 한 모델이라도 이상치(-1)로 판단하면 True 반환
        if pred_if == -1 or pred_lof == -1:
            return True
            
        return False

    except Exception as e:
        print(f"[ML DETECT ERROR] {e}")
        return False
