import os, joblib, pandas as pd
import math, time
from collections import deque
from urllib.parse import urlparse

# IP별 상태 저장을 위한 딕셔너리
# - 각 IP의 요청 기록(타임스탬프, 경로)을 저장하여 시간 기반 특징을 계산하는 데 사용
ip_states = {}

#────────────────── 모델 로드 ──────────────────#
# - 필요한 모델 및 인코더 파일의 경로를 설정
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
    # - Isolation Forest와 LOF 모델 로드
    # - 두 모델 모두 스케일러가 포함된 파이프라인 형태
    _model = joblib.load(MODEL_PATH)
    _lof_model = joblib.load(LOF_MODEL_PATH)
    _model_none = False
except FileNotFoundError as e:
    print(f"[MODEL LOAD ERROR] {e}")
    _model_none = True

# - 범주형 데이터를 인코딩하기 위한 LabelEncoder 로드
enc_method  = joblib.load(ENC_METHOD_PATH)
enc_accept  = joblib.load(ENC_ACCEPT_PATH)
enc_referer = joblib.load(ENC_REF_PATH)


#────────────────── 특징 목록 정의 ──────────────────#
# - 모델 학습에 사용된 특징(feature)들의 순서와 목록을 정의
_FEATURES = [
    "path_depth",               # 경로 깊이
    "path_token_count",         # 경로 토큰 수
    "path_token_numeric_ratio", # 경로 토큰 중 숫자 비율
    "uri_entropy",              # URI 엔트로피
    "auth_validity",            # 인증 헤더 유효성
    "referer_domain",           # 리퍼러 도메인 (인코딩됨)
    "method",                   # HTTP 메소드 (인코딩됨)
    "accept_type",              # Accept 헤더 타입 (인코딩됨)
    "cookie_count",             # 쿠키 수
    "req_count",                # 60초 내 총 요청 수
    "interval",                 # 이전 요청과의 시간 간격
    "req_count_in_last_10s",    # 10초 내 요청 수
    "unique_paths_in_last_60s"  # 60초 내 고유 경로 수
]

#────────────────── 엔트로피 계산 ──────────────────#
def _calc_entropy(s: str) -> float:
    # - 문자열의 엔트로피를 계산하여 복잡도를 측정
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

# ───────────────── 인코딩 ───────────────────#
# - 범주형 데이터를 학습된 인코더를 사용해 숫자형으로 변환
def _encode_method(v: str) -> int:
    # - HTTP 메소드를 인코딩
    try:
        return enc_method.transform([v])[0]
    except ValueError:
        return -999 # 학습되지 않은 메소드는 -999로 처리

def _encode_accept(v: str) -> int:
    # - Accept 헤더를 인코딩
    try:
        # - 학습 시와 동일하게, 첫 번째 MIME 타입만 사용
        main_type = v.split(',')[0].strip()
        return enc_accept.transform([main_type])[0]
    except (ValueError, IndexError):
        # - 처음 보는 타입은 '기타'(*/*)로 처리
        try:
            return enc_accept.transform(["*/*"])[0]
        except ValueError:
            return -1 # */* 조차 없으면 -1 반환

def _encode_referer(v: str) -> int:
    # - Referer 헤더의 도메인을 인코딩
    try:
        domain = urlparse(v).netloc
        # - 학습된 도메인이면 해당 값으로, 아니면 __OTHER__로 처리
        val = domain if domain in enc_referer.classes_ else "__OTHER__"
        return enc_referer.transform([val])[0]
    except:
        return enc_referer.transform(["__OTHER__"])[0]

def _feature_vector(data: dict) -> pd.DataFrame:
    # - 입력 데이터를 받아 모델이 예측할 수 있는 특징 벡터로 변환
    def get_auth_validity(auth: str) -> int:
        # - Authorization 헤더의 유효성을 검사하여 점수 반환
        auth = str(auth)
        if not auth or auth.lower() == 'nan':
            return 0  # 헤더 없음
        
        parts = auth.split()
        if len(parts) != 2:
            return -1 # 형식 오류

        scheme, token = parts
        if scheme.lower() == 'bearer':
            return 1 if token.count('.') == 2 else -1 # JWT 형식 검사
        elif scheme.lower() == 'basic':
            return 1
        
        return -1

    # ─── IP별 상태 관리 ───
    ip = data.get("ip", "127.0.0.1")
    current_time = time.time()
    if ip not in ip_states:
        ip_states[ip] = {'requests': deque()}
    
    # - 60초가 지난 오래된 요청 기록은 제거
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
    
    # ─── 시간 윈도우 기반 특징 계산 ───
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


#────────────────── ML 탐지 ───────────────────#
def ml_detect(data: dict) -> bool:
    # - 최종적으로 ML 모델을 사용하여 이상 탐지를 수행하는 함수
    if _model_none:
        return False # 모델이 로드되지 않았으면 탐지 수행 안함
    try:
        vec = _feature_vector(data)
        
        # - 두 모델(Isolation Forest, LOF)로 예측 수행
        # - 파이프라인에 스케일러가 포함되어 있어 별도 스케일링 불필요
        pred_if = _model.predict(vec)[0]
        pred_lof = _lof_model.predict(vec)[0]

        # - 두 모델 중 하나라도 이상치(-1)로 판단하면 비정상(True)으로 간주
        if pred_if == -1 or pred_lof == -1:
            return True
            
        return False

    except Exception as e:
        print(f"[ML DETECT ERROR] {e}")
        return False