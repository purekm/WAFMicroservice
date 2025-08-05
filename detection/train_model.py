import pandas as pd
import numpy as np
import joblib
import math
from urllib.parse import urlparse
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# ─── 데이터 로딩 ───
df = pd.read_csv("traffic_log.csv").sort_values(["ip", "timestamp"])

# ─── 기본 전처리 ───
df["path_depth"] = df["path"].astype(str).str.count("/")
df["referer_domain"] = df["referer"].astype(str).apply(lambda x: urlparse(x).netloc)
# ─── 인증 헤더 유효성 분석 ───
def get_auth_validity(auth: str) -> int:
    auth = str(auth)
    if not auth or auth.lower() == 'nan':
        return 0  # 헤더 없음
    
    parts = auth.split()
    if len(parts) != 2:
        return -1 # 형식 오류

    scheme, token = parts
    if scheme.lower() == 'bearer':
        # JWT는 보통 2개의 점을 가짐
        return 1 if token.count('.') == 2 else -1
    elif scheme.lower() == 'basic':
        return 1 # Basic은 형식만 맞으면 정상으로 간주
    
    return -1 # 알려지지 않은 스킴

df["auth_validity"] = df["authorization"].apply(get_auth_validity)

# ─── 시간 윈도우 특징 생성 ───
# Unix 타임스탬프를 datetime 객체로 변환
df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
df = df.sort_values('timestamp').set_index('timestamp')

# IP별로 그룹화하여 롤링 특징 계산
df['req_count'] = df.groupby('ip')['path'].rolling('60s').count().reset_index(0, drop=True)
df['req_count_in_last_10s'] = df.groupby('ip')['path'].rolling('10s').count().reset_index(0, drop=True)

# .rolling().apply()가 문자열에 직접 작동하지 않으므로, 경로를 숫자 코드로 변환 후 nunique 계산
df['path_code'], _ = pd.factorize(df['path'])
df['unique_paths_in_last_60s'] = df.groupby('ip')['path_code'].rolling('60s').apply(lambda x: x.nunique()).reset_index(0, drop=True)
df = df.drop(columns=['path_code']) # 임시 컬럼 제거

# NaN 값은 0으로 채움 (윈도우에 데이터가 없는 경우)
df.fillna(0, inplace=True)
df = df.reset_index() # 인덱스 리셋

# ─── 요청 간격(interval) 특징 생성 ───
df['interval'] = df.groupby('ip')['timestamp'].diff().dt.total_seconds().fillna(0)


# ─── path token 기반 feature ───
def extract_tokens(path):
    return [t for t in path.strip("/").split("/") if t]

df["path_tokens"] = df["path"].astype(str).apply(extract_tokens)
df["path_token_count"] = df["path_tokens"].apply(len)
df["path_token_numeric_ratio"] = df["path_tokens"].apply(
    lambda tokens: sum(t.isnumeric() for t in tokens) / len(tokens) if tokens else 0
)

# ─── uri 엔트로피 ───
def calculate_entropy(s):
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

df["uri_entropy"] = df["path"].astype(str).apply(calculate_entropy)

# ─── -999 방식 인코딩 함수 ───
def safe_label_encode(encoder, value, unknown_value=-999):
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return unknown_value

# ─── max+1 방식 인코딩 함수 ───
def encode_accept(value):
    try:
        return enc_accept.transform([value])[0]
    except ValueError:
        return len(enc_accept.classes_)

# ─── method 인코딩 (LabelEncoder + -999 처리) ───
df["method"] = df["method"].astype(str)
enc_method = LabelEncoder()
enc_method.fit(df["method"])
df["method"] = df["method"].apply(lambda x: safe_label_encode(enc_method, x))
joblib.dump(enc_method, "enc_method.pkl")

# ─── accept_type 인코딩 (첫 번째 타입만 사용) ───
df["accept_type"] = df["accept_type"].astype(str).str.split(",").str[0].str.strip()
enc_accept = LabelEncoder()
enc_accept.fit(df["accept_type"])
df["accept_type"] = enc_accept.transform(df["accept_type"])
joblib.dump(enc_accept, "enc_accept.pkl")

# ─── referer_domain 인코딩 (상위 20개 + __OTHER__) ───
top_20 = df["referer_domain"].value_counts().nlargest(20).index.tolist()
df["referer_domain"] = df["referer_domain"].apply(lambda x: x if x in top_20 else "__OTHER__")

# ★ 꼭 학습용 데이터에 '__OTHER__'이 포함되도록 보장
if '__OTHER__' not in df['referer_domain'].values:
    df.loc[df.index[0], 'referer_domain'] = '__OTHER__'
    
enc_referer = LabelEncoder()
enc_referer.fit(df["referer_domain"])
df["referer_domain"] = enc_referer.transform(df["referer_domain"])
joblib.dump(enc_referer, "enc_referer.pkl")

# ─── 특징 목록 ───
FEATURES = [
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

# ─── 모델 구성 및 학습 ───
# 각 모델은 독립적으로 이상 점수를 예측함 (-1: 이상, 1: 정상)
isolation_forest = IsolationForest(contamination=0.1, random_state=42)
lof = LocalOutlierFactor(novelty=True, contamination=0.1)

# 두 모델 모두 스케일러를 포함한 파이프라인으로 구성
pipe_if = make_pipeline(StandardScaler(), isolation_forest)
pipe_lof = make_pipeline(StandardScaler(), lof)

# 파이프라인 학습
pipe_if.fit(df[FEATURES])
pipe_lof.fit(df[FEATURES])

# ─── 모델 저장 ───
joblib.dump(pipe_if, "model.pkl")
joblib.dump(pipe_lof, "lof_model.pkl")
print("저장 완료: model.pkl, lof_model.pkl")
