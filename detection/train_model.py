import pandas as pd
import numpy as np
import joblib
import math
from urllib.parse import urlparse
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# ─── 1. 데이터 로딩 및 기본 전처리 ───
# - 생성된 트래픽 로그를 로드하고, IP와 타임스탬프 순으로 정렬
df = pd.read_csv("traffic_log.csv").sort_values(["ip", "timestamp"])

# - 경로 깊이, 리퍼러 도메인 등 기본적인 특징 추출
df["path_depth"] = df["path"].astype(str).str.count("/")
df["referer_domain"] = df["referer"].astype(str).apply(lambda x: urlparse(x).netloc)

# ─── 2. 특징 공학 (Feature Engineering) ───

# ─── 2-1. 인증 헤더 유효성 분석 ───
def get_auth_validity(auth: str) -> int:
    """
    - Authorization 헤더의 유효성을 분석하여 수치로 변환
    - 0: 헤더 없음, 1: 유효 형식, -1: 유효하지 않은 형식
    """
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
        return 1 # Basic은 형식만 맞으면 정상으로 간주
    
    return -1 # 알려지지 않은 스킴

df["auth_validity"] = df["authorization"].apply(get_auth_validity)

# ─── 2-2. 시간 윈도우 기반 특징 생성 ───
# - IP별로 시간 순서에 따른 행동 패턴을 분석하기 위한 특징
df['timestamp_dt'] = pd.to_datetime(df['timestamp'], unit='s')
df = df.sort_values('timestamp_dt').set_index('timestamp_dt')

# - IP별 60초/10초 롤링 윈도우 내 요청 횟수 계산
df['req_count'] = df.groupby('ip')['path'].rolling('60s').count().reset_index(0, drop=True)
df['req_count_in_last_10s'] = df.groupby('ip')['path'].rolling('10s').count().reset_index(0, drop=True)

# - IP별 60초 롤링 윈도우 내 고유 경로 수 계산
df['path_code'], _ = pd.factorize(df['path'])
df['unique_paths_in_last_60s'] = df.groupby('ip')['path_code'].rolling('60s').apply(lambda x: x.nunique()).reset_index(0, drop=True)
df = df.drop(columns=['path_code'])

# - 롤링 윈도우 초기에 발생하는 NaN 값은 0으로 채움
df.fillna(0, inplace=True)
df = df.reset_index()

# - IP별 요청 간 시간 간격 계산
df['interval'] = df.groupby('ip')['timestamp'].diff().fillna(0)


# ─── 2-3. 경로(Path) 토큰 기반 특징 ───
def extract_tokens(path):
    # - 경로를 '/' 기준으로 분리하여 토큰 리스트 생성
    return [t for t in path.strip("/").split("/") if t]

df["path_tokens"] = df["path"].astype(str).apply(extract_tokens)
df["path_token_count"] = df["path_tokens"].apply(len)
# - 경로 토큰 중 숫자가 차지하는 비율 계산
df["path_token_numeric_ratio"] = df["path_tokens"].apply(
    lambda tokens: sum(t.isnumeric() for t in tokens) / len(tokens) if tokens else 0
)

# ─── 2-4. URI 엔트로피 계산 ───
def calculate_entropy(s):
    # - URI의 복잡도를 측정. 높을수록 무작위 문자열일 가능성 있음
    if not s: return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

df["uri_entropy"] = df["path"].astype(str).apply(calculate_entropy)

# ─── 3. 범주형 데이터 인코딩 ───
# - 문자열 형태의 데이터를 모델이 학습할 수 있도록 숫자형으로 변환

# ─── 3-1. Method 인코딩 ───
df["method"] = df["method"].astype(str)
enc_method = LabelEncoder()
df["method"] = enc_method.fit_transform(df["method"])
joblib.dump(enc_method, "enc_method.pkl")

# ─── 3-2. Accept-Type 인코딩 ───
# - Accept 헤더는 복잡하므로, 가장 중요한 첫 번째 타입만 사용
df["accept_type"] = df["accept_type"].astype(str).str.split(",").str[0].str.strip()
enc_accept = LabelEncoder()
df["accept_type"] = enc_accept.fit_transform(df["accept_type"])
joblib.dump(enc_accept, "enc_accept.pkl")

# ─── 3-3. Referer-Domain 인코딩 ───
# - 빈도가 높은 상위 20개 도메인만 사용하고 나머지는 '__OTHER__'로 통합
top_20 = df["referer_domain"].value_counts().nlargest(20).index.tolist()
df["referer_domain"] = df["referer_domain"].apply(lambda x: x if x in top_20 else "__OTHER__")

# - 학습 데이터에 '__OTHER__'가 없는 경우를 대비해 강제로 추가
if '__OTHER__' not in df['referer_domain'].unique():
    df.loc[df.index[0], 'referer_domain'] = '__OTHER__'
    
enc_referer = LabelEncoder()
df["referer_domain"] = enc_referer.fit_transform(df["referer_domain"])
joblib.dump(enc_referer, "enc_referer.pkl")

# ─── 4. 모델 학습 및 저장 ───

# - 학습에 사용할 최종 특징 목록 정의
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

# - 이상치 탐지 모델 정의 (Isolation Forest, Local Outlier Factor)
# - contamination: 데이터셋에서 예상되는 이상치 비율
isolation_forest = IsolationForest(contamination=0.1, random_state=42)
lof = LocalOutlierFactor(novelty=True, contamination=0.1)

# - 데이터 스케일링과 모델 학습을 한 번에 처리하는 파이프라인 생성
# - StandardScaler: 각 특징의 평균을 0, 분산을 1로 조정하여 모델 성능 향상
pipe_if = make_pipeline(StandardScaler(), isolation_forest)
pipe_lof = make_pipeline(StandardScaler(), lof)

# - 파이프라인 학습
pipe_if.fit(df[FEATURES])
pipe_lof.fit(df[FEATURES])

# - 학습된 파이프라인(스케일러+모델)을 파일로 저장
joblib.dump(pipe_if, "model.pkl")
joblib.dump(pipe_lof, "lof_model.pkl")
print("저장 완료: model.pkl, lof_model.pkl")