import pandas as pd
import numpy as np
import joblib
import math
from urllib.parse import urlparse
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest

# ─── 데이터 로딩 ───
df = pd.read_csv("traffic_log.csv").sort_values(["ip", "timestamp"])

# ─── 기본 전처리 ───
df["path_depth"] = df["path"].astype(str).str.count("/")
df["referer_domain"] = df["referer"].astype(str).apply(lambda x: urlparse(x).netloc)
df["cookie_count"] = df["cookie"].astype(str).apply(lambda x: len(x.split(";")) if x else 0)
df["interval"] = df.groupby("ip")["timestamp"].diff().fillna(1).clip(lower=0.1)
df["interval"] = np.log1p(df["interval"])
df["req_count"] = df.groupby("ip")["ip"].transform("count")

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
enc_method = LabelEncoder()
enc_method.fit(df["method"])
df["method"] = df["method"].apply(lambda x: safe_label_encode(enc_method, x))
joblib.dump(enc_method, "enc_method.pkl")

# ─── accept_type 인코딩 (max+1 방식) ───
enc_accept = LabelEncoder()
enc_accept.fit(df["accept_type"])
df["accept_type"] = df["accept_type"].apply(encode_accept)
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

# ─── 모델 구성 및 학습 ───
pipe = make_pipeline(
    StandardScaler(),
    IsolationForest(contamination=0.1, random_state=42)
)
pipe.fit(df[FEATURES])

# ─── 모델 저장 ───
joblib.dump(pipe, "model.pkl")
print("✅ 저장 완료: model.pkl")
