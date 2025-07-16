import pandas as pd
import numpy as np
import joblib
import pathlib
from urllib.parse import urlparse
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
import math

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

# ─── 인코딩 ───
def safe_label_encode(encoder, value, unknown_value=-999):
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return unknown_value
    
enc_accept = LabelEncoder()
enc_accept.fit(df["accept_type"])
df["accept_type"] = enc_accept.transform(df["accept_type"])
joblib.dump(enc_accept, "enc_accept.pkl")

enc_method = LabelEncoder()
enc_method.fit(df["method"])
df["method"] = enc_method.transform(df["method"])
joblib.dump(enc_method, "enc_method.pkl")

enc_referer = LabelEncoder()
enc_referer.fit(df["referer_domain"])
df["referer_domain"] = enc_referer.transform(df["referer_domain"])
joblib.dump(enc_referer, "enc_referer.pkl")

# ─── 최종 특징 목록 ───
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
