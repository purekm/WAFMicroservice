from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import pandas as pd, joblib, pathlib
import numpy as np

# ─── 데이터 준비 ───
N = 2000
df = pd.DataFrame({
    "req_count"   : np.random.normal(20, 10,  N),
    "interval"    : np.random.normal(3.0, 1.0, N),
    "uri_len"     : np.random.normal(15, 5,   N),
    "ua_len"      : np.random.normal(60, 10,  N),
    "accept_type" : np.random.choice(["html","json","wildcard","none"], N),
})

# ─── 인코딩 ───
enc = LabelEncoder()
df["accept_type"] = enc.fit_transform(df["accept_type"])
FEATURES = ["req_count","interval","uri_len","ua_len","accept_type"]

# ─── 모델 구성 ───
pipe = make_pipeline(
    StandardScaler(),
    IsolationForest(contamination=0.05, random_state=42)
)
pipe.fit(df[FEATURES])

# ─── 저장 ───
out_path = pathlib.Path("model.pkl")
joblib.dump({"model": pipe, "encoder": enc}, out_path)
print(f"✅ 저장 완료: {out_path}")
