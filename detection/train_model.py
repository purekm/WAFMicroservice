import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import pickle

# ▶ 정상 요청 2000건 생성
normal = pd.DataFrame({
    "req_count": np.random.normal(20, 5, 2000),       # 분당 평균 20회
    "interval": np.random.normal(3, 1, 2000),         # 3초 간격
    "uri_len": np.random.normal(15, 5, 2000),         # URI 평균 길이
    "ua_len": np.random.normal(60, 10, 2000),         # 정상 UA 평균 길이
})

# ▶ 이상 요청 100건 생성
attack = pd.DataFrame({
    "req_count": np.random.normal(120, 30, 100),      # 매우 많은 요청
    "interval": np.random.normal(0.5, 0.2, 100),      # 빠른 간격
    "uri_len": np.random.normal(5, 2, 100),           # 비정상 URI 길이
    "ua_len": np.random.normal(10, 5, 100),           # 비정상 UA 길이
})

# ▶ 병합 및 모델 학습
data = pd.concat([normal, attack], ignore_index=True)

model = IsolationForest(contamination=0.05, random_state=42) #contamination은 이상치 비율 
model.fit(data)

# ▶ 모델 저장
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ 모델 저장 완료: model.pkl")
