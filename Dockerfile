# Dockerfile (위치: WAFMicroservice/Dockerfile)

FROM python:3.10-slim

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 복사
COPY requirements.txt .

# 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 전체 코드 복사
COPY . .

# Flask 서버 실행 (host=0.0.0.0 → 외부에서 접근 가능)
CMD ["uvicorn", "detection.app:app", "--host", "0.0.0.0", "--port", "8000"]