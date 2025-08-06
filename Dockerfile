# Dockerfile (위치: WAFMicroservice/Dockerfile)

FROM python:3.10-slim

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# detection 디렉토리의 모든 내용을 /app 으로 복사
COPY ./detection/ .

# FAST API 서버 실행
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]