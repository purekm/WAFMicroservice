# responder/Dockerfile

# 1. 베이스 이미지 선택
FROM python:3.11-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 의존성 파일 복사 (responder 폴더 내의 requirements.txt)
COPY requirements.txt .

# 4. 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 5. 나머지 소스 코드 복사 (responder 폴더의 모든 내용)
COPY . .

# 6. 서비스 포트 노출
EXPOSE 8000

# 7. 컨테이너 시작 명령어
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
