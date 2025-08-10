# detection/Dockerfile

# 1. 베이스 이미지 선택 (Python 3.11)
FROM python:3.11-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 의존성 파일 먼저 복사
COPY requirements.txt .

# 4. 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 5. 나머지 소스 코드 복사
COPY . .

# 6. detection 서비스가 사용할 포트 노출 (5000번으로 가정)
EXPOSE 5000

# 7. 컨테이너 시작 명령어 정의
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
