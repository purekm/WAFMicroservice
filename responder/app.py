
import os
import redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# --- Redis 연결 설정 ---
# docker-compose에서 설정한 환경 변수 'REDIS_HOST'를 읽어옵니다.
# 환경 변수가 없으면 기본값으로 'redis'를 사용합니다.
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = 6379
BLACKLIST_SET_KEY = "ip_blacklist" # Redis에서 사용할 Set의 키 이름

try:
    # decode_responses=True: Redis에서 받은 응답을 자동으로 UTF-8 문자열로 변환합니다.
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        decode_responses=True,
        socket_connect_timeout=5
    )
    redis_client.ping() # 연결 테스트
    print(f"✅ Successfully connected to Redis at {REDIS_HOST}")
except redis.exceptions.ConnectionError as e:
    print(f"❌ Error connecting to Redis: {e}")
    redis_client = None

# --- 데이터 모델 정의 ---
class BlockRequest(BaseModel):
    ip: str

# --- FastAPI 앱 정의 ---
app = FastAPI(title="WAF Responder Service")

# --- API 엔드포인트 구현 ---
@app.post("/block", summary="Block an IP address")
def block_ip(request: BlockRequest):
    """특정 IP를 블랙리스트(Set)에 추가합니다."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")
    
    # SADD: Set에 멤버를 추가. 이미 있으면 아무 변화 없음. 1을 반환하면 추가 성공, 0은 이미 있었음을 의미.
    added_count = redis_client.sadd(BLACKLIST_SET_KEY, request.ip)
    return {"status": "success", "ip": request.ip, "is_newly_blocked": bool(added_count)}

@app.post("/unblock", summary="Unblock an IP address")
def unblock_ip(request: BlockRequest):
    """특정 IP를 블랙리스트(Set)에서 제거합니다."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    # SREM: Set에서 특정 멤버를 제거. 1을 반환하면 제거 성공, 0은 원래 없었음을 의미.
    removed_count = redis_client.srem(BLACKLIST_SET_KEY, request.ip)
    if removed_count > 0:
        return {"status": "success", "ip": request.ip, "unblocked": True}
    else:
        raise HTTPException(status_code=404, detail=f"IP {request.ip} was not found in the blacklist.")

@app.get("/is_blocked/{ip}", summary="Check if an IP is blocked")
def is_ip_blocked(ip: str):
    """특정 IP가 블랙리스트(Set)에 있는지 확인합니다."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    # SISMEMBER: Set에 특정 멤버가 존재하는지 확인 (True/False 반환)
    is_member = redis_client.sismember(BLACKLIST_SET_KEY, ip)
    return {"ip": ip, "is_blocked": is_member}

@app.get("/health", summary="Health Check")
def health_check():
    """서비스 상태 및 Redis 연결 상태를 확인합니다."""
    redis_ok = False
    if redis_client:
        try:
            redis_ok = redis_client.ping()
        except redis.exceptions.ConnectionError:
            redis_ok = False
            
    if not redis_ok:
        raise HTTPException(status_code=503, detail="Redis connection failed")
        
    return {"status": "ok", "redis_connection": "ok"}
