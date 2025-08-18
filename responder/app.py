
import os
import redis
from redis.cluster import RedisCluster, ClusterConnectionError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# --- Redis 연결 설정 ---
# docker-compose에서 설정한 환경 변수 'REDIS_HOST'를 읽어옵니다.
# 환경 변수가 없으면 기본값으로 'redis'를 사용합니다.
REDIS_HOST = os.getenv("REDIS_HOST", "clustercfg.wafcache2.jwukuh.apn2.cache.amazonaws.com")
REDIS_PORT = 6379
BLACKLIST_EXPIRATION_SECONDS = 300  # 5분

try:
    # decode_responses=True: Redis에서 받은 응답을 자동으로 UTF-8 문자열로 변환합니다.
    # Redis Cluster에 연결하기 위해 RedisCluster 클라이언트를 사용합니다.
    redis_client = RedisCluster(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=5,
        skip_full_coverage_check=True  # AWS ElastiCache와 같은 관리형 서비스를 위한 설정
    )
    redis_client.ping()  # 연결 테스트
    print(f"✅ Successfully connected to Redis Cluster at {REDIS_HOST}")
except (ClusterConnectionError, redis.exceptions.ConnectionError) as e:
    print(f"❌ Error connecting to Redis Cluster: {e}")
    redis_client = None

# --- 데이터 모델 정의 ---
class BlockRequest(BaseModel):
    ip: str

# --- FastAPI 앱 정의 ---
app = FastAPI(title="WAF Responder Service")

# --- API 엔드포인트 구현 ---
@app.post("/block", summary="Block an IP address with a time limit")
def block_ip(request: BlockRequest):
    """특정 IP를 주어진 시간(초) 동안 블랙리스트에 추가합니다."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    key = f"blacklist:{request.ip}"
    # SET with EX: 키에 값을 저장하고 만료 시간을 초 단위로 설정합니다.
    # 키가 이미 존재하면 값을 덮어쓰고 만료 시간도 새로 설정합니다.
    result = redis_client.set(key, "blocked", ex=BLACKLIST_EXPIRATION_SECONDS)
    
    return {"status": "success", "ip": request.ip, "ttl_seconds": BLACKLIST_EXPIRATION_SECONDS}

@app.post("/unblock", summary="Unblock an IP address")
def unblock_ip(request: BlockRequest):
    """특정 IP를 블랙리스트에서 즉시 제거합니다."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    key = f"blacklist:{request.ip}"
    # DEL: 키를 삭제합니다. 삭제 성공 시 1, 키가 없을 경우 0을 반환합니다.
    removed_count = redis_client.delete(key)
    
    if removed_count > 0:
        return {"status": "success", "ip": request.ip, "unblocked": True}
    else:
        raise HTTPException(status_code=404, detail=f"IP {request.ip} was not found in the blacklist.")

@app.get("/is_blocked/{ip}", summary="Check if an IP is blocked")
def is_ip_blocked(ip: str):
    """특정 IP가 블랙리스트에 있는지 확인합니다."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    key = f"blacklist:{ip}"
    # EXISTS: 키가 존재하는지 확인합니다. (1: 존재, 0: 미존재)
    is_blocked = redis_client.exists(key)
    
    return {"ip": ip, "is_blocked": bool(is_blocked)}

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
