import os
import redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# 테라폼 output에서 나올 주소를 환경 변수로 받음
REDIS_HOST = os.getenv("REDIS_HOST") 
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
TTL_SECONDS = int(os.getenv("BLACKLIST_EXPIRATION_SECONDS", "3600"))

# 클러스터 모드가 아닌 일반 Redis/Valkey 연결로 수정
try:
    r = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=3,
        retry_on_timeout=True
    )
    r.ping()
except Exception as e:
    print(f"Valkey 연결 실패: {e}")
    r = None

# --- FastAPI 앱 생성 ---
app = FastAPI(title="WAF Responder")

# --- 요청 모델 정의 ---
class BlockRequest(BaseModel):
    # - /block, /unblock 엔드포인트에서 사용할 요청 본문 모델
    ip: str

# --- Redis 의존성 함수 ---
def need_redis():
    # - Redis 연결이 없는 경우, 503 Service Unavailable 에러를 발생시키는 의존성
    if r is None:
        raise HTTPException(status_code=503, detail="Redis is not available")

# --- API 엔드포인트 ---

@app.post("/block")
def block_ip(req: BlockRequest):
    """
    - 특정 IP를 블랙리스트에 추가
    - 지정된 TTL(Time-To-Live) 이후 자동으로 삭제됨
    """
    need_redis() # Redis 연결 확인
    # - 'blacklist:{ip}' 형태의 키로 Redis에 저장
    ok = r.set(f"blacklist:{req.ip}", "1", ex=TTL_SECONDS)
    if not ok:
        raise HTTPException(status_code=500, detail="set failed")
    return {"status": "ok", "ip": req.ip, "ttl": TTL_SECONDS}

@app.post("/unblock")
def unblock_ip(req: BlockRequest):
    """
    - 블랙리스트에서 특정 IP를 제거
    """
    need_redis() # Redis 연결 확인
    removed = r.delete(f"blacklist:{req.ip}")
    if removed:
        return {"status": "ok", "ip": req.ip, "unblocked": True}
    # - 해당 IP가 블랙리스트에 없는 경우 404 Not Found 에러 발생
    raise HTTPException(status_code=404, detail="not found")

@app.get("/is_blocked/{ip}")
def is_blocked(ip: str):
    """
    - 특정 IP가 블랙리스트에 있는지 확인
    """
    need_redis() # Redis 연결 확인
    return {"ip": ip, "is_blocked": bool(r.exists(f"blacklist:{ip}"))}

@app.get("/health")
def health():
    if r and r.ping():
        return {"status": "ok"}
    raise HTTPException(status_code=503, detail="Redis connection failed")