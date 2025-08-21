import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from redis.cluster import RedisCluster
from redis.exceptions import RedisError

# --- 설정 ---
# - 환경 변수에서 Redis 호스트, 포트, 블랙리스트 만료 시간을 가져옴
# - 환경 변수가 없으면 기본값을 사용
REDIS_HOST = os.getenv("REDIS_HOST", "clustercfg.wafcache3.jwukuh.apn2.cache.amazonaws.com")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
TTL_SECONDS = int(os.getenv("BLACKLIST_EXPIRATION_SECONDS", "300"))  # 기본 5분

# --- Redis 클러스터 연결 ---
try:
    # - 주어진 호스트와 포트로 Redis 클러스터에 연결
    r = RedisCluster(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,          # 응답을 UTF-8로 디코딩
        socket_connect_timeout=5,       # 연결 타임아웃 5초
        socket_timeout=5,               # 읽기/쓰기 타임아웃 5초
        skip_full_coverage_check=True,  # 모든 노드를 확인하지 않고 시작
    )
    r.ping() # 연결 테스트
except RedisError as e:
    print("Redis connect fail:", e)
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
    """
    - 서비스 및 Redis 연결 상태를 확인하는 헬스 체크 엔드포인트
    """
    need_redis() # Redis 연결 확인
    try:
        r.ping() # Redis 서버에 PING을 보내 응답 확인
        return {"status": "ok"}
    except RedisError:
        raise HTTPException(status_code=503, detail="Redis ping failed")