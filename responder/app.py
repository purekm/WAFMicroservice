import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from redis.cluster import RedisCluster
from redis.exceptions import RedisError

REDIS_HOST = os.getenv("REDIS_HOST", "clustercfg.wafcache3.jwukuh.apn2.cache.amazonaws.com")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
TTL_SECONDS = int(os.getenv("BLACKLIST_EXPIRATION_SECONDS", "300"))  # 5분

# Redis Cluster 연결 (필요한 것만)
try:
    r = RedisCluster(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        skip_full_coverage_check=True,
    )
    r.ping()
except RedisError as e:
    print("Redis connect fail:", e)
    r = None

app = FastAPI(title="WAF Responder")

class BlockRequest(BaseModel):
    ip: str

def need_redis():
    if r is None:
        raise HTTPException(status_code=503, detail="Redis is not available")

@app.post("/block")
def block_ip(req: BlockRequest):
    need_redis()
    ok = r.set(f"blacklist:{req.ip}", "1", ex=TTL_SECONDS)
    if not ok:
        raise HTTPException(status_code=500, detail="set failed")
    return {"status": "ok", "ip": req.ip, "ttl": TTL_SECONDS}

@app.post("/unblock")
def unblock_ip(req: BlockRequest):
    need_redis()
    removed = r.delete(f"blacklist:{req.ip}")
    if removed:
        return {"status": "ok", "ip": req.ip, "unblocked": True}
    raise HTTPException(status_code=404, detail="not found")

@app.get("/is_blocked/{ip}")
def is_blocked(ip: str):
    need_redis()
    return {"ip": ip, "is_blocked": bool(r.exists(f"blacklist:{ip}"))}

@app.get("/health")
def health():
    need_redis()
    try:
        r.ping()
        return {"status": "ok"}
    except RedisError:
        raise HTTPException(status_code=503, detail="Redis ping failed")
