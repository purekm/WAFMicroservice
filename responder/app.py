import os
import redis
from redis.cluster import RedisCluster
from redis.exceptions import ClusterConnectionError  
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

REDIS_HOST = os.getenv("REDIS_HOST", "clustercfg.wafcache3.jwukuh.apn2.cache.amazonaws.com")
REDIS_PORT = 6379
BLACKLIST_EXPIRATION_SECONDS = 300  # 5분

try:
    redis_client = RedisCluster(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=5,
        skip_full_coverage_check=True
    )
    redis_client.ping()
    print(f"✅ Successfully connected to Redis Cluster at {REDIS_HOST}")
except (ClusterConnectionError, redis.exceptions.ConnectionError) as e:
    print(f"❌ Error connecting to Redis Cluster: {e}")
    redis_client = None

class BlockRequest(BaseModel):
    ip: str

app = FastAPI(title="WAF Responder Service")

@app.post("/block")
def block_ip(request: BlockRequest):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    key = f"blacklist:{request.ip}"
    redis_client.set(key, "blocked", ex=BLACKLIST_EXPIRATION_SECONDS)
    return {"status": "success", "ip": request.ip, "ttl_seconds": BLACKLIST_EXPIRATION_SECONDS}

@app.post("/unblock")
def unblock_ip(request: BlockRequest):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    key = f"blacklist:{request.ip}"
    removed_count = redis_client.delete(key)

    if removed_count > 0:
        return {"status": "success", "ip": request.ip, "unblocked": True}
    else:
        raise HTTPException(status_code=404, detail=f"IP {request.ip} was not found in the blacklist.")

@app.get("/is_blocked/{ip}")
def is_ip_blocked(ip: str):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis is not available")

    key = f"blacklist:{ip}"
    is_blocked = redis_client.exists(key)
    return {"ip": ip, "is_blocked": bool(is_blocked)}

@app.get("/health")
def health_check():
    redis_ok = False
    if redis_client:
        try:
            redis_ok = redis_client.ping()
        except redis.exceptions.ConnectionError:
            redis_ok = False

    if not redis_ok:
        raise HTTPException(status_code=503, detail="Redis connection failed")

    return {"status": "ok", "redis_connection": "ok"}
