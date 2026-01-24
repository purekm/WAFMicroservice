import os
import redis
import json

# 테라폼 환경 변수에서 Redis 주소를 가져옴
REDIS_HOST = os.environ.get('REDIS_HOST')
REDIS_PORT = 6379

# Redis 클라이언트 설정 (커넥션 풀 사용 권장)
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True) 
# 기본적으로 Redis는 bytes타입 사용하는데, decode_responses=True 옵션을 주면 str 타입으로 반환됨
# db=0은 redis안에 여러 db중에 0번을 사용한다는 의미

def handler(event, context):
    # 1. CloudFront 요청에서 클라이언트 IP 추출
    try:
        request = event['Records'][0]['cf']['request'] # 
        client_ip = request['clientIp']
        
        # 2. Redis에서 해당 IP가 블랙리스트에 있는지 조회 (1: 차단 대상, None: 정상)
        is_blocked = r.get(f"blacklist:{client_ip}")
        
        if is_blocked:
            # 3. 차단 대상이면 403 Forbidden 응답 반환
            print(f"Blocking malicious request from: {client_ip}")
            return {
                'status': '403',
                'statusDescription': 'Forbidden',
                'body': 'Your IP is blocked due to EDoS detection.'
            }
        
        # 4. 정상적인 요청은 그대로 통과
        return request

    except Exception as e:
        print(f"Error checking blacklist: {e}")
        # 에러 발생 시 서비스 가용성을 위해 일단 통과시킴
        return event['Records'][0]['cf']['request']