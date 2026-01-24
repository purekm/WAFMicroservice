EDoS 방어 시스템 구축: 최신 오픈소스 Valkey와 IaC 활용기
이번에는 클라우드 리소스를 활용해 공격을 차단하는 인프라를 Terraform으로 구축해 보았습니다.

이번 프로젝트의 핵심은 **"비용 효율성"**과 **"IaC(코드로서의 인프라)"**입니다.

1. 프로젝트 구조 및 설정 (provider.tf)
provider.tf: AWS 및 Terraform 버전 설정
network.tf: VPC, Subnet, IGW 등 기본 네트워크
security.tf: 리소스별 보안 그룹(SG) 설정
redis.tf: 블랙리스트 저장을 위한 Valkey 클러스터
alb.tf: 트래픽 관문인 로드밸런서
lambda.tf: 실시간 IP 판독 로직 엔진

먼저 전체 인프라를 코드로 관리하기 위한 디렉터리 구조와 기본 설정을 정의

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = "ap-northeast-2" # 서울 리전
}

2. 네트워크 및 보안 설계 (network.tf, security.tf)
고가용성을 위해 2개의 가용 영역에 서브넷을 분산 배치
외부 노출이 필요한 ALB는 Public Subnet에, redis와 lambda는 Private Subnet에 배치하여 보안을 신경씀

# network.tf  (Public/Private 서브넷 분리)
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "edos-vpc" }
}

# 보안 그룹: 필요한 포트(80, 6379)만 최소한으로 허용
resource "aws_security_group" "redis_sg" {
  name   = "edos-redis-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block] # VPC 내부 통신만 허용
  }
}
3. DB용 redis인 valkey (redis.tf)
기존 Redis가 라이선스 정책을 유료화로 변경하면서, 대형 CSP 및 리눅스 Foundation이 만든 기존 코드 가져와서 최적화 시켜서 만들어진 valkey 가 나와서 찾아봄
redis보다 비용효율적이고 성능도 좋아서 valkey로 사용

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "edos-valkey-cluster"
  engine               = "valkey"         # Redis 대신 Valkey 채택
  engine_version       = "7.2"
  node_type            = "cache.t4g.micro" # 비용 효율적인 인스턴스
  parameter_group_name = "default.valkey7.2"
  security_group_ids   = [aws_security_group.redis_sg.id]

}
4. 실시간 방어 로직 (lambda.tf & Lambda Code)
CloudFront에서 들어오는 요청을 가로채 Valkey에 등록된 블랙리스트 IP인지 확인
공격 IP로 확인되면 ALB로 트래픽을 넘기지 않고 403 Forbidden으로 즉시 차단

resource "aws_iam_role" "lambda_role" {
  name = "edos_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "edos_detector" {
  filename      = "lambda_function.zip"
  function_name = "edos-ip-detector"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_c.id]
    security_group_ids = [aws_security_group.redis_sg.id]
  }

  environment {
    variables = { REDIS_HOST = aws_elasticache_cluster.redis.cache_nodes[0].address }
  }
}

import os
import redis

# 환경변수로 전달받은 Valkey 엔드포인트 연결
REDIS_HOST = os.environ.get('REDIS_HOST')
r = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)

def handler(event, context):
    try:
        request = event['Records'][0]['cf']['request']
        client_ip = request['clientIp']
        
        # Valkey에서 블랙리스트 여부 확인
        if r.get(f"blacklist:{client_ip}"):
            return {
                'status': '403',
                'body': 'Access Denied: EDoS Detected.'
            }
        return request # 정상 사용자는 통과
    except Exception as e:
        return event['Records'][0]['cf']['request']

확실히 콘솔에서 클릭할 때보다 코드로 짜니 인프라 전체의 흐름이 한눈에 들어오는 것 같아서 좋네요. 가독성도 좋고 테라폼 안 쓸수가 없는 것 같네요 ㅎㅎ.. 
기존 프로젝트에서는 valkey가 그냥 신규 출시됐길래 사용했었는데, 이유를 찾아 보고 나니까 무조건 valkey쓰는 게 좋은 것 같아요.
다음번엔 테라폼으로 생성된 aws 리소스들이랑 로컬 k8s에서 실행하는 컨테이너 연결을 도전해볼 것 같습니다!
