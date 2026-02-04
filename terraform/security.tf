# 1. ALB를 위한 보안 그룹
resource "aws_security_group" "alb_sg" {
  name        = "edos-alb-sg"
  description = "Allow HTTP/HTTPS from Internet"
  vpc_id      = aws_vpc.main.id

  # 인바운드: 인터넷 전체(0.0.0.0/0)에서 80, 443 허용
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 아웃바운드: 모든 곳으로 나가는 트래픽 허용
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # -1은 모든 프로토콜을 의미함
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "edos-alb-sg" }
}

# 2. Redis(Valkey)를 위한 보안 그룹 (Lambda & Proxy 공용)
resource "aws_security_group" "redis_sg" {
  name        = "edos-redis-sg"
  description = "Allow access from Proxy EC2 and Future Lambda"
  vpc_id      = aws_vpc.main.id

  # 인바운드 규칙 1: Proxy EC2 (현재 테스트용)
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.proxy_sg.id] 
  }

  # 인바운드 규칙 2: VPC 내부 대역 (Lambda 및 기타 내부 자원용)
  # Lambda가 특정 SG를 가지기 전까지는 VPC 내부 통신을 열어두는 것이 확장성에 좋습니다.
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}