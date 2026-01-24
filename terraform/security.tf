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

# 2. Redis를 위한 보안 그룹
resource "aws_security_group" "redis_sg" {
  name        = "edos-redis-sg"
  description = "Allow access from Lambda only"
  vpc_id      = aws_vpc.main.id

  # 인바운드: 보안 그룹 간 참조를 사용하여 보안 강화
  # 나중에 만들 Lambda 전용 SG가 생성되면 그 ID를 여기에 넣어야 함
  # 일단은 편의상 VPC 내부 아이피(10.0.0.0/16) 대역에서만 6379 허용으로 설정
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

  tags = { Name = "edos-redis-sg" }
}