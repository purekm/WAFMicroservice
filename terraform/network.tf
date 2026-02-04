# 1. VPC 생성
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true # 도메인 네임 사용 가능하게 설정
  tags = { Name = "edos-vpc" }
}

# 2. Public Subnet 2개 (가용영역 A, C)
resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-northeast-2a"
  tags = { Name = "edos-pub-sub-2a" }
}

resource "aws_subnet" "public_c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-2c"
  tags = { Name = "edos-pub-sub-2c" }
}

# 3. Private Subnet 2개 (Redis용)
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "ap-northeast-2a"
  tags = { Name = "edos-pri-sub-2a" }
}

resource "aws_subnet" "private_c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "ap-northeast-2c"
  tags = { Name = "edos-pri-sub-2c" }
}

# 4. 인터넷 게이트웨이 및 라우팅 설정 (Public Subnet 통신용)
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "pub_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "pub_c" {
  subnet_id      = aws_subnet.public_c.id
  route_table_id = aws_route_table.public_rt.id
}

# Proxy EC2 인스턴스 (Public Subnet에 배치)
resource "aws_instance" "proxy_server" {
  ami                    = "ami-0ff23e8726c9ce3cd" # Amazon Linux 2023 (ap-northeast-2 기준)
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id # 기존 Public Subnet ID
  vpc_security_group_ids = [aws_security_group.proxy_sg.id]
  key_name               = "kyeongmin-key" # 사용 중인 키페어 이름
  associate_public_ip_address = true
  tags = {
    Name = "EDoS-Proxy-Server"
  }
}

# Proxy EC2를 위한 보안 그룹
resource "aws_security_group" "proxy_sg" {
  name        = "edos-proxy-sg"
  description = "Security group for Hybrid Proxy EC2"
  vpc_id      = aws_vpc.main.id

  # SSH (22): 경민님 노트북에서 터널링을 하기 위해 허용
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # 실제 운영 시에는 경민님 공인 IP/32로 제한하는 것을 권장합니다.
    cidr_blocks = ["115.137.231.242/32"] 
  }

  # HTTP (8080): ALB로부터 들어오는 트래픽을 수신
  ingress {
    from_port       = 8080             # 터널 입구인 8080으로 변경
    to_port         = 8080
    protocol        = "tcp"
    # 중요: 0.0.0.0/0 대신 ALB 보안 그룹 ID만 허용
    security_groups = [aws_security_group.alb_sg.id] # 수정
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}