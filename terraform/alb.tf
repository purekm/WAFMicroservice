# 1. 로드밸런서 본체 생성
resource "aws_lb" "main" {
  name               = "edos-alb"
  internal           = false # 외부 인터넷에서 접속 가능하도록 설정
  load_balancer_type = "application" # HTTP 프로토콜사용하니까 application type 사용
  security_groups    = [aws_security_group.alb_sg.id] # security.tf 참조
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_c.id] # public 서브넷 2개 배치
  tags = { Name = "edos-alb" }
}



# 2. 타겟 그룹 생성 
resource "aws_lb_target_group" "main" {
  name        = "edos-tg"
  port        = 8080 # 수정한곳!
  protocol    = "HTTP"
  target_type = "instance" # 로컬 k8s를 터널링으로 연결할 것이므로 IP 방식 권장
  vpc_id      = aws_vpc.main.id
  health_check {
    path                = "/"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

# 3. 리스너 생성 (80 포트로 들어오는 요청 수신)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# EC2를 대상 그룹의 대상으로 작성
resource "aws_lb_target_group_attachment" "proxy_attachment" {
  target_group_arn = aws_lb_target_group.main.arn
  target_id        = aws_instance.proxy_server.id # EC2 리소스 이름
  port             = 8080                      # 우리가 뚫어놓은 터널 포트
}