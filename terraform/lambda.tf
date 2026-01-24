# 1. Lambda 실행을 위한 IAM 역할
resource "aws_iam_role" "lambda_role" {
  name = "edos_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# 2. VPC 접속 및 로그 기록을 위한 기본 권한 부여
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# 3. Lambda 함수 생성
resource "aws_lambda_function" "edos_detector" {
  filename      = "lambda_function.zip" # 실제 파이썬 코드가 압축된 파일
  function_name = "edos-ip-detector"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  # VPC 연동 설정: Private 서브넷에 배치하여 Redis 접근 허용
  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_c.id]
    security_group_ids = [aws_security_group.redis_sg.id] # Redis와 통신 가능한 SG 사용
  }

  environment {
    variables = {
      REDIS_HOST = aws_elasticache_replication_group.redis.primary_endpoint_address
    }
  }
}