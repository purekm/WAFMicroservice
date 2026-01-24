# 1. ElastiCache 서브넷 그룹 (Redis가 binding 될 서브넷 정의)
resource "aws_elasticache_subnet_group" "redis_subnet_group" {
  name       = "edos-redis-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_c.id] # network.tf 참조
}

# 2. Redis 클러스터 생성
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "edos-valkey-group"
  description          = "Valkey cluster for BlacklistIP"
  engine               = "valkey"         # valkey 기존 오픈소스였던 redis 코드를 복붙해서 최적화한 redis
  engine_version       = "7.2"            # 버전 지정
  num_cache_clusters   = 1 # 노드 개수
  node_type            = "cache.t4g.micro"
  parameter_group_name = "default.valkey7" # valkey 전용 파라미터 그룹
  port                 = 6379             # 포트는 6379 사용
  subnet_group_name    = aws_elasticache_subnet_group.redis_subnet_group.name
  security_group_ids   = [aws_security_group.redis_sg.id] # security.tf 참조

  tags = { Name = "edos-redis" }
}