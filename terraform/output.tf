output "alb_dns_name" {
  description = "생성된 로드밸런서의 접속 주소"
  value       = aws_lb.main.dns_name
}

output "valkey_primary_endpoint" {
  description = "Valkey 복제 그룹의 마스터 엔드포인트"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}