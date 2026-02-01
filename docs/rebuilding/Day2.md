
---

## [Troubleshooting] Terraform 적용기: Valkey 삽질과 Jenkins 리팩토링

계획은 완벽했다고 생각하지만, 역시 한 번에 성공하는 법은 없나 봅니다...
이번 포스팅에서는 구축 과정에서 만난 에러들과 이를 해결하며 배운 점들을 정리해 봅니다.

### 1. ElastiCache(Valkey) 설치 오류와 리소스 전환

가장 먼저 만난 에러는 Valkey 설정이었습니다.

#### **에러 1: Parameter Group을 찾을 수 없음**

`default.valkey7.2`를 넣었으나 404 에러가 발생했습니다. 
콘솔을 확인해 보니 정확한 명칭이 `default.valkey7`이더군요. 버전 명칭을 수정해 해결했습니다.

#### **에러 2: API 지원 문제 (Cluster vs Replication Group)**

수정 후 다시 돌리니 이번엔 400 에러가 떴습니다.

> *"This API doesn't support Valkey engine. Please use CreateReplicationGroup API"*

Valkey는 `aws_elasticache_cluster`가 아닌 **`aws_elasticache_replication_group`** 리소스를 사용해야 하더군요... 
그래서 리소스를 통째로 수정하며 필요한 속성들(`description`, `num_cache_clusters` 등)을 다시 정의했습니다.

```hcl
# 수정된 redis.tf
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "edos-valkey-group"
  description          = "Valkey cluster for BlacklistIP"
  engine               = "valkey" 
  engine_version       = "7.2"
  num_cache_clusters   = 1 # 노드 개수
  node_type            = "cache.t4g.micro"
  parameter_group_name = "default.valkey7" 
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.redis_subnet_group.name
  security_group_ids   = [aws_security_group.redis_sg.id]

  tags = { Name = "edos-redis" }
}

```

#### **Lambda 참조 주소 수정**

리소스가 변경되면서 Lambda에서 Valkey를 바라보는 엔드포인트 참조 방식도 바뀌었습니다. 개별 노드 주소가 아닌 **복제 그룹의 대표 주소**를 사용하도록 수정했습니다.

* `aws_elasticache_cluster.redis.cache_nodes[0].address` → `aws_elasticache_replication_group.redis.primary_endpoint_address`

---

### 2. 귀찮음을 해결해주는 `output.tf`

매번 콘솔에 들어가서 ALB 주소나 Valkey 엔드포인트를 복사하는 게 번거로웠는데, `output` 기능을 활용하니 `apply` 직후 터미널에서 바로 확인할 수 있어 훨씬 편해졌습니다.

```hcl
# output.tf
output "alb_dns_name" {
  description = "생성된 로드밸런서의 접속 주소"
  value       = aws_lb.main.dns_name
}

output "valkey_primary_endpoint" {
  description = "Valkey 복제 그룹의 마스터 엔드포인트"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

```

---

### 3. CI/CD: Jenkins 파이프라인 리팩토링

이미지 빌드 후 도커 허브에 수동으로 올리는 과정이 귀찮아져서, 예전에 사용하던 Jenkins 파일을 꺼내 현재 환경에 맞게 고쳤습니다.

**주요 리팩토링 내용:**

1. **보안 강화 (Access Token)**: 직접적인 비밀번호 대신 Docker Hub 전용 Access Token을 생성해 보안을 높였습니다.
2. **Jenkins Credentials**: 발급받은 토큰을 Jenkins 자격 증명 시스템에 등록했습니다.
3. **네트워크 터널링 (ngrok)**: 로컬 Jenkins와 외부 GitHub를 연결하기 위해 ngrok으로 Webhook을 다시 연동했습니다.

기존 AWS ECR 기반에서 Docker Hub 기반으로 전환하며 오랜만에 Jenkins를 만지니 어색하더라구요 ㅎㅎ..

---

### 내일의 도전 과제

오늘은 인프라와 배포 파이프라인의 뼈대를 완성했습니다. 내일은 본격적으로 K8s 위에 서비스를 올릴 예정입니다.

1. **Deployment & Service YAML 작성**: 이미지와 Terraform output으로 나온 ALB 주소 등을 환경변수로 넣어 작성할 계획입니다.
2. **ConfigMap 활용**: 관리할 환경변수가 많아질 것 같아 ConfigMap을 도입해 보려 합니다. 


---