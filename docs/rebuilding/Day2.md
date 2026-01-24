Terraform 코드 apply
역시나 에러없이 한번에 잘 되진 않았다..
대부분 잘 생성되었지만 redis인 valkey 설치가 제대로 되지 않았음!

 Error: creating ElastiCache Cache Cluster (edos-valkey-cluster): operation error ElastiCache: CreateCacheCluster, https response error StatusCode: 404, RequestID: b64455e4-3cf6-4e59-ace9-de53449b8e22, CacheParameterGroupNotFound: CacheParameterGroup not found: default.valkey7.2

처음엔 parameterGroup에 default.valkey7.2 없다고 해서 aws console 들어가서 확인해보니 사진과 같이 존재해서 valkey7로 수정!

![alt text](image.png)

수정 후 바로 될 것이라고 기대했지만..
 Error: creating ElastiCache Cache Cluster (edos-valkey-cluster): operation error ElastiCache: CreateCacheCluster, https response error StatusCode: 400, RequestID: 7ff878ee-3758-4d64-8785-1941f9041536, InvalidParameterValue: This API doesn't support Valkey engine. Please use CreateReplicationGroup API for Valkey cluster creation.

valkey는 리소스를 aws_elasticache_cluster -> aws_elasticache_replication_group로 수정해야 한다고 함

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

이후 Lambda에서도 redis 주소로 참조 하고 있었으니까 수정!
aws_elasticache_cluster.redis.cache_nodes[0].address -> 
aws_elasticache_replication_group.redis.primary_endpoint_address
기존에는 0번노드의 주소를 달라였다면, valkey는 복제그룹을 사용하기 때문에 개별노드 주소가 아니라 대표 주소를 사용하는게 권장된다고 해서 저렇게 주소를 사용하는 것 같음

이뿐만이 아니라 리소스가 변경됨으로써 정의해야되는 요소들도 많이 변경됨
description 추가 및 num_cache_clusters, replication_group_id 수정하고 난 뒤에 elasticache 구성 완료!



