EDoS 탐지 및 대응 WAF Microservice 리빌딩 계획

기존에 진행했던 프로젝트는 클라우드 환경의 Auto Scaling 아키텍처를 악용해 불필요한 자원 확장과 비용을 유발하는 EDoS(Economic Denial of Sustainability) 공격을 방어하기 위한 시스템이었습니다.

기존 시스템 구성:
탐지 및 대응: Rule 기반과 ML기반의 두 가지 방식을 결합하여 지능형 트래픽을 분류하고 탐지
인프라 구조: CloudFront를 최전방에 두고 AWS Lambda와 ElastiCache를 연동하여 블랙리스트를 조회하는 구조
배포 및 운영: Jenkins를 활용해 CI/CD 파이프라인을 구축했으며 배포 환경에서는 AWS ECR과 ECS를 사용

1. 왜 리빌딩을 결심했나? (아쉬웠던 점)
기존 프로젝트를 통해 기본적인 방어 체계는 구축했지만, 실제 운영과 확장 측면에서 몇 가지 아쉬운 점이 남았다.
수동 구축의 비효율성: 당시 인프라의 많은 부분을 AWS 콘솔에서 수동으로 구축하다 보니, 환경을 재현하거나 관리하는 데 한계가 있었다.
운영 환경의 유연성 부족: ECS 기반의 운영은 안정적이었지만, 학습용으로 계속 유지하기에는 비용 부담이 커서 비용 효율성이 아쉬웠다.
실전 K8s 적용: 최근 CKA 자격증을 취득하며 배운 전문적인 지식들을 실제 프로젝트의 아키텍처에 깊이 있게 적용해보고 싶은 욕심이 생겼다.

2. 핵심 아키텍처
이번 리빌딩의 테마는 **"코드로 관리하는 자동화와 하이브리드를 통한 비용 최적화"**

Traffic Flow: CloudFront → Lambda(redis) → ALB → Local k8s (Ingress) → Detection Pod → Responder Pod
Infrastructure (AWS): VPC, Subnet, ALB, WAF (Terraform으로 관리)
Compute (Local): Docker Desktop k8s 기반의 탐지/대응 마이크로서비스 운영

3. 주요 구현 기술 
- 인프라 자동화 (Terraform)
VPC, Public Subnet, Security Group 등 네트워크 기반 시설 코드화
ALB 및 Target Group 설정을 통한 외부 트래픽 인입 경로 자동 구축
- 컨테이너 오케스트레이션 (Kubernetes)
MSA 전환: 탐지(Detection)와 대응(Responder) 로직을 개별 포드로 분리
가용성 확보: HPA(Horizontal Pod Autoscaler)를 설정하여 공격 시 포드 자동 확장
운영 안정성: Self-healing 기능을 통해 서비스 연속성 보장
- 하이브리드 커넥티비티
Ngrok 또는 VPN 터널링을 사용하여 AWS ALB와 로컬 k8s 서비스 간 연동

4. 구조
- CloudFront : VPC 외부의 검문소 느낌 (IGW는 따로 생성)
- Lambda : VPC 연동
- ALB : Public Subnet
- Redis : Private Subnet
- containers: local 

혹시 제가 설계한 구조에서 개선할 점이나 더 효율적인 방법이 보인다면, 아낌없이 훈수와 조언 부탁드립니다!
