# WAF Microservice - EDoS 탐지 및 대응 마이크로 서비스

## 1. 소개 (Introduction)

최신 클라우드 환경에서는 사용량 기반 과금 모델을 악용하여, 서버를 마비시키지 않고 비용만 대량으로 발생시키는 E-DoS 공격이 새로운 위협이 되고 있습니다.

**WAF Microservice**는 이러한 지능형 공격을 탐지하기 위해 개발되었습니다. 기존의 시그니처(룰) 기반 보안 시스템이 탐지하기 어려운, 알려지지 않은 비정상 행위를 머신러닝으로 포착하는 데 중점을 둡니다. 따라서 WAF Microservice는 기존 시스템을 대체하는 것이 아니라, 상호 보완하여 보안의 사각지대를 해소하는 역할을 합니다.

## 2. 주요 특징 (Key Features)
*   **룰 기반 이상 탐지**: 
*   **머신러닝 기반 이상 탐지**: 비지도 학습(Unsupervised Learning)을 통해 알려지지 않은 E-DoS 공격 패턴을 실시간으로 분석하고 탐지합니다.
*   **다각적인 특징 분석**: 요청의 구조, 엔트로피, 시간적 패턴 등 13개 이상의 구체적인 특징을 조합하여 공격을 정밀하게 식별합니다.
*   **유연한 구조**: 마이크로서비스 기반으로 설계되어, 다양한 환경에 맞게 유연하게 통합하고 확장할 수 있습니다.

## 3. 아키텍처 (Architecture)

WAF Microservice는 실제 운영 환경, 특히 AWS 클라우드 환경에 최적화된 유연한 아키텍처를 기반으로 설계되었습니다. 핵심은 **실시간 요청-응답 경로에 영향을 주지 않는 비동기 분석 방식**으로 동작하여, 보안 분석으로 인한 지연(latency)을 원천적으로 제거하는 것입니다.

![alt text](image.png)

## 4. 기술 스택 (Technology Stack)

*   **Backend**: Python, FastAPI
*   **ML/Data**: Scikit-learn, Pandas, Numpy
*   **Infrastructure**: Docker, DockerCompose, Jenkins
*   **Database**: Elasticache (Redis)
*   **AWS**: ECS, ECR, ALB, Lambda

## 5. 시작하기 (Getting Started)

Docker와 `docker-compose`가 설치된 환경에서 아래 명령어로 간단히 실행할 수 있습니다.

```bash
# 1. 프로젝트 클론
git clone https://github.com/purekm/WAFMicroservice.git
cd edos

# 2. Docker 컨테이너 실행
docker-compose up -d
```

## 6. 향후 계획 (Future Plans)

WAF Microservice는 다음과 같은 기능들을 추가하여 지속적으로 발전할 계획입니다.

하이브리드 탐지: Suricata 도입, 시그니처 기반 탐지 추가
모델 고도화: 지도학습 도입 및 적응형 임계값 적용
피처 확장: TLS 지문(JA4), GeoIP/ASN 정보 분석 기능 추가
클라우드 인프라 구조 고도화
