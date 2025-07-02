# 2025.07.02(수) E-dos 조사

## AWS에서 E-DoS를 어떻게 부르고 있을까?
공식 문서·콘솔에는 ‘E-DoS(Economic Denial of Sustainability)’라는 용어가 거의 등장하지 않습니다.
AWS가 경제적 피해를 동반한 DDoS를 다룰 때는 “DDoS cost protection for scaling” 또는 **“DDoS cost protection”**이라는 표현을 사용합니다. 이 기능은 AWS Shield Advanced에 포함돼 있으며, 공격 때문에 Auto Scaling이 확장돼 발생한 과금분을 서비스 크레딧으로 환급해 주는 제도입니다.

<img width="810" alt="스크린샷 2025-07-02 오후 5 07 00" src="https://github.com/user-attachments/assets/e4b43990-91f1-4f20-8dcd-1e5ec4daf519" />

<img width="795" alt="스크린샷 2025-07-02 오후 5 08 19" src="https://github.com/user-attachments/assets/0fa5a1a2-7a8a-4670-99a7-5aafc0cc4048" />
<img width="905" alt="스크린샷 2025-07-02 오후 5 30 32" src="https://github.com/user-attachments/assets/3fb6834e-24b3-47b6-85c9-a7beea60a137" />

L3/ L4 Layer에서의 방어는 힘들것이라고 판단, L3/L4 단계에서는 AWS 시스템에 의존하자
#### 우리가 만들 것은 L7위에서의 효과적인 차단 Microservice로 지정. </br>

그렇다면 우리는 어떤 것을 만들어야 할까
<img width="789" alt="스크린샷 2025-07-02 오후 5 57 29" src="https://github.com/user-attachments/assets/7c74c9a8-ad19-4fca-9f62-19d5c1d30f50" />
<img width="800" alt="스크린샷 2025-07-02 오후 5 57 46" src="https://github.com/user-attachments/assets/3bdd9f98-42dd-4489-b695-59924f240d93" />




