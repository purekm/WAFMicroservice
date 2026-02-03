이제 어느정도 완성된 구조를 테스트 해볼 차례!
확인해야 할 것
ngrok으로 열어놓은 포트를 ingress를 위한 80 포트로 수정했으니까 제대로 CI/CD가 되는지 확인해야함
pod 및 deploy가 running 상태인지 확인해야 함

![alt text](image-9.png) 

BadGateway ㅠㅠ
그래서 ingress controller 쪽 확인해봄
![alt text](image-10.png)

Nodeport방식이였던 것..! helm 차트로 만들어서 신경 못 쓰고 있었다..

ngrok 할때 NodePort인 30890을 해줘야 함

![alt text](image-11.png)

이번엔 왜 NotFound인가...
생각해보니 jenkins를 ingress에서 트래픽을 줘서 path 경로를 수정을 안해줬던 것..!

![alt text](image-12.png)
jenkins를 위한 path 수정완료

![alt text](image-13.png)
이제 잘되는 것 까지 확인!

![alt text](image-14.png)
테스트를 위해 ALB에 트래픽(공격) 보내보기

ALB까지는 잘 갔는데, Ingress까지 오지 않음.
=> ALB는 VPC 내로만 라우팅해주기 때문에.. ALB를 활용하려면 VPN이나 proxy 서버가 필요한데.. 비쌀 것으로 예상.
일단 트래픽 탐지 및 대응 테스트까지는 ingress로 바로 트래픽을 보내 볼 예정이고, 이후에 테스트를 마치고 나면 ALB 도입해볼 예정

일단은 ngrok을 통해 ingress로 트래픽 보내기!




