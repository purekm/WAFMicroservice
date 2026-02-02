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
