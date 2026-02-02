![alt text](image-1.png)
deployment에는 env가 1개만 필요하니까.. 따로 가져와주기(큰 의미는 없지만.. 이러면 보안상 좋지않을까 해서 ㅎㅎ..)
이후 호기롭게 실행!

![alt text](image-2.png)
하지만 이미지 에러..
왜인지 확인해보니 image에 내 도커허브 경로가 적혀있지 않았다..

![alt text](image-3.png)
pod는 제대로 생성되었길래 deployment가 좀 늦게 나오나 했는데.. 계속 pod가 ready되지 않는 상태..?(알고보니 pod에서 이후에 어떤 파일이 없다고.. CrashLoopBackOff에러가 발생했다)
이미지로 다 같이 보내서 괜찮은 줄 알았는데..?
 
일단 해결해보려고
configMap을 새로 만들어서 그걸로 파일 제공하려고 했는데.. Configmap은 1MB까지만 파일을 담을 수 있다고 함
=> gpt와 얘기하면서 찾은 점은.. git ignore에 해당 파일이 적혀있어서 못 가져온 것..! 수정

ImagePullPolicy가 Always여서 도커 이미지 재빌드하니까 복구 완료!
![alt text](image-4.png)

이젠 responder 해야지..
![alt text](image-5.png)
이번엔 configmap의 대부분의 env를 사용하니까 그냥 configmap 가져오기

![alt text](image-6.png)
responder도 정상적으로 작동하는 것 확인!

![alt text](image-7.png)
pod가 각각 1개면 가용성이 불안하니까 2개로 스케일링 해줌

이제는 vpc와 local k8s를 연결시킬 차례!
ngrok을 사용하려고 했는데.. 현재는 jenkins와 github를 연결한다고 1개를 사용하고 있었다..
2개를 사용하려니까 무료로는 불가능한 사태가 발생!!!

어차피 ingress로 트래픽 분산을 해주려고 했으니까 ingresscontroller용으로 80포트 열고,
jenkins도 트래픽 분산을 하면 되지않을까 싶음!

ingressController를 설치해야함
manifest가져와서 설치하거나 helm 으로 설치할 수 있을 것 같은데..
manifest는 관리 및 추가 설정이 힘들 것 같으니까 helm 방식으로!

역시 편하다 helm..!
![alt text](image-8.png)

아.. jenkins는 예전에 배포해뒀던걸 썼었는데 pod로써 배포한게 아니라 docker 컨테이너로 배포한 것이였음..
트래픽 라우팅하기가 힘들어졌다고 생각했는데, Endpoint를 사용해서 내 로컬로 수동 연결이 가능하다고 함
다른 부분이 안정화되면 수정해볼 계획

ingress 만들어서 실행해보니.. 깜빡하고 각 pod에 서비스를 생성 안 했었다..!
생성해줌






