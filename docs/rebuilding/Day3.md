![alt text](image-1.png)
deployment에는 env가 1개만 필요하니까.. 따로 가져와주기(큰 의미는 없지만.. 이러면 보안상 좋지않을까 해서 ㅎㅎ..)
이후 호기롭게 실행!

![alt text](image-2.png)
하지만 이미지 에러..
왜인지 확인해보니 image에 내 도커허브 경로가 적혀있지 않았다..

![alt text](image-3.png)
pod는 제대로 생성되었길래 deployment가 좀 늦게 나오나 했는데.. 계속 pod가 ready되지 않는 상태..?(알고보니 pod에서 이후에 어떤 파일이 없다고.. CrashLoopBackOff에러가 발생했다)
=> 로컬에서는 잘 돌아갔지만 k8s의 pod가 내 로컬의 파일에 접근할 수 있을리가.. 없으니까 해당 파일들도 제공해줘야함 

configMap을 새로 만들어서 그걸로 파일 제공하려고 했는데.. Configmap은 1MB까지만 파일을 담을 수 있다고 함
=> 방법 변경을 해야하는데