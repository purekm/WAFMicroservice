#날짜 및 내용 작성할 것!!!!

## 7월 2일
#### 금일 내용
기획안 작성.</br>
#### 다음날 할일
기획안 마저 작성.(E-dos 정의 내리기 및 어떻게 막을지 생각해오기)

## 7월 3일
#### 금일 내용
EDoS에 대한 조사</br>
#### 다음날 할일
Jenkins에 대한 공부를 진행하며, Jenkins와 Github 연동 테스트 진행 중.
테스트를 purekm의 repo로 진행 중
로컬 Docker에서 Jenkins를 설치했으며, Github Webhook과 연동을 하기 위해 ngrok을 사용함
![alt text](image-2.png)
![alt text](image-3.png)

ngrok에 200 OK 가 처리되었으며, Jenkins에서 System Log 또한 잘 받았다고 로그가 나옴
하지만.. 빌드는 아직 되지 않음
Jenkins에서 Docker를 통한 이미지 자동 빌드를 실행 중 컨테이너를 지워서 처음부터 다시 시작..
시행착오
1. Jenkins 컨테이너에는 Docker cli가 깔려있어야 함
2. docker socket을 실행할 수 있는 권한을 jenkins에도 줘야함




