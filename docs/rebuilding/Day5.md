결국 고민 끝에 EC2를 프록시로 세우기로 하고, 바로 테라폼 코드를 짰다. 손으로 일일이 만드는 것보다 나중에 재사용하기도 편하고..! 이제 다신 콘솔로 못 돌아갈 것 같다ㅎㅎ..

1. Proxy EC2용 보안 그룹 가장 먼저 프록시 서버의 문을 열어줬다.

SSH:내 노트북에서 터널을 뚫어야 하니 내 공인 IP만 허용.
HTTP: 나중에 ALB 트래픽을 받아줄 용도.

2. Valkey용 보안 그룹도 생성. Valkey가 Private Subnet에 숨어 있어서 외부 접근이 안 됐는데, 방금 만든 프록시 EC2가 '징검다리' 역할을 할 수 있게 설정했다.
6379 포트: 프록시 서버의 보안 그룹 ID를 소스로 등록해서, 터널을 타고 들어온 데이터만 Valkey에 박힐 수 있게 설계했다.

3. Proxy EC2 인스턴스 생성 t3.micro로 가볍게 올릴 예정.
ssh하려면 key pair가 필요하니까 이건 콘솔에서 직접 생성해줬따
Key Pair: AWS 콘솔에서 미리 만든 키를 참조하게 설정.
Subnet: 외부와 소통해야 하니 당연히 Public Subnet에 배치.

이제야 제대로 구상이 완료된 느낌!
ALB -> EC2(Proxy) -> Ingress(local k8s)를 통한 하이브리드 구조

EC2 서버도 새로 생성해서 봤더니..! 
![alt text](image-15.png)

퍼블릭 IP주소가 없다..? 퍼블릭 서브넷이 존재하는 건 확인했음..
알고보니 서브넷 설정할 때 인스턴스 생성하면 퍼블릭 IP를 제공한다는 옵션이 있는데, 그걸 설정하지 않았던 것..
그래도 인스턴스에 공인 IP받도록 설정할 수도 있어서 associate_public_ip_address = true 를 추가!

# Proxy EC2 인스턴스 (Public Subnet에 배치)
resource "aws_instance" "proxy_server" {
  ami                    = "ami-0ff23e8726c9ce3cd" # Amazon Linux 2023 (ap-northeast-2 기준)
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id # 기존 Public Subnet ID
  vpc_security_group_ids = [aws_security_group.proxy_sg.id]
  associate_public_ip_address = true
  key_name               = "kyeongmin-key" # 사용 중인 키페어 이름
  tags = {
    Name = "EDoS-Proxy-Server"
  }
}

이제 ssh 터널링을 해볼 차례!
ssh -i "kyeongmin-key.pem" \
    -R 80:localhost:30890 \
    -L 6379:[Valkey주소]:6379 \
    ec2-user@[EC2퍼블릭주소]
를 통해서 ssh 양방향 터널링

ssh 성공..!
![alt text](image-16.png)

내 로컬에서 ec2 프록시 서버를 열어두고 이제 private subnet의 valkey에 접근 가능한지 테스트해볼 차례!

![alt text](image-17.png)
ec2 서버를 연 상태에서 ping 보내니까 pong..!! 감동스럽다.. 

이제 로컬 -> private subnet의 Valkey는 테스트가 성공했으니, ALB-> Ingress가 가능한지 테스트해볼 차례..!
일단 EC2 -> Ingress 먼저 확인해보려고, EC2의 공인 IP를 활용해서 ingress path들을 접속해봤는데.. timeoutdl 이 발생한다..?
찾아보니 ssh는 EC2내부의 기본적으로 localhost포트만 열고, 외부에서 접근하려면 gateway port라는 config를 수정해줘야 가능하다고 함

ec2의 /etc/ssh/sshd_config에서 GatewayPorts를 no -> yes로 수정후 restart!
그리고 ssh는 기본적으로 ec2의 로컬호스트만 받아들여가지고 다른 외부에서도 접근 가능하도록 * 사용!


ssh -i "kyeongmin-key.pem" -v -R *:8080:localhost:30890 -L 6379:edos-valkey-group.1ngxr9.ng.0001.apn2.cache.amazonaws.com:6379 ec2-user@15.165.74.214
혹시 보안적 문제가 생길까 생각을 해봤는데, 보안그룹으로 EC2에 현재 내 IP만 허용하면 터널이 완전히 열려도 괜찮을 것 같음

그래서 해봤는데.. 여전히 Connection Refused.. 왜 그런지 해서 80포트를 listen하고 있는지 확인하려고 sudo netstat -ntlp | grep :80 했는데 아무것도 안나옴..!!! 뭐가 80포트를 이미 사용하고 있어서 그런건가?
그래서 8080포트로 ssh하게 수정했더니 Listen하는게 생김!
=> gemini말로는 1~1023번은 관리자 권한이 필요한 특권포트여서 안됐다고 함

*가아니라 0.0.0.0 써주니까 입구가 확장됐는지.. 연락가능하게 됨

ssh -i "kyeongmin-key.pem" -v -R 0.0.0.0:8080:localhost:30890 -L 6379:edos-valkey-group.1ngxr9.ng.0001.apn2.cache.amazonaws.com:6379 ec2-user@15.165.74.214

![alt text](image-18.png)

이제 EC2 -> Ingress도 가능하다는 것을 알게됨

이제 슬슬 포트가 어지러운데
ALB(80) -> Proxy EC2(8080) -> SSH tunnel(8080->30890) -> IngressController(30890)-> Container식으로 진행됨

이제 그럼 ALB -> EC2를 테스트하면 전체적으로 가능할 것 같음


이전에 EC2 포트를 8080으로 바꿔서 타겟 그룹 수정 및 ec2에서 alb만 허용하도록 수정
![alt text](image-19.png)
![alt text](image-20.png)

기존에는 EC2 IP로 접근했었는데 이제는 ALB DNS로 접근하려고 함
http://edos-alb-1814415094.ap-northeast-2.elb.amazonaws.com/github-webhook

하지만 503 에러..!가 발생했지만, ALB 대상 그룹에 등록된 대상이 없었던 것..!

# EC2를 대상 그룹의 대상으로 작성
resource "aws_lb_target_group_attachment" "proxy_attachment" {
  target_group_arn = aws_lb_target_group.main.arn
  target_id        = aws_instance.proxy_server.id # EC2 리소스 이름
  port             = 8080                      # 우리가 뚫어놓은 터널 포트
}
를 통해 프록시 서버로 만든 EC2를 대상 그룹의 대상으로 설정 했더니 성공했다..!

![alt text](image-21.png)

이제 ALB -> Proxy -> Ingress -> Container 구조가 성공했다 ㅠㅠㅠㅠ 하이브리드 완성인가


ab -n 1000 -c 50 http://edos-alb-1814415094.ap-northeast-2.elb.amazonaws.com/detect
를 통해서 50개씩 총 1000번의 트래픽을 보내볼 예정


![alt text](image-22.png)

호기롭게 보냈지만 차단된 IP는 없었다.. (실패했다는 뜻)
![alt text](image-23.png) 

역시 로그를 확인해보기 위해 Detection을 봤는데..! 200OK로 잘 왔음
하지만 Responder에서 503 에러가..ㅠ
계속 생각해보다가 configmap을 봤었는데 초기에 잘못 작성했었다.
detection -> alb로 보내고 있던것과 RedisHost는 ssh 터널로 인해 내 노트북의 프라이빗 IP를 써야한다는 점..
그외 상당히 많은 환경변수 수정과 rollout restart가 존재했다..
하지만 responder에서 계속 503 에러가 발생하는 것을 확인했는데..
알고보니 ssh 터널을 열 때 아까처럼 기본적으로 127.0.0.1로 들어오는 요청만 Valkey로 보내줬던 것...

ssh -i "kyeongmin-key.pem" -v -R 0.0.0.0:8080:localhost:30890 -L 0.0.0.0:6379:edos-valkey-group.1ngxr9.ng.0001.apn2.cache.amazonaws.com:6379 ec2-user@15.165.74.214

이것처럼 Remote 뿐만이 아니라, Local 또한 0.0.0.0으로 개방해줘야했다..
하지만 또 503에러!!!!!!!!!!!!!!!!!!!!!!!!!

gemini가 많은 클라우드 네이티브 앱들이 기동 시점에 백엔드 서비스(Valkey)와의 연결을 확정 짓기 때문에, 인프라 복구 후에는 반드시 애플리케이션의 재시작(Restart)을 통해 상태를 동기화해야 한다.라고 해서 rollout restart를 마지막으로 진행했더니..! 성공했다.
redis에 블랙리스트가 추가된 것을 볼 수 있었다 ㅠㅠㅠㅠ 

![alt text](image-24.png)