pipeline {
    agent any

    environment {
        // --- ECR 설정 ---
        // Jenkins 관리자는 아래 값들을 실제 환경에 맞게 수정해야 합니다.
        
        // 1. AWS 계정 ID
        AWS_ACCOUNT_ID = '257394454217' 
        
        // 2. AWS 리전
        AWS_REGION = 'ap-northeast-2' 
        
        // 3. Jenkins에 등록된 AWS Credentials ID
        AWS_CREDENTIALS_ID = 'aws-credentials-for-ecr'

        // --- 자동으로 계산되는 변수 (수정 불필요) ---
        ECR_REGISTRY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        
        // --- 서비스별 ECR 리포지토리 이름 ---
        ECR_REPOSITORY_RESPONDER = 'wafmicroservice/responder'
        ECR_REPOSITORY_DETECTION = 'wafmicroservice/detection'
    }

    stages {
        stage('Clone') {
            steps {
                echo ' GitHub 저장소에서 코드 받는 중...'
                checkout scm
            }
        }

        stage('Build Docker Images') { 
            steps {
                echo " Docker Compose로 이미지 build"
                sh "docker-compose build"
            }
        }

        stage('Push to ECR') {
            steps {
                script {
                    // Jenkins에 저장된 AWS 자격 증명을 사용하여 ECR에 로그인합니다.
                    withCredentials([aws(credentialsId: env.AWS_CREDENTIALS_ID, accessKeyVariable: 'AWS_ACCESS_KEY_ID', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                        
                        echo "ECR에 로그인 중..."
                        sh "aws ecr get-login-password --region ${env.AWS_REGION} | docker login --username AWS --password-stdin ${env.ECR_REGISTRY}"

                        // Responder 이미지를 태그하고 ECR에 푸시합니다.
                        echo "Pushing Responder image to ECR..."
                        sh "docker tag waf-responder:latest ${env.ECR_REGISTRY}/${env.ECR_REPOSITORY_RESPONDER}:${env.BUILD_NUMBER}"
                        sh "docker push ${env.ECR_REGISTRY}/${env.ECR_REPOSITORY_RESPONDER}:${env.BUILD_NUMBER}"

                        // Detection 이미지를 태그하고 ECR에 푸시합니다.
                        echo "Pushing Detection image to ECR..."
                        sh "docker tag waf-detection:latest ${env.ECR_REGISTRY}/${env.ECR_REPOSITORY_DETECTION}:${env.BUILD_NUMBER}"
                        sh "docker push ${env.ECR_REGISTRY}/${env.ECR_REPOSITORY_DETECTION}:${env.BUILD_NUMBER}"
                    }
                }
            }
        }
    }
    post {
        // (기존과 동일)
        success {
            script {
                withCredentials([string(credentialsId: 'Discord_Webhook', variable: 'DISCORD_URL')]) {
                    discordSend(
                        webhookURL: DISCORD_URL,
                        title: "${env.JOB_NAME} ✅ 성공",
                        description: " Build #${env.BUILD_NUMBER} 성공! ECR에 이미지가 푸시되었습니다.",
                        result: 'SUCCESS'
                    )
                }
            }
        }
        failure {
            script {
                withCredentials([string(credentialsId: 'Discord_Webhook', variable: 'DISCORD_URL')]) {
                    discordSend(
                        webhookURL: DISCORD_URL,
                        title: "${env.JOB_NAME} ❌ 실패",
                        description: " Build #${env.BUILD_NUMBER} 실패...\n",
                        result: 'FAILURE'
                    )
                }
            }
        }
    }
}