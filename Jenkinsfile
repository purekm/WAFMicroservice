pipeline {
    agent any

    environment {
        IMAGE_NAME = "edos-service"
        IMAGE_TAG = "latest"
        CONTAINER_NAME = "edos-test"
        PORT = "5000"
    }

    stages {
        stage('Clone') {
            steps {
                echo '📥 GitHub 저장소에서 코드 받는 중...'
                checkout scm
            }
        }

        stage('Docker Build') {
            steps {
                echo "🐳 Docker 이미지 빌드 중..."
                sh "docker build -t $IMAGE_NAME ."
            }
        }

        stage('Remove Old Container') {
            steps {
                echo "🗑 기존 컨테이너 삭제 시도..."
                sh """
                    docker stop $CONTAINER_NAME || true
                    docker rm $CONTAINER_NAME || true
                """
            }
        }

        stage('Run New Container') {
            steps {
                echo "🚀 새 컨테이너 실행 중..."
                sh "docker run -d -p $PORT:$PORT --name $CONTAINER_NAME $IMAGE_NAME:$IMAGE_TAG"
            }
        }

        stage('Check Running') {
            steps {
                echo "📦 실행 중인 컨테이너 확인:"
                sh "docker ps | grep $CONTAINER_NAME || true"
            }
        }
    }
    post {
    success {
        script {
            discordSend(
                webhookURL: credentials('Discord_Webhook'),
                title: "${env.JOB_NAME} ✅ 성공",
                description: "🎉 Build #${env.BUILD_NUMBER} 성공!\n${env.BUILD_URL}",
                result: currentBuild.currentResult
            )
        }
    }
    failure {
        script {
            discordSend(
                webhookURL: credentials('Discord_Webhook'),
                title: "${env.JOB_NAME} ❌ 실패",
                description: "🚨 Build #${env.BUILD_NUMBER} 실패...\n${env.BUILD_URL}",
                result: currentBuild.currentResult
            )
        }
    }
}
