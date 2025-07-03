pipeline {
    agent any

    environment {
        IMAGE_NAME = "edos-service"
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

        stage('Docker Image 확인') {
            steps {
                echo "🔍 생성된 이미지 목록 확인:"
                sh "docker images | grep $IMAGE_NAME"
            }
        }
    }
}
