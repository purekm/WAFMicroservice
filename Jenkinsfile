pipeline {
    agent any

    environment {
        DOCKER_USER = 'kyeongmin516'
        DOCKER_CREDENTIALS_ID = 'docker-hub-login' // 👈
        
        IMAGE_RESPONDER = "${DOCKER_USER}/waf-responder"
        IMAGE_DETECTION = "${DOCKER_USER}/waf-detection"
    }

    stages {
        stage('Clone') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Images') { 
            steps {
                // docker-compose build 시 이미지 이름이 waf-responder로 나오는지 확인!
                sh "docker-compose build"
            }
        }

        stage('Push to Docker Hub') {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: env.DOCKER_CREDENTIALS_ID, usernameVariable: 'USER', passwordVariable: 'PASS')]) {
                        
                        // --password-stdin을 사용하여 보안 유지
                        sh "echo ${PASS} | docker login -u ${USER} --password-stdin"

                        // Responder 푸시
                        sh "docker tag waf-responder:latest ${env.IMAGE_RESPONDER}:${env.BUILD_NUMBER}"
                        sh "docker tag waf-responder:latest ${env.IMAGE_RESPONDER}:latest"
                        sh "docker push ${env.IMAGE_RESPONDER}:${env.BUILD_NUMBER}"
                        sh "docker push ${env.IMAGE_RESPONDER}:latest"

                        // Detection 푸시
                        sh "docker tag waf-detection:latest ${env.IMAGE_DETECTION}:${env.BUILD_NUMBER}"
                        sh "docker tag waf-detection:latest ${env.IMAGE_DETECTION}:latest"
                        sh "docker push ${env.IMAGE_DETECTION}:${env.BUILD_NUMBER}"
                        sh "docker push ${env.IMAGE_DETECTION}:latest"
                    }
                }
            }
        }
    }
    
    post {
        always {
            // 빌드 후 깔끔하게 로그아웃
            sh "docker logout"
        }
        success {
            echo "✅ Build #${env.BUILD_NUMBER} 성공!"
        }
        failure {
            echo "❌ Build #${env.BUILD_NUMBER} 실패..."
        }
    }
}