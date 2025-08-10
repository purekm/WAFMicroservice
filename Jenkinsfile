pipeline {
    agent any

    stages {
        stage('Clone') {
            steps {
                echo ' GitHub 저장소에서 코드 받는 중...'
                checkout scm
            }
        }

        stage('Run Services with Docker Compose') {
            steps {
                script {
                    dockerCompose.up(build: true, detached: true)
                }
            }
        }

        stage('Check Running') {
            steps {
                echo " 실행 중인 서비스 확인:"
                sh "docker-compose ps"
                echo " Responder 서비스 Health Check 시도..."
                sh "sleep 10"
                sh "curl --fail http://localhost:8000/health"
            }
        }
    }
    post {
        always {
            script {
                echo " 모든 컨테이너 정리 중..."
                dockerCompose.down(volumes: true)
            }
        }
        success {
            script {
                withCredentials([string(credentialsId: 'Discord_Webhook', variable: 'DISCORD_URL')]) {
                    discordSend(
                        webhookURL: DISCORD_URL,
                        title: "${env.JOB_NAME} ✅ 성공",
                        description: " Build #${env.BUILD_NUMBER} 성공!",
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