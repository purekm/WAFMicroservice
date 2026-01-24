# provider.tf

terraform {
  required_providers { # 프로젝트를 실행하기에 필요한 도구
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # 5.0 버전 사용
    }
  }
}
provider "aws" {
  region = "ap-northeast-2" # 서울 리전
}