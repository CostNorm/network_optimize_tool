# 네트워크 최적화 도구 (Network Optimize Tool)

AWS VPC 환경에서 EC2 인스턴스의 네트워크 트래픽을 분석하여 VPC 엔드포인트 생성을 통한 네트워크 최적화를 자동화하는 도구입니다.

## 개요

이 도구는 CloudTrail 로그를 분석하여 EC2 인스턴스가 AWS 서비스(S3, ECR 등)에 접근할 때 VPC 엔드포인트를 사용하지 않는 트래픽을 감지하고, 필요한 VPC 엔드포인트를 자동으로 생성합니다.

## 프로젝트 구조

```
network_optimize_tool/
├── IaC/                          # Terraform 인프라 코드
│   ├── main.tf                   # Terraform 메인 설정
│   ├── variables.tf              # Terraform 변수 정의
│   └── terraform.tfstate*        # Terraform 상태 파일
└── code/                         # Lambda 함수 코드
    ├── lambda_function.py        # 메인 Lambda 함수
    └── vpc_endpoint_utils.py     # VPC 엔드포인트 유틸리티
```

## 주요 기능

### 1. CloudTrail 로그 분석
- EC2 인스턴스별 AWS 서비스 접근 트래픽 분석
- VPC 엔드포인트 미사용 트래픽 감지
- S3, ECR 등 대상 서비스 지원

### 2. VPC 엔드포인트 자동 생성
- Gateway 엔드포인트 (S3)
- Interface 엔드포인트 (ECR 등)
- 고가용성(HA)을 위한 다중 AZ 서브넷 자동 선택
- 기존 엔드포인트 중복 생성 방지

### 3. 네트워크 리소스 자동 관리
- 라우트 테이블 자동 선택 및 연결
- 보안 그룹 자동 적용
- Private DNS 설정

## 사용 방법

### 1. 인프라 배포

```bash
cd IaC
terraform init
terraform plan
terraform apply
```

### 2. Lambda 함수 호출

```json
{
  "instance_id": "i-xxxxxxxxx",
  "region": "ap-northeast-2",
  "days": 1,
  "hours": 12
}
```

#### 입력 파라미터
- `instance_id` (필수): 분석할 EC2 인스턴스 ID
- `region` (필수): AWS 리전
- `days` (선택): 분석 기간 (일 단위)
- `hours` (선택): 분석 기간 (시간 단위)

#### 응답 형태
```json
{
  "statusCode": 200,
  "body": [
    {
      "service": "S3",
      "region": "ap-northeast-2",
      "status": "created",
      "endpoint_id": "vpce-xxxxxxxxx",
      "state": "pending"
    }
  ]
}
```

## 설정

### Terraform 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `region` | AWS 리전 | `ap-northeast-2` |
| `profile` | AWS 프로파일 | `costnorm` |
| `function_name` | Lambda 함수명 | `network_optimize_lambda` |
| `lambda_timeout` | 실행 제한 시간 (초) | `300` |
| `lambda_memory` | 메모리 할당 (MB) | `1024` |
| `lambda_runtime` | Python 런타임 | `python3.13` |
| `lambda_handler` | 핸들러 함수 | `lambda_function.lambda_handler` |
| `lambda_architecture` | 아키텍처 | `x86_64` |

### 환경 설정

- `TARGET_SERVICES`: 분석 대상 AWS 서비스
- `ENDPOINT_MISSING_THRESHOLD`: VPC 엔드포인트 생성 임계값 (기본값: 5회)

## 전제 조건

### AWS 권한
Lambda 함수에는 다음 권한이 필요합니다:
- EC2 서비스 관련 권한
- CloudTrail 로그 읽기 권한
- CloudWatch 로그 쓰기 권한

### AWS 서비스
- CloudTrail 활성화 필수
- VPC 환경에서 실행되는 EC2 인스턴스

## 지원 서비스

현재 지원하는 AWS 서비스:
- **S3** (Gateway 엔드포인트)
- **ECR** (Interface 엔드포인트)

## 제한사항

- CloudTrail 로그 보존 기간: 최대 90일
- 분석 가능한 최대 이벤트 수: 페이지네이션으로 처리
- 동일 VPC 내 기존 엔드포인트가 있을 경우 생성하지 않음