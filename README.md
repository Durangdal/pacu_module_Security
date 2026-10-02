# cloudtrail__enum_security

Pacu용 읽기 전용 CloudTrail 보안 열거 및 IAM 권한 시뮬레이션 모듈입니다.
공식 Pacu 커밋 e597f23ecfb88b82f706c5f0cac9d4577c2af262에서 확인한 모듈/API/DB 패턴을 사용합니다.

## 설치

이 저장소의 cloudtrail__enum_security 폴더를 Pacu 저장소의
`pacu/modules/cloudtrail__enum_security/`에 복사하고 Pacu를 다시 시작하세요.
기존 Pacu의 boto3/botocore 외 추가 의존성은 없습니다. Python 3.9 이상입니다.

```text
run cloudtrail__enum_security --regions us-east-1,ap-northeast-2
data CloudTrail
```

기본 실행에서 발견한 리소스를 대상으로 IAM 시뮬레이션을 수행합니다.
실제 중단/삭제/변경 API는 실행하지 않습니다.
시뮬레이션을 생략하려면 `--no-simulate`를 지정하세요.

## 출력

`CloudTrail.SecurityPosture`에 원본 설정, 섹션별 조회 상태, 캐시 정책 증거,
시뮬레이션 대상 ARN·응답·누락 조건을 저장합니다. 기존 CloudTrail 필드는 보존합니다.
마지막에 Security Summary를 출력합니다.

SimulationDecision:
- `allowed`: 입력한 리소스와 조건에서 시뮬레이션 허용
- `explicitDeny`: 시뮬레이션 명시적 거부
- `implicitDeny`: 시뮬레이션 범위에서 허용 근거 없음
- `UNKNOWN`: 대상 미발견, 주체 식별 실패, API 거부/오류, 누락 조건, 불완전 응답

**실제 실행 가능 여부를 확정하는 값이 아닙니다.** LiveExecution은 항상 NOT TESTED입니다.
Assumed role은 IAM GetRole로 경로를 포함한 정식 role ARN을 조회합니다.
이는 기본 역할 정책 평가이며 현재 STS 세션 제약을 완전히 재현하지 않습니다.
root/federated 등 지원하지 않는 주체는 UNKNOWN입니다.

S3는 발견한 로그 버킷/접두사 아래의 **가상 객체 ARN**을 시뮬레이션합니다.
실제 로그 객체/버전 존재, Object Lock에 따른 삭제 성공 여부를 검증하지 않습니다.
Logs는 필터가 발견된 log group ARN, CloudWatch는 metric namespace/name이 연결된
후보 alarm ARN을 평가합니다. EventBridge는 발견한 모든 rule ARN을 평가하므로
CloudTrail 관련 규칙이라고 자동 확정하지 않습니다.

권한 시뮬레이션용 추가 호출:
- sts:GetCallerIdentity
- iam:GetRole (assumed role만)
- iam:GetContextKeysForPrincipalPolicy
- iam:SimulatePrincipalPolicy

이 권한들이 없더라도 구성 열거를 계속하며 시뮬레이션은 UNKNOWN으로 기록합니다.
조건이 필요한 경우 선택적으로 IAM ContextEntries JSON 목록 파일을 전달할 수 있습니다:

```text
run cloudtrail__enum_security --context-file /path/to/context.json
```

예시 파일 내용:

```json
[
  {"ContextKeyName": "aws:RequestedRegion", "ContextKeyValues": ["us-east-1"], "ContextKeyType": "string"}
]
```

제공한 조건은 모든 평가에 그대로 적용됩니다. 실제 요청의 조건이라는 보장은 없으며,
여러 리전에서는 조건 파일을 분리해 실행하세요. 조건값을 임의로 추정하지 않습니다.

## 수집 범위

- Trail 이름/HomeRegion/MultiRegion/Organization, Logging 상태와 전달 오류
- Management/Data/ReadWrite/EventSelectors/AdvancedEventSelectors, Insights
- LogFileValidation과 반환된 digest 상태; digest 파일/서명 검증은 수행하지 않음
- S3 policy/versioning/Object Lock/encryption, Trail·bucket KMS metadata/policy/rotation
- 연결된 Logs group/metric filters, 지역 metric/composite alarms와 후보 연결
- 선택한 리전 EventBridge buses/rules/targets, 발견된 SNS topics/subscriptions
- 위험 권한 10개에 대한 활성 키 캐시 증거 및 리소스별 IAM 시뮬레이션

알림 전달 성공, composite alarm 재귀 연결, 외부 SIEM, CloudTrail Lake, 다른 계정의
전체 커버리지 및 최종 유효 권한은 검증하지 않습니다. 객체 데이터는 다운로드하지 않습니다.
페이지 중간 실패 시 받은 자료는 보존하되 실패 상태로 표시합니다.
읽기/시뮬레이션 API도 감사 로그 및 탐지 알림을 발생시킬 수 있습니다.

## 검증

```text
python -m py_compile cloudtrail__enum_security/main.py
python -m unittest discover -s . -p "test_cloudtrail_enum_security.py"
```

제공된 테스트는 AWS 접속 없이 동작을 확인합니다. botocore가 없는 테스트 환경에서는
예외 타입 대역을 사용합니다. 실제 AWS 및 Pacu 전체 통합 실행은 검증하지 않았습니다.

AWS API 참고:
https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html

GitHub에는 이 모듈 폴더·README·테스트만 업로드하세요. Pacu 전체 과거 이력은 필요하지 않습니다.
