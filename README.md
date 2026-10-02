# cloudtrail__enum_security

공식 RhinoSecurityLabs/Pacu master의 커밋 `e597f23ecfb88b82f706c5f0cac9d4577c2af262`를 기준으로 작성했습니다.
`module_info`, `parser`, `main(args, pacu_main)`, `summary(data, pacu_main)`가 모두 main.py에 포함됩니다.

## 설치 및 실행

Pacu 소스 체크아웃의 `pacu/modules/cloudtrail__enum_security/`에 이 폴더의
`main.py`와 `__init__.py`를 복사하세요. 기존 Pacu Python 환경의 boto3/botocore를 사용합니다.
새 DB 스키마나 추가 패키지는 필요하지 않습니다. 모듈을 복사한 뒤 Pacu를 다시 시작하세요.

```text
pacu
help cloudtrail__enum_security
run cloudtrail__enum_security --regions us-east-1,ap-northeast-2
data CloudTrail
```

전체 세션 리전을 사용할 때:

```text
run cloudtrail__enum_security
```

이전에 detection__enum_services가 수집한 Trail 목록을 재사용할 때:

```text
run cloudtrail__enum_security --use-cached-trails --regions us-east-1,ap-northeast-2
```

캐시 옵션은 **목록 발견만** 생략하며, 목록의 최신성/완전성을 보장하지 않습니다.
나머지 설정은 다시 조회합니다. 기존 목록이 없으면 캐시 모드에서 Trail을 발견하지 않습니다.
기본 실행은 목록을 새로 읽되 기존 `session.CloudTrail.Trails`를 덮어쓰지 않습니다.

비대화형 실행:

```text
pacu --session SESSION_NAME --module-name cloudtrail__enum_security --exec --module-args="--regions us-east-1,ap-northeast-2"
```

## 결과와 재사용

- `get_active_session`, `get_regions`, `get_boto3_client`, `pacu_main.print` 및
  deepcopy → `session.update(pacu_main.database, CloudTrail=...)` 패턴을 기존 모듈에서 재사용합니다.
- 기존 CloudTrail 필드를 보존하고 `session.CloudTrail.SecurityPosture`에 저장합니다.
- `key_info()`의 `Permissions.Allow/Deny`, `Resources`, `Conditions` 및
  `PermissionsConfirmed` 구조는 AWSKey와 iam__enum_permissions 소스에 맞췄습니다.
- 기존 수집기 전체를 호출하면 불필요한 서비스 열거가 발생하고, S3 다운로드 모듈은
  객체 다운로드를 포함하므로 직접 실행하거나 import하지 않습니다.
- 동일 실행 중 버킷/리전/요청 인자가 같은 읽기는 캐시하며 shadow Trail은 ARN으로 중복 제거합니다.

각 조회 결과에는 `Status`, `Data`, 실패 시 `ErrorCode`가 있습니다.
`OK`인 빈 목록과 `UNKNOWN`/`ACCESS DENIED`를 구분합니다. 페이지 중간 실패는
이미 받은 자료를 보존하면서 실패 상태로 표시합니다. 예상된 미설정 오류는
`NOT CONFIGURED`입니다. 권한 거부를 다른 리전/리소스 전체에 일반화하지 않습니다.

## 수집 범위

1. Trail 원본 설정: Name, HomeRegion, IsMultiRegionTrail, IsOrganizationTrail.
   get_trail_status: IsLogging, 최신 전달 시각/오류 및 반환되는 digest 전달 정보.
2. get_event_selectors: EventSelectors의 IncludeManagementEvents, DataResources,
   ReadWriteType, ExcludeManagementEventSources와 AdvancedEventSelectors 원본 조건.
   get_insight_selectors의 반환 정보도 저장합니다.
3. LogFileValidationEnabled와 가능한 상태 정보. **Digest 파일/서명 체인 검증은 수행하지 않습니다.**
4. S3 버킷 위치, policy, versioning, Object Lock, 기본 encryption.
   Trail KMS 및 버킷에서 명시한 KMS key의 metadata/key policy/rotation.
   버킷 기본 암호화는 개별 객체의 암호화/보존을 증명하지 않습니다.
5. 연결된 Logs 그룹, metric filters와 해당 리전 metric/composite alarms.
   Namespace/name으로 metric alarm 후보를 연결합니다. 차원·metric math·composite alarm의
   재귀 연결 및 실제 알림 전달 성공은 판정하지 않습니다.
   선택한 리전의 EventBridge 모든 bus/rule/target을 페이지 끝까지 열거하며,
   event pattern 적용 여부는 자동 확정하지 않습니다. 로그 그룹은 ARN의 리전에서 읽습니다.
   Trail, 연결 후보 alarm, EventBridge target에 명시된 SNS topic의 attributes/subscriptions를 읽습니다.
   전체 SNS 계정 목록이나 다른 대상 서비스의 내부 전달 체인은 추적하지 않습니다.
6. 위험 권한: **활성 키의 기존 Pacu 권한 데이터만** 사용합니다.
   Allow/Deny 패턴과 증거를 표시하고 실제 EffectivePermission은 항상 UNKNOWN입니다.
   리소스/조건, 명시적 Deny, SCP, permissions boundary, 세션 정책, 리소스 정책,
   캐시 수집 시각을 종합한 최종 권한 검증을 수행하지 않기 때문입니다.
   관련 기록이 없으면 PolicyEvidence 역시 UNKNOWN입니다. IAM 모듈을 자동 실행하지 않습니다.

조회 API도 AWS 감사 로그/탐지 알림의 대상이 될 수 있습니다.
StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors/PutInsightSelectors,
S3 DeleteObject/DeleteObjectVersion 및 탐지 변경 API는 호출하지 않습니다.
허용한 조회 이름만 Reader에서 실행할 수 있도록 제한했습니다.

CloudTrail Lake, 계정 전체 유효 이벤트 커버리지, 외부 SIEM, 조직 다른 계정의 설정은
이 모듈의 완전성 주장에 포함되지 않습니다. Security Summary의 경고는 구성 관찰이며
정책/위협 모델에 따른 최종 보안 판정을 대신하지 않습니다.

## 검증

검증 결과: Python 문법 검사 통과, boto3 1.28.85 / botocore 1.31.85
(공식 Pacu 의존성 범위)에서 오프라인 테스트 4개 통과. 실제 AWS 실행 및
Pacu 전체 의존성을 설치한 통합 런타임 검증은 수행하지 않았습니다.

문법 검사:

```text
python -m py_compile pacu/modules/cloudtrail__enum_security/main.py
```

제공한 테스트 파일은 모듈 폴더와 나란히 놓고 Pacu의 Python 환경에서 실행합니다:

```text
python -m unittest discover -s . -p "test_cloudtrail_enum_security.py"
```

오프라인 테스트는 botocore 공식 service model로 실행 인자를 검증하고,
권한 거부 후 계속 실행, 페이지 처리/부분 실패, ARN 중복 제거, SNS 연결 후보,
기존 DB 필드 보존, JSON 직렬화, 권한 UNKNOWN 및 변경 API 차단을 확인합니다.
실제 AWS 자격 증명이나 AWS 연결은 사용하지 않습니다.

## 확인한 공식 소스

- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/modules/detection__enum_services/main.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/modules/cloudtrail__download_event_history/main.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/modules/cloudwatch__download_logs/main.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/modules/s3__download_bucket/main.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/modules/sns__enum/main.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/modules/iam__enum_permissions/main.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/core/models.py
- https://github.com/RhinoSecurityLabs/pacu/blob/e597f23ecfb88b82f706c5f0cac9d4577c2af262/pacu/main.py
