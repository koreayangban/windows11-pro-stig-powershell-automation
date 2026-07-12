# windows11-pro-stig-powershell-automation
![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=flat-square&logo=powershell&logoColor=white)
![Windows 11 Pro](https://img.shields.io/badge/Windows%2011%20Pro-%230078D4.svg?style=flat-square&logo=windows-11&logoColor=white)
![STIG V2R7](https://img.shields.io/badge/STIG-V2R7-orange?style=flat-square)
![CMMC Level 2](https://img.shields.io/badge/CMMC-Level%202-green?style=flat-square)
![K-RMF](https://img.shields.io/badge/K--RMF-Compliance-0f2b5c?style=flat-square)

DISA Windows 11 STIG (V2R7) PowerShell automation for standalone/air-gapped Pro workgroup systems — CMMC Level 2 CM Domain, RMF / K-RMF CM Family

Windows 11 Pro 에디션 보안 기준선을 자동으로 점검하고 조치하는 PowerShell 도구입니다. 기준선은 DISA Windows 11 STIG V2R7 을 따르고 각 항목을 CMMC Level 2 보안통제에 매핑했습니다. 외부 의존성없이 단독으로 동작합니다. 운영 환경에 적용하기 전에 반드시 시험용 PC에서 16_* 을 기본값(미리보기)으로 먼저 확인하세요.
어떠한 보증도 제공하지 않으며 적용결과에 대한 책임은 사용자에게 있습니다. 

※ 「Microsoft Windows 11 STIG SCAP Benchmark(Ver. 2, Rel. 7)」의 전체 보안통제항목(262개) 중 174개 항목에 대해 안전한 보안 설정으로 자동 적용합니다. 나머지 항목은 관리자가 직접 수동으로 조치하거나 운영 환경에 따라 해당 없음(N/A)으로 분류하여야 합니다. SCC(SCAP Compliance Checker) 5.14.1을 이용하여 적용 결과의 유효성을 검증할 수 있습니다.

## 파일 구성

| 파일 | 설명 |
|------|------|
| `15_STIG_Win11_Check.ps1`   | 보안 기준선 PASS/FAIL/NA/MANUAL 결과를 확인합니다. |
| `16_STIG_Win11_Enforce.ps1` | 적용 가능한 항목을 조치합니다. 기본은 미리보기(변경 없음)이며 실제 변경은 `-Apply` 를 붙일 때만 수행합니다. |
| `STIG_Win11_Restore.ps1`    | 조치 도구가 만든 `backup_<시각>` 폴더로 원상복구합니다. |
| `_CmmcCommon.ps1`           | 공용 함수(실행 컨텍스트, 로깅) |
| `STIG_Win11_Baseline.csv`   | 기준선 데이터로 STIG 항목 1건이 한 행이며, 점검방법·레지스트리 경로·현재값·기대값·CCI·CMMC Practices·비고를 담습니다. |
| `01_PasswordPolicy.ps1`     | [단독 모듈] 계정/암호 정책 |
| `04_AuditPolicy.ps1`        | [단독 모듈] 고급 감사 정책(GUID 기반) |
| `06_FipsMode.ps1`           | [단독 모듈] FIPS 알고리즘 정책 |
| `07_BitLocker.ps1`          | [단독 모듈] BitLocker 상태/구성 |

CSV는 전체 기준선입니다. 일부 행은 이 샘플 코드에 포함되지 않은 보조 모듈을 가리킵니다.

## 요구 사항

- Windows 11, PowerShell 5.1 이상
- `16_*`(조치: -mode enforce)와 `STIG_Win11_Restore.ps1`은 관리자 권한 필요
- `15_*`(점검)과 단독 모듈의 점검 모드는 읽기 전용
- 스크립트가 서명되어 있지 않으므로 기본 실행 정책에서 차단됩니다. 관리자 권한 PowerShell로 실행하고, 실행 정책을 우회하세요(아래 '시작하기' 참고).

## 시작하기

PowerShell을 관리자 권한으로 실행하세요. 그런 다음 실행 정책을 우회합니다.

```powershell
powershell -ep bypass
# powershell -ExecutionPolicy Bypass 와 동일
```
이후 스크립트가 있는 폴더로 이동(`cd`)한 뒤 아래 명령을 실행합니다.

## 사용법

```powershell
# 1) 읽기 전용 점검
.\15_STIG_Win11_Check.ps1

# 2) 조치 미리보기(변경 없음 — 기본값)
.\16_STIG_Win11_Enforce.ps1

# 3) 선택 항목만 실제 조치(관리자 권한 필요, 변경 전 자동 백업)
.\16_STIG_Win11_Enforce.ps1 -Apply -Only WN11-AU-000500,WN11-CC-000039

# 4) 적용 가능한 전체 기준선 조치
.\16_STIG_Win11_Enforce.ps1 -Apply

# 5) 직전 조치를 원복
.\STIG_Win11_Restore.ps1 -BackupDir .\_output\backup_YYYYMMDD_HHMMSS -Apply
```

단독 모듈은 `-Mode Check`(읽기 전용) 또는 `-Mode Enforce` 로 실행합니다.

```powershell
.\06_FipsMode.ps1 -Mode Check
.\01_PasswordPolicy.ps1 -Mode Check
```

## 주요 항목 참고

- 이벤트 로그 크기(`WN11-AU-000500/505/510`)는 레지스트리 `MaxSize` 값으로 조치합니다. 목표값은 `5120000` 입니다.
- ECC 곡선 순서(`WN11-CC-000052`)는 두 항목(`NistP384 NistP256`)을 가진 `REG_MULTI_SZ` 입니다.
- 다른 사용자로 실행 제거(`WN11-CC-000039`)는 네 개 레지스트리 경로(batfile/cmdfile/exefile/mscfile)에 `SuppressionPolicy=4096` 을 씁니다. CSV에서는 네 경로가 한 행에 `|` 로 구분되어 있고, `15`/`16` 이 이를 나누어 각각 처리합니다.
- VBS / HVCI(`WN11-CC-000070/000080`)는 DeviceGuard 레지스트리 값을 설정하지만 실제 활성화에는 호환 하드웨어(가상화/secure boot)가 필요합니다. 하드웨어가 지원하지 않으면 N/A 또는 편차로 처리하세요.

## 안전장치

- `16_*` 은 기본이 미리보기입니다. `-Apply` 를 붙이지 않으면 아무것도 변경하지 않습니다.
- 모든 변경은 `_output\backup_<시각>\` 아래에 백업(레지스트리 키별 `reg export`, `secedit /export`, `auditpol /backup`)됩니다. 되돌리려면 `STIG_Win11_Restore.ps1` 을 사용하세요. ※ 백업 시점에 없던 정책값은 복원 시점에 적용되지 않습니다.
- 계정 잠금·인증 관련하여 정책을 조치할 때는 자체 `계정잠김`에 주의하세요.
- 일부 정책은 적용에 재부팅이 필요합니다.
