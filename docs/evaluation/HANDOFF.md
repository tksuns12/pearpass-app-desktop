# PearPass 독립 포크 — 개발 인수인계

작성일: 2026-09-18 (Asia/Seoul)
상태: **4단계 패치의 Mac 반영·재검증 완료. 평가용이며 제품 사용·배포 불가.**

## 1. 지금 어디까지 왔는가

목표는 로컬 우선 오픈소스 시크릿 관리자다. QR로 승인한 기기들이 중앙 금고 서버 없이 변경을 전달하고, A와 C가 직접 만나지 않아도 B가 중간에서 보관·전달할 수 있어야 한다. 최종 대상은 Windows, macOS, Linux, Android, iOS다. 현재는 PearPass 기존 앱·복제 엔진을 유지하면서 보안 정책과 독립 배포 가능성을 평가하고 있다. 새 제품명은 미정이며 개발 표시 이름은 `Local Vault Evaluation`이다.

**앱에서 실제 바뀐 부분은 평가 프로필 격리, 원본 OTA 차단, 배포 보호장치, 불완전한 기기 퇴출 UI 비활성화다. 서명된 변경 이력·키 세대·기기별 키 전달·영속 전환 코드는 별도 평가 모듈이며 앱의 금고 쓰기·조회·자동완성에는 아직 연결되지 않았다.**

| 항목 | 현재 위치/기준 |
|---|---|
| 개발 저장소 | `tksuns12/pearpass-app-desktop` |
| 작업 브랜치 | `evaluation/bootstrap` |
| 4단계 구현 커밋 | `5dd933594b2e83f145449d414e996887cf537038` |
| 패치 적용 직전 커밋 | `87ad7c4c5cc3adc0ec6013fd4b08a246201abdfe` |
| 로컬 작업 폴더 | `~/Developer/pearpass-evaluation-20260918/pearpass-app-desktop` |
| 모바일 포크 | `tksuns12/pearpass-app-mobile` — 이번 작업에서 변경하지 않음 |
| 코어 포크 | `tksuns12/pearpass-lib-vault-core` — 이번 작업에서 변경하지 않음 |
| 현재 Mac 런타임 | 프로젝트 전용 Node `22.23.2`, macOS arm64 |
| 원본 main | `4378c33479368eb9e46d91c95a779551ffc0e740` — 변경·병합하지 않음 |

구현 이후 문서 전용 커밋이 있을 수 있다. 재개 시 `git log -3 --oneline`과 원격 브랜치를 확인한다. PR, 릴리스, 앱스토어 배포는 이 작업 범위가 아니다.

## 2. 먼저 읽을 파일

| 파일 | 역할 |
|---|---|
| `AGENTS.md` | 기존 UI 컴포넌트·스타일 규칙. UI 수정 전에 읽는다. |
| `docs/evaluation/stage4-macos-verification.json` | 이번 Mac 적용 후 테스트·빌드·해시 검증의 최신 기록 |
| `docs/evaluation/STAGE4.md` | 키 전달 형식, 전환 상태, 저장 어댑터 계약과 한계 |
| `docs/evaluation/STAGE3.md` | 기존 퇴출 호출 경로, 서명된 버전·세대 정책 |
| `docs/evaluation/STAGE2.md` | 설치 재현 방법, 실제 엔진 A→B→C 실험, 기존 엔진 정책 차이 |
| `docs/evaluation/upstream-baseline.json` | 최초 저장소·의존성 커밋·lockfile 기준 |

`stage4-verification.json`과 `stage4-tests.tap`은 **최초 Linux 검토본의 과거 기록**이다. 그 파일의 “Mac 미적용”은 당시 전달 상태이며, 현재 적용 여부는 `stage4-macos-verification.json`을 기준으로 판단한다. 초기 README의 `NOT_RUN` 표 역시 당시 기록이며 후속 단계 자료를 함께 읽어야 한다.

## 3. 코드 지도와 검증된 범위

### 앱 보호장치

`electron/evaluation-profile.cjs`는 평가용 프로필과 명시적 가짜 데이터 모드를 확인한다. `scripts/evaluation/preflight.mjs`는 런타임·의존성·OTA·배포 차단 등을 점검한다. `src/containers/Modal/RevokeAccessModalContentV2/`는 키 교체가 미통합인 현재 퇴출 동작을 비활성화한다. 이는 UI 차단이지 낮은 수준의 모든 IPC/API를 봉쇄한 보안 경계가 아니다.

### 서명된 버전과 키 세대

`scripts/evaluation/policy/signed-policy.mjs`에 `signEpoch`, `verifyEpoch`, `acceptEpoch`, `RevisionLog`, `automaticValue`가 있다. 관리자 공개키를 신뢰 기준으로 세대 연결과 구성원을 검증하며, 각 변경의 작성자 서명과 부모 관계로 최종 버전을 계산한다. 동시 수정과 삭제/수정 충돌은 여러 버전으로 남긴다. `automaticValue`는 단일 확정 버전 외의 상태를 거부하지만, 기존 앱 자동완성은 아직 이 함수를 호출하지 않는다.

`policy/engine-policy.integration.test.mjs`는 실제 Autopass/Corestore에 별도 revision 키로 이력을 저장해 충돌 보존·재시작·명시적 해결을 시험한다. 새 키/구키 비교도 실제 암호문을 사용하지만 키 등록과 전달은 테스트 설정이다.

### 기기별 키 전달 — 이번 적용 코드

`scripts/evaluation/cutover/key-envelope.mjs`의 주요 경계는 다음과 같다.

- `signDeviceBox` / `verifyDeviceBox`: Ed25519 서명 키와 X25519 암호화 키의 연결 문서. 검증에는 신뢰한 서명 공개키와 **별도로 승인한 문서 ID**가 모두 필요하다.
- `sealEpochKey` / `verifyKeyEnvelope` / `openEpochKey`: 수신자·문서·세대·암호문을 관리자 서명과 결합하고 복호화 후 키 확인값을 검증한다.

암호 연산은 Node/OpenSSL의 X25519, HKDF-SHA256, AES-256-GCM, Ed25519를 사용한다. **메시지 조합은 평가용 커스텀 형식이며 HPKE 구현이나 독립 감사 완료 프로토콜이 아니다.** QR 등록, 개인키 소유 증명, OS 키 저장소, 실제 네트워크 전달은 미통합이다. 자체 서명 문서만 보고 새 기기를 승인하면 안 된다.

### 영속 세대 전환 — 이번 적용 코드

`scripts/evaluation/cutover/epoch-journal.mjs`의 `EpochJournal`은 SQLite WAL과 트랜잭션으로 다음 상태를 관리한다.

```text
active(old)
  └─ prepare(next) 커밋 → prepared(old, next): 이 API의 enqueue 차단
       └─ resume(materializeAndVerify) → 검증 후 activate 커밋 → active(next)
```

`prepare` 이후 오류가 나면 준비 상태를 유지하며 구세대 쓰기를 자동 재개하지 않는다. `resume`은 완료 상태 재시도를 처리한다. `enqueue(expectedEpoch, plaintext)`는 세대 확인과 암호화 대기열 저장을 같은 트랜잭션으로 묶는다. 구세대 대기열은 지우지 않고 격리 상태로 보존한다.

**현재 보호 범위는 이 저널 API뿐이다.** 기존 앱/Corestore 쓰기, 발송 중 메시지, 네트워크 전송·수신 확인은 통제하지 않는다. `node:sqlite` 어댑터는 평가용 Linux/macOS 경로만 허용하며 Windows에서는 중단한다. 모바일/Bare/Electron에 그대로 이식 가능한 공통 코어로 간주하지 않는다.

## 4. 이번 Mac 재검증 결과

환경: Node `22.23.2`, macOS arm64, OpenSSL `3.5.7`, SQLite `3.51.3`. 이 단계에서는 앱 GUI를 실행하지 않았고, 실제 시크릿을 가져오거나 마이그레이션하지 않았다.

| 검사 | 결과 |
|---|---|
| `npm run eval:cutover` | **47개 통과**: 키 전달 22, 저널 18, 실제 프로세스 종료 복구 7 |
| `npm run eval:policy-model` | **27개 통과** |
| `npm run eval:policy-integration` | **2개 통과** |
| `npm run eval:test` | **21개 통과** |
| `npm run eval:engine` | **1개 통과**: 기존 A→B→C 엔진 시나리오 |
| `npm test -- --runInBand` | **109개 스위트·726개 테스트·13개 스냅샷 통과** |
| `npm run build` | 통과. 개발 코드 빌드이며 다섯 플랫폼 패키징은 아님 |
| `npm run lint` | 종료 코드 0. 기존 경고는 남아 있음 |
| `npm run eval:preflight` | 종료 코드 0. 제품 보안 승인이나 모든 게이트 통과를 의미하지 않음 |
| `npm run eval:policy` | **종료 코드 2 유지**. 기본 엔진의 기밀성 퇴출 요구사항 실패를 재현 |

47개와 726개는 서로 다른 테스트 범위다. 전체 앱 테스트에 포함된 기존 Electron 33개·퇴출 UI 4개를 다시 합산하지 않는다. 강제 종료 시험은 자기 자식 프로세스의 `SIGKILL`과 DB 재열기이며, 물리적인 전원 차단·디스크 고장·전체 디스크 롤백 시험은 아니다. 엔진 복제 시험은 한 Mac의 독립 저장소와 메모리 스트림이며 실기기 QR/LAN/NAT 검증이 아니다.

## 5. 바로 재개하는 명령

현재 Mac의 기존 설치에서 실행한다. `.nvmrc`는 원본 `22.12.0`이므로 아래 프로젝트 전용 PATH를 선택한다. 사용자의 기본 Node나 전역 설정을 바꾸지 않는다.

```sh
cd ~/Developer/pearpass-evaluation-20260918/pearpass-app-desktop
export PATH="$PWD/../.tools/node-v22.23.2-darwin-arm64/bin:$PATH"
node --version

git status --short
git branch --show-current
git log -3 --oneline

npm run eval:cutover
npm run eval:policy-model
npm run eval:policy-integration
npm run eval:test
npm run eval:engine
npm test -- --runInBand
npm run build
npm run lint
npm run eval:preflight
```

기존 엔진의 미충족 요구사항 확인은 정상 통과 명령들과 분리한다.

```sh
npm run eval:policy
# 예상 종료 코드: 2. 이 결과를 보안 요구사항 성공으로 바꾸면 안 된다.
```

GUI가 필요한 경우에만 `npm run dev:eval`을 사용하고 가짜 데이터만 입력한다. 새 복사본에는 `.tools`와 `node_modules`가 포함되지 않는다. 새 설치는 먼저 `STAGE2.md`, `install-pinned.py`, `prepare-ui.py`를 읽는다. 기존 설치 위에 설치 도구를 다시 실행하지 않는다. 일반 `npm ci --ignore-scripts`에서 Git 의존성 prepare 실행이 관찰된 이력이 있으며, 현재 설치는 고정 커밋 압축본을 이용한 별도 평가 설치다.

## 6. 다음 작업: 실제 Autopass 체크포인트 어댑터

**가장 먼저 할 일은 `materializerStub`을 제품 검증 결과로 취급하지 않고, 그 자리에 실제 저장소 어댑터를 구현·시험하는 것이다.** `EpochJournal.resume(materializeAndVerify)`가 호출할 신뢰한 로컬 함수의 현재 입력은 `{epoch, key}`, 반환값은 `{epoch, storageKey, checkpoint}`다.

어댑터는 실제 새 저장소를 열고 대상 공개키를 확인해야 한다. 이전 체크포인트의 시크릿·서명·부모 관계·삭제 표식·동시 수정 버전을 검증하고, 새 키 저장소에 보존한 뒤 저장 완료를 확인해야 한다. **피어가 보낸 성공 boolean이나 영수증을 그대로 반환하면 안 된다.** 현 저널은 반환값의 일치만 검사하며 데이터 복사·서명 검증 자체를 대신 수행하지 않는다.

중요한 설계 걸림돌: `RevisionLog.ingest()`는 자신의 epoch와 다른 revision을 거부한다. 따라서 과거 revision을 새 epoch로 단순 복사하거나 작성자를 바꿔 재서명하는 것으로 해결하지 않는다. 과거 작성자 서명을 유지하는 검증된 체크포인트/스냅샷과 새 epoch의 수정 이력을 어떻게 연결할지 먼저 정의한다. 수용할 부모 이력 범위와 체크포인트 밖의 과거 변경 격리 정책도 함께 정해야 한다.

완료 기준은 실제 엔진에서 (1) 충돌·삭제 이력의 보존, (2) 저장 중 강제 종료 후 재개, (3) 영수증 전후 종료 시 일관된 상태, (4) 구키만 가진 피어의 새 데이터 해독 실패, (5) 이전 대기열 보존과 구세대 발송 차단을 확인하는 것이다. 현재 저널은 네트워크 발송을 하지 않으므로 마지막 조건에는 추가 구현이 필요하다. 이 단계가 끝나기 전에 퇴출 버튼을 다시 켜지 않는다.

그다음 QR로 승인한 기기 문서와 OS 보안 저장소를 연결하고, 모든 앱 쓰기·조회·자동완성·백그라운드 경로에 같은 세대 경계를 적용한다. 이후 실기기·외부망 차단 LAN·다섯 플랫폼·복구·서명 배포를 검증한다.

## 7. 반드시 유지할 경계와 알려진 미완성

- `removeWriter()`는 쓰기 권한 제거이며 미래 시크릿 읽기 차단을 대신하지 않는다. 기존 경로에는 상대에게 삭제 알림을 보내는 동작이 있으나, 변조된 상대의 자발적 삭제를 보안 전제로 삼지 않는다.
- 이미 읽힌 평문 회수와 전역 즉시 퇴출은 보장하지 않는다. 아직 전환 소식을 모르는 오프라인 기기는 구세대로 계속 작업할 수 있다. 실제 서비스 비밀번호·API 토큰 교체는 별도다.
- 관리자 복구·이중 서명/분기, 전체 백업 복원 후 롤백 기준점, 장기 키 유출 시 과거 전달문 기밀성, OS 키 저장소는 미해결이다. JavaScript 메모리 전체의 완전한 삭제도 보장하지 않는다.
- 기본 복제 엔진의 버전 정책과 새 정책은 병존한다. 테스트 통과를 앱 전체 데이터 보존·퇴출 성공으로 확대하지 않는다. 독립 보안 감사는 미실행이다.
- 테스트/소스에 시크릿·개인키를 로그로 남기지 않는다. 이 테스트의 키는 임시 값이며 자식 프로세스에는 IPC로 전달한다.

## 8. Git·의존성 작업 주의사항

현재 런타임 핵심은 Autopass `3.3.0`, Autobase `7.28.1`, Corestore `7.9.2`, Hypercore `11.30.2`다. 앱 lockfile은 코어 커밋 `a2f686326cd41b14782be78168a04dfaa31beaa6`을 사용한다. 코어 포크 main과 다르므로 포크 최신 버전으로 조용히 교체하지 않는다.

원본 `package-lock.json` SHA-256은 다음이며 이번에도 유지했다.

```text
5887f82727b0ee61b921d276485cf5fb58f42bba831f868a1ec07c3edb530a08
```

전달된 4단계 패치 SHA-256:

```text
366df64477a63463fc3db279db22e60b73df9020a9ea90f336d8c0364fbaae5d
```

추적되지 않은 `graphify-out/`은 기존 로컬 훅 생성물이다. 이번 코드와 함께 올리거나 임의로 삭제하지 않는다. `.evaluation-reports/`, `.evaluation-install/`, 실제 프로필, 의존성 폴더도 커밋 대상이 아니다. 원격 작업 폴더의 상위 경로에는 전달 확인용 `pearpass-stage4-review.patch`와 `stage4-review-transfer.b64`가 남아 있으며 제품 소스가 아니다.

커밋·push 전 프로젝트 Node PATH를 선택한다. 기존 pre-push 훅은 lint/test/build를 실행한다. 실패 시 훅을 끄거나 강제로 push하지 않는다. 기본 `main`과 원본 `pull_request_target` 워크플로를 안전성 검토 없이 변경하지 않고, 자동화 영향을 확인하기 전 PR을 만들지 않는다. 새 코드의 Apache-2.0/SPDX와 원본 LICENSE/NOTICE를 유지한다.

## 9. 다음 담당자에게 붙여 넣을 시작 문구

> `tksuns12/pearpass-app-desktop`의 `evaluation/bootstrap`에서 계속 작업한다. 먼저 `docs/evaluation/HANDOFF.md`와 `stage4-macos-verification.json`을 읽고 현재 Git 상태를 확인한다. 4단계 키 전달/전환 패치는 Mac에 적용됐지만 앱에는 미통합이다. `materializerStub` 대신 실제 Autopass 체크포인트 복사·서명/인과관계 검증·저장 완료 어댑터를 구현하는 것이 다음 목표다. 과거 revision은 epoch가 다르므로 이력/스냅샷 전환 형식을 먼저 정한다. 실제 시크릿을 사용하지 말고, 기존 의존성·main·미추적 파일·퇴출 버튼 차단을 유지한다. 프로젝트 전용 Node 22.23.2에서 새 47개와 기존 앱 726개 검사를 재실행하되, `eval:policy`의 예상 코드 2는 미충족 요구사항으로 남긴다. 모의 실험과 실기기/앱 통합 완료를 구분해서 보고한다.
