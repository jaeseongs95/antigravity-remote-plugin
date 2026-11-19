# antigravity-remote-plugin

[English README](./README.md)

**버전:** `1.0.0`

`antigravity-remote-plugin`은 데스크톱 네이티브 전용 동반 플러그인(`antigravity-statusbar`, `antigravity-ko-translator`, `antigravity-mcp-manager`)으로부터 원격 웹 제어 책임을 완전히 분리하기 위해 설계된 벤더 독립적 원격 브리지 플러그인입니다.

## 아키텍처

본 프로젝트는 엄격한 의존 방향 경계를 갖춘 육각형(Ports & Adapters) 아키텍처를 따릅니다.

- `src/core/`: 벤더·DOM 비종속 조율기(`RemoteOrchestrator`), 결정적 수명주기 관리(`DisposableStore`, `EventChain`, `SingleFlight`), 포트 계약 검증기, 구조화 진단 버스(`DiagnosticsBus`).
- `src/security/`: 벤더 비종속 보안 불변식 계층 — 정확 오리진·서브도메인 경계 검증(`origin-policy.js`), 스코프 TrustedTypes 정책 생성(`trusted-types.js`), Worker/AudioWorklet 스크립트 URL 가드(`script-guard.js`), 안전 DOM 생성기(`dom-guard.js`), 시크릿 마스킹(`redactor.js`).
- `src/bridges/`: 호스트 비종속 표준 확장 브리지:
  - `dom-overlay-bridge.js`: `antigravity-ko-translator` 등 순수 DOM 오버레이를 위한 최소 권한 수명주기(`mount`/`updateSettings`/`dispose`) 브리지.
  - `sidecar-ui-bridge.js`: `antigravity-statusbar` 등 공식 `sidecar_sdk` 기반 사이드카의 UI·JSON API(`/api/telemetry`, `/api/context-limit`, `/api/compact`) 중계 및 오리진 검증 `postMessage`(`theme-change`, `workspace-change`) 브리지.
  - `mcp-extension-slot.js`: 향후 원격 MCP 관리를 위한 독립 확장 슬롯(사용자 미확인 원격 `stdio` 실행 및 보호 설정 파일 수정 차단 포함).
- `src/adapters/antigravity/`: Antigravity 전용 Connect RPC(`GetAllPlugins`, `GetSidecars`), 루프백 사이드카 중계(`X-Sidecar-Token`), 원격 프레임 승격 및 읽기 전용 설정 정제 어댑터.
- `src/runtime/bootstrap.js`: 어댑터와 동반 브리지를 조립하는 단일 진입점.

## 보안 및 호환성 불변식

- **정본 기반 활성 판별**: 플러그인·사이드카 활성 여부는 호스트 `GetAllPlugins` 및 `GetSidecars` 응답만 정본으로 신뢰합니다. `app.asar` 바이너리 패치와 공유 주입 파일 문자열 병합 방식은 영구 금지됩니다.
- **CSP 및 TrustedTypes 준수**: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` 및 `<base>` 태그 주입을 금지하며, 예약된 TrustedTypes 정책(`default`, `dompurify`, `angular`)을 생성하지 않습니다.
- **최소 권한 격리**: 순수 DOM 오버레이에는 RPC 클라이언트, CSRF 토큰, 사이드카 토큰을 일절 전달하지 않으며, 진단 로그와 미리보기에서 `token`, `csrf`, `env`, `headers` 시크릿을 마스킹합니다.
- **Protobuf 무변조**: 호스트 protobuf 메시지 객체를 직접 변조하지 않습니다.

## 빌드 및 검증

Node.js `>= 20.0.0` 환경이 필요합니다.

```bash
npm run verify
```

위 명령은 `scripts/build.js`로 `dist/remote_bridge.js`와 `dist/manifest.json`을 생성한 뒤 [docs/TEST_CASES.md](./docs/TEST_CASES.md)에 정의된 전체 `node --test` 스위트를 실행합니다.

## 릴리스 노트

- [v1.0.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.0.0.md)
