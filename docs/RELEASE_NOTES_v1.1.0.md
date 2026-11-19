# Release Notes — v1.1.0 (EN / KO)

---

## English

### Highlights
- **Official Antigravity Sidecar Panel (Desktop + Mobile Web)**: Added `sidecars/remote-panel/` (`sidecar.json`, `server.mjs`, `ui/*`) and `src/adapters/antigravity/sidecar-host.js` using Antigravity's built-in `sidecar_sdk` (`SidecarApp` + `preload.js`). Loopback calls to `LanguageServerService` and `antigravity-statusbar` run strictly on the host PC sidecar process while desktop and mobile browsers (`iOS Safari`, `Android Chrome`) access the responsive UI through Antigravity's per-sidecar remote gateway.
- **Mobile-First Responsive & Accessible UI**: Strict CSP (`default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'`), zero `innerHTML`, `>= 44px` touch targets, zero horizontal overflow on `390x844` mobile viewports, host `theme-change`/`workspace-change` sync, `AbortController` race protection, and error-retry UX.
- **Trusted Library Adoption (Dev Tooling)**:
  - Replaced the custom regex ESM bundler in `scripts/build.js` with `esbuild` (`devDependencies`), preserving byte-for-byte deterministic builds and 18-module SHA-256 verification.
  - Replaced the raw WebSocket CDP harness in `test/browser-e2e.test.js` with `playwright` (`devDependencies`) and added Desktop (`1280x800`) + Mobile (`390x844`, touch) E2E coverage.

### Verification
- `npm run verify`: 25/25 test blocks (`ARP-TC-001` through `ARP-TC-026`) passed with exit code `0`.
- Vendor-independence boundary (`src/core/`, `src/security/`, `src/bridges/`) preserved with 0 vendor literals (`ARP-TC-001`).

---

## 한국어

### 주요 변경 사항
- **Antigravity 공식 Sidecar 원격 패널 추가 (데스크톱 + 모바일 웹 지원)**: Antigravity 내장 `sidecar_sdk`(`SidecarApp` + `preload.js`) 기반 `sidecars/remote-panel/`(`sidecar.json`, `server.mjs`, `ui/*`) 및 `src/adapters/antigravity/sidecar-host.js`를 추가했습니다. `LanguageServerService` 및 `antigravity-statusbar` 루프백 호출은 PC의 Sidecar 백엔드에서만 수행하며, 데스크톱 보조 패널과 모바일 브라우저(`iOS Safari`, `Android Chrome`)는 Antigravity 플랫폼 내장 per-sidecar 원격 게이트웨이를 통해 반응형 UI에 안전하게 접속합니다.
- **모바일 우선 반응형·접근성 UI**: 엄격한 CSP(`default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'`), `innerHTML` 전면 배제, `44px` 이상 터치 영역, `390x844` 모바일 화면 가로 오버플로 `0px`, 호스트 `theme-change`/`workspace-change` 동기화, `AbortController` 경합 방지, 오류 재시도 흐름을 구현했습니다.
- **신뢰 라이브러리 적용 (개발 도구)**:
  - `scripts/build.js`의 자체 정규식 번들러를 `esbuild`(`devDependencies`)로 교체하고 결정적 빌드와 18개 모듈 SHA-256 검증을 유지했습니다.
  - `test/browser-e2e.test.js`의 원시 WebSocket CDP 클라이언트를 `playwright`(`devDependencies`)로 교체하고 데스크톱(`1280x800`) + 모바일(`390x844`, 터치) E2E 검증(`ARP-TC-026`)을 추가했습니다.

### 검증 결과
- `npm run verify`: 25개 테스트 블록(`ARP-TC-001`~`ARP-TC-026`) 전원 통과(종료 코드 `0`).
- 벤더 독립 경계(`src/core/`, `src/security/`, `src/bridges/`) 벤더 리터럴 `0`건 유지(`ARP-TC-001`).
