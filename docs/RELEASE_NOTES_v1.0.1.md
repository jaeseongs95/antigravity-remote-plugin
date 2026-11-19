# Release Notes — v1.0.1

## English

### Overview
Maintenance and hardening release (`v1.0.1`) of `antigravity-remote-plugin`, addressing all four non-blocking follow-up recommendations from the `v1.0.0` independent audit (`ANTIGRAVITY_REMOTE_PLUGIN-T-0002`, `VERIFIED`).

### Changes
- **Protected MCP Path Expansion (`src/runtime/bootstrap.js`)**: Added `.gemini/config/mcp_config.json` and `.gemini/config/plugins/[^/]+/config.json` to `ANTIGRAVITY_PROTECTED_MCP_PATHS`.
- **Shared Deep Secret Stripping & Safe Fallback (`src/security/redactor.js`, `src/bridges/dom-overlay-bridge.js`, `src/adapters/antigravity/settings-adapter.js`)**: Unified recursive secret/function stripping into `stripSensitiveDeep` (supporting 2D/nested arrays and preserving shared non-cyclic DAG references via `seen.delete`), and added automatic fallback to `google-translate` when `provider === 'custom-https'` with a missing or invalid `customEndpoint`.
- **Frame Guard Ordering (`src/adapters/antigravity/frame-adapter.js`)**: Prevented premature `currentFrame` mutation when `hostLoadGuard` rejects a frame promotion.
- **Alias Resolution & Reconcile Diagnostics (`src/bridges/dom-overlay-bridge.js`, `src/core/orchestrator.js`)**: Passed matched alias `plugin?.name || pluginName` to `settingsPort.readPluginSettings()` and exposed `failedIds` in `RemoteOrchestrator.reconcile()` results.

### Verification
- `npm run verify`: 23/23 PASS (0 fail, 0 skip), including standalone bundle verification, `node:http` loopback integration, and real headless Chromium CSP/iframe/`window.fetch` E2E across Linux and Windows CI.

---

## 한국어

### 개요
`v1.0.0` 독립 감사의 비차단 후속 권고 4건(`ANTIGRAVITY_REMOTE_PLUGIN-T-0002`, `VERIFIED`)을 전건 반영한 보안·안정성 보완 릴리스(`v1.0.1`)입니다.

### 주요 변경 사항
- **보호 MCP 설정 경로 확장 (`src/runtime/bootstrap.js`)**: `ANTIGRAVITY_PROTECTED_MCP_PATHS`에 `.gemini/config/mcp_config.json` 및 `.gemini/config/plugins/[^/]+/config.json` 추가.
- **공통 심층 시크릿 정제 및 안전 폴백 (`src/security/redactor.js`, `src/bridges/dom-overlay-bridge.js`, `src/adapters/antigravity/settings-adapter.js`)**: `stripSensitiveDeep` 공통 헬퍼로 중첩 객체·2차원 배열·함수 요소 제거 및 `seen.delete` 기반 비순환 공유 참조 보존을 통합하고, `provider === 'custom-https'`이면서 `customEndpoint`가 누락·무효인 경우 `google-translate`로 안전 폴백하도록 보완.
- **프레임 가드 순서 보강 (`src/adapters/antigravity/frame-adapter.js`)**: `hostLoadGuard`가 거부(`false`)할 때 `currentFrame`이 선갱신되지 않도록 차단.
- **별칭 설정 조회 및 실패 진단 노출 (`src/bridges/dom-overlay-bridge.js`, `src/core/orchestrator.js`)**: alias 매칭 시 실제 `plugin?.name || pluginName`을 `settingsPort.readPluginSettings()`로 전달하고, `RemoteOrchestrator.reconcile()` 반환값에 `failedIds`를 노출.

### 검증
- `npm run verify`: 23/23 PASS (0 fail, 0 skip), 자립 번들 격리 검증·`node:http` 실루프백 통합·실 헤드리스 Chromium CSP/iframe/`window.fetch` E2E를 Linux 및 Windows CI에서 검증.
