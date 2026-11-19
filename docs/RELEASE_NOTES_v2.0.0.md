# Release Notes — v2.0.0 (EN / KO)

---

## English

### Breaking Changes
- **Migrated to `AddonManifest.v1` + `RemotePlugin.v1` Standard Host**: Removed legacy desktop sidecar (`sidecars/remote-panel/`) and hardcoded companion UI/translator hooks (`remote-translator-engine.js`, `remote-dock-ui.js`). Companion plugins now integrate strictly by implementing the standard `RemotePlugin.v1` contract and declaring their own UI slot placement.
- **Separated Side-Effect-Free ESM Library from Auto-Mount Entries**: `dist/remote_bridge.js` no longer auto-mounts on import and contains zero production `window.__ARP_*` test hooks.

### Highlights
- **Desktop `AddonManifest.v1` Companion (`addon-manifest.json` + `dist/addon-renderer.js`)**: Declares `capabilities: ["renderer"]`, non-exclusive `settings-pane` (`antigravity-remote-plugin.settings`), `noTranslate: true`, `i18nSelfManaged: true`, and `storageNamespace: "antigravity-remote-plugin"`. Delegates 100% of DOM/style/lifecycle operations to `addonHost` capability APIs with zero `app.asar` patching.
- **Standard `RemotePlugin.v1` Interface & Slot-Based Declarative Renderer (`docs/SPEC_REMOTE_PLUGIN_V1.md`)**:
  - Supports all standard UI slot placements (`status-bar`, `title-bar`, `composer-toolbar`, `settings-pane`, `aux-pane`, `sidebar`, `overlay`, `modal`, `theme`, `custom`) with exclusive slot collision defense.
  - Declarative-only UI inside Closed Shadow DOM (`0 innerHTML`), `44px` mobile touch targets, `0px` horizontal overflow on `390px`, explicit 2-step `confirmation_required` dialog (never auto-confirmed), `conflict` CAS handling (never silently retried), self-managed KO/EN toggle, and closed `MessageChannel` nonce handshake (`src/security/plugin-handshake.js`).
- **SOLID Hexagonal Shared `HostSurfacePort`**: Desktop `AddonHostSurfaceAdapter` and Remote Web `ShadowSurfaceAdapter` implement the exact same `HostSurfacePort` contract with verified LSP substitutability.
- **Deterministic 4-Artifact `esbuild` Pipeline & 29 Automated Test Cases (`ARP-TC-001`–`ARP-TC-029`)**: Full byte-for-byte SHA-256 verification of committed `dist/` artifacts, real `addon-host --validate`, and real Playwright Chromium Desktop + Mobile (`390x844` touch) E2E testing both Userscript and real `javascript:` Bookmarklet execution.

---

## 한국어

### 주요 변경(Breaking Changes)
- **`AddonManifest.v1` + `RemotePlugin.v1` 표준 호스트로 전면 전환**: 기존 데스크톱 로컬 사이드카(`sidecars/remote-panel/`)와 하드코딩된 동반 플러그인 UI·번역기(`remote-translator-engine.js`, `remote-dock-ui.js`)를 제거했습니다. 이제 모든 동반 플러그인은 표준 `RemotePlugin.v1` 인터페이스를 구현하고 자신의 UI 슬롯 배치를 선언해 연동합니다.
- **부작용 없는 ESM 라이브러리 분리 및 프로덕션 테스트 훅 제거**: `dist/remote_bridge.js`는 import 시 자동 마운트 부작용이 없으며, 프로덕션 번들에서 `window.__ARP_*` 전역 테스트 훅을 완전히 제거했습니다.

### 주요 기능
- **데스크톱 `AddonManifest.v1` 컴패니언 (`addon-manifest.json` + `dist/addon-renderer.js`)**: `capabilities: ["renderer"]`, 비독점 `settings-pane`(`antigravity-remote-plugin.settings`), `noTranslate: true`, `i18nSelfManaged: true`, `storageNamespace: "antigravity-remote-plugin"`을 선언하며 `app.asar` 패치 없이 `addonHost` capability API만 사용합니다.
- **표준 `RemotePlugin.v1` 인터페이스 및 슬롯별 선언적 렌더러 (`docs/SPEC_REMOTE_PLUGIN_V1.md`)**:
  - 각 플러그인이 선언한 UI 슬롯(`status-bar`, `title-bar`, `composer-toolbar`, `settings-pane`, `aux-pane`, `sidebar`, `overlay`, `modal`, `theme`, `custom`) 배치에 맞춰 렌더링하며 독점 슬롯 충돌을 차단합니다.
  - Closed Shadow DOM 선언적 UI(`innerHTML` 0건), 모바일 `44px` 터치 영역, `390px` 가로 오버플로 `0px`, 명시적 2단계 확인(`confirmation_required`, 자동 승인 금지), `conflict` CAS 처리(무단 재시도 금지), 자체 KO/EN 토글, 닫힌 `MessageChannel` 논스 핸드셰이크를 제공합니다.
- **SOLID 헥사고날 공통 `HostSurfacePort`**: 데스크톱 `AddonHostSurfaceAdapter`와 원격 웹 `ShadowSurfaceAdapter`가 동일한 `HostSurfacePort` 계약을 구현해 LSP 대체 가능성을 검증했습니다.
- **결정적 4종 산출물 빌드 및 29개 자동 검증 (`ARP-TC-001`–`ARP-TC-029`)**: `dist/` 전체 바이트/SHA-256 재빌드 일치 검증, 실제 `addon-host --validate` 검증, 그리고 실제 `https://antigravity.google.com/remote` origin에서의 Userscript 및 실제 `javascript:` 북마클릿 Playwright 데스크톱·모바일(`390x844` 터치) E2E를 포함합니다.
