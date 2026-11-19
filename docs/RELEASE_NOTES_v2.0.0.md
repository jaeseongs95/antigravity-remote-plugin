# Release Notes — v2.0.0 (EN / KO)

---

## English

### Breaking Changes
- **Migrated to `AddonManifest.v1` + `RemotePlugin.v1` Standard Host**: Removed legacy desktop sidecar (`sidecars/remote-panel/`) and hardcoded companion UI/translator hooks (`remote-translator-engine.js`, `remote-dock-ui.js`). Companion plugins now integrate strictly by implementing the standard `RemotePlugin.v1` contract and declaring their own UI slot placement.
- **Separated Side-Effect-Free ESM Library & Split Composition Roots**: `dist/remote_bridge.js` exports decoupled `desktop-addon-runtime.js` and `remote-web-runtime.js` with zero auto-mount side effects, zero production `window.__ARP_*` test hooks, and zero Closed Shadow DOM escape hatches.

### Highlights
- **Desktop `AddonManifest.v1` Companion (`addon-manifest.json` + `dist/addon-renderer.js`)**: Declares `capabilities: ["renderer"]`, non-exclusive `settings-pane` (`antigravity-remote-plugin.settings`), `noTranslate: true`, `i18nSelfManaged: true`, and `storageNamespace: "antigravity-remote-plugin"`. Delegates 100% of DOM/style/lifecycle operations to `addonHost` capability APIs with pre-subscribed `addonHost.onDispose` teardown safety (zero `ERR_HANDLE_DISPOSED` errors on host disposal, zero `app.asar` patching).
- **Standard `RemotePlugin.v1` Interface & Slot-Based Declarative Renderer (`docs/SPEC_REMOTE_PLUGIN_V1.md`)**:
  - Supports all standard UI slot placements (`status-bar`, `title-bar`, `composer-toolbar`, `settings-pane`, `aux-pane`, `sidebar`, `overlay`, `modal`, `theme`, `custom`) with strict boolean `exclusive` validation, capability-gated action buttons, and exclusive slot collision defense.
  - Declarative-only UI inside impenetrable Closed Shadow DOM (`0 innerHTML`, origin-first check + module-private `WeakMap` host tracking, minimal locked-down `window.antigravityRemoteHost`), `44px` mobile touch targets, `0px` horizontal overflow on `390px`, `AsyncMutex`/generation-guarded actions, explicit 2-step `confirmation_required` dialog (cleaned immediately on `unregister`, never auto-confirmed), `conflict` CAS handling, and live KO/EN switching (including dynamic action feedback and inline bar status).
  - Full cross-context `MessageChannel` challenge-response handshake (origin+source-bound TTL nonces) + `MessagePort` RPC bridge (`src/bridges/remote-plugin-port-bridge.js`) supporting `register`, `snapshot`, `invoke`, `dirty`, `list`, `unregister`, and deterministic port release.
- **SOLID Hexagonal Shared `HostSurfacePort`**: Desktop `AddonHostSurfaceAdapter` and Remote Web `ShadowSurfaceAdapter` implement the identical `HostSurfacePort` contract (including `listOwnedSlots`) with verified LSP substitutability.
- **Deterministic 4-Artifact `esbuild` Pipeline & 30 Automated Test Cases (`ARP-TC-001`–`ARP-TC-030`)**: Full byte-for-byte SHA-256 verification of committed `dist/` artifacts, real `addon-host --validate`, real Playwright Chromium Desktop + Mobile (`390x844` touch) Closed Shadow DOM CDP E2E (Userscript + real `javascript:` Bookmarklet + untrusted origin fail-closed), and real cross-context `<iframe>` `MessageChannel` RPC E2E.

---

## 한국어

### 주요 변경(Breaking Changes)
- **`AddonManifest.v1` + `RemotePlugin.v1` 표준 호스트로 전면 전환**: 기존 데스크톱 로컬 사이드카(`sidecars/remote-panel/`)와 하드코딩된 동반 플러그인 UI·번역기(`remote-translator-engine.js`, `remote-dock-ui.js`)를 제거했습니다. 이제 모든 동반 플러그인은 표준 `RemotePlugin.v1` 인터페이스를 구현하고 자신의 UI 슬롯 배치를 선언해 연동합니다.
- **부작용 없는 ESM 라이브러리·컴포지션 루트 분리 및 보안 하드닝**: `dist/remote_bridge.js`는 `desktop-addon-runtime.js`와 `remote-web-runtime.js`로 분리되어 import 시 자동 마운트 부작용이 없으며, 프로덕션 번들에서 `window.__ARP_*` 전역 테스트 훅과 Closed Shadow DOM 우회 훅(`getSlotRoot`)을 완전히 제거했습니다.

### 주요 기능
- **데스크톱 `AddonManifest.v1` 컴패니언 (`addon-manifest.json` + `dist/addon-renderer.js`)**: `capabilities: ["renderer"]`, 비독점 `settings-pane`(`antigravity-remote-plugin.settings`), `noTranslate: true`, `i18nSelfManaged: true`, `storageNamespace: "antigravity-remote-plugin"`을 선언하며, `addonHost.onDispose` 선구독으로 호스트 주도 해제 시 `ERR_HANDLE_DISPOSED` 예외 없이 안전하게 정리됩니다(`app.asar` 미수정).
- **표준 `RemotePlugin.v1` 인터페이스 및 슬롯별 선언적 렌더러 (`docs/SPEC_REMOTE_PLUGIN_V1.md`)**:
  - 각 플러그인이 선언한 UI 슬롯(`status-bar`, `title-bar`, `composer-toolbar`, `settings-pane`, `aux-pane`, `sidebar`, `overlay`, `modal`, `theme`, `custom`) 배치에 맞춰 렌더링하며, `exclusive` 엄격 boolean 검증·`capabilities` 기반 액션 필터링·독점 슬롯 충돌 차단을 적용했습니다.
  - 우회 불가 Closed Shadow DOM(`innerHTML` 0건, 오리진 선검증 + 모듈 비공개 `WeakMap` 호스트 추적, 최소 잠금 공개 표면 `window.antigravityRemoteHost`), 모바일 `44px` 터치 영역, `390px` 가로 오버플로 `0px`, `AsyncMutex`/세대 가드 기반 직렬화 액션, 명시적 2단계 확인(`unregister` 시 즉시 정리·자동 승인 금지), `conflict` CAS 처리, 동적 KO/EN 피드백 및 인라인 바 상태 표시를 제공합니다.
  - 오리진·소스 결합 TTL 논스 기반 크로스컨텍스트 `MessageChannel` 핸드셰이크 및 `MessagePort` RPC 브리지(`register`/`snapshot`/`invoke`/`dirty`/`list`/`unregister`/`disconnect`·포트 해제)를 완비했습니다.
- **SOLID 헥사고날 공통 `HostSurfacePort`**: 데스크톱 `AddonHostSurfaceAdapter`와 원격 웹 `ShadowSurfaceAdapter`가 동일한 `HostSurfacePort`(`listOwnedSlots` 포함) 계약을 구현해 LSP 대체 가능성을 검증했습니다.
- **결정적 4종 산출물 빌드 및 30개 자동 검증 (`ARP-TC-001`–`ARP-TC-030`)**: `dist/` 전체 바이트/SHA-256 재빌드 일치, 실제 `addon-host --validate`, Playwright 데스크톱·모바일(`390x844` 터치) Closed Shadow DOM CDP E2E(Userscript + 실제 `javascript:` 북마클릿 + 비허용 오리진 fail-closed), 실제 크로스컨텍스트 `<iframe>` `MessageChannel` RPC E2E를 포함합니다.
