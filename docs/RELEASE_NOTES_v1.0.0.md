# Release Notes — v1.0.0

## English

### Overview
First official release (`v1.0.0`) of `antigravity-remote-plugin`, providing a vendor-independent Hexagonal (Ports & Adapters) remote web bridge that separates remote web lifecycle, CSP/TrustedTypes security, and sidecar relay responsibilities from desktop-native companion plugins.

### Highlights
- **Vendor-Independent Core & Security (`src/core/`, `src/security/`)**: Zero vendor or DOM sink references; enforces exact origin/subdomain allowlists, cached scoped TrustedTypes policies, guarded Worker/AudioWorklet Blob URLs preserving native `TrustedScriptURL`, `<base>` and HTML sink prohibition, secret redaction with deep-frozen diagnostics, and mutex/epoch-serialized `RemoteOrchestrator` lifecycles.
- **Standardized Companion Bridges (`src/bridges/`)**:
  - `DomOverlayBridge` for pure DOM overlays (`antigravity-ko-translator`) with least-privilege isolation, rollback on failed `start()`, and remote `local-llm` fallback.
  - `SidecarUiBridge` for official `sidecar_sdk` UI and JSON API relay (`antigravity-statusbar`: `/api/telemetry`, `/api/context-limit`, `/api/compact`), deferred `iframe load` `theme-change`/`workspace-change` sync, and fail-closed `origin`/`event.source` validation.
  - `McpExtensionSlot` for decoupled future MCP integration (`antigravity-mcp-manager`) with canonicalized path traversal/NUL/drive-relative guards and unconfirmed remote `stdio` protection.
- **Antigravity Host Adapter (`src/adapters/antigravity/`)**: Authoritative `GetAllPlugins` and `GetSidecars` Connect RPC discovery, loopback `X-Sidecar-Token` relay (IPv4 & IPv6) with `globalThis`-bound default `fetch`, real iframe promotion, `ThemeWorkspaceSyncPort`, and read-only settings normalization.
- **Verification**: 23 automated test cases (`ARP-TC-001` through `ARP-TC-023`), including standalone self-contained `dist/remote_bridge.js` verification, real `node:http` loopback integration, and real headless Chromium default `window.fetch`/CSP/iframe/TrustedTypes E2E verified across Linux and Windows CI.

---

## 한국어

### 개요
데스크톱 네이티브 동반 플러그인으로부터 원격 웹 수명주기, CSP/TrustedTypes 보안, 사이드카 중계 책임을 완전히 분리하는 벤더 독립적 육각형(Ports & Adapters) 원격 브리지 `antigravity-remote-plugin`의 첫 정식 릴리스(`v1.0.0`)입니다.

### 주요 변경 사항
- **벤더 독립 코어 및 보안 계층 (`src/core/`, `src/security/`)**: 벤더·DOM 싱크 참조 0건을 유지하며, 정확 오리진·서브도메인 경계 검증, 재초기화 안전 스코프 TrustedTypes 정책, 네이티브 `TrustedScriptURL`을 보존하는 Worker/AudioWorklet Blob URL 가드, `<base>` 및 HTML 싱크·비문자열 URI 우회 차단, 시크릿 마스킹·deepFreeze 진단, mutex/epoch 직렬화 `RemoteOrchestrator` 수명주기를 제공합니다.
- **표준 동반 브리지 (`src/bridges/`)**:
  - `DomOverlayBridge`: `antigravity-ko-translator` 등 순수 DOM 오버레이를 위한 최소 권한 격리, `start()` 실패 롤백 및 원격 `local-llm` 안전 폴백 지원.
  - `SidecarUiBridge`: `antigravity-statusbar` 등 공식 `sidecar_sdk` 기반 UI·JSON API(`/api/telemetry`, `/api/context-limit`, `/api/compact`) 중계, iframe `load` 이후 `theme-change`·`workspace-change` 동기화 및 fail-closed 오리진·`event.source` 검증.
  - `McpExtensionSlot`: `antigravity-mcp-manager`를 위한 비의존 선택 확장 슬롯 및 경로 정규화·NUL/드라이브 상대경로 차단·사용자 미확인 원격 `stdio` 차단.
- **Antigravity 호스트 어댑터 (`src/adapters/antigravity/`)**: `GetAllPlugins`·`GetSidecars` 정본 Connect RPC 탐색, `globalThis` 바인딩 기본 `fetch` 기반 루프백 `X-Sidecar-Token` 중계(IPv4·IPv6), 실 iframe 승격, `ThemeWorkspaceSyncPort` 및 읽기 전용 설정 정제 구현.
- **검증**: 사전 작성 테스트케이스 23건(`ARP-TC-001`~`ARP-TC-023`, 자립 번들 격리 검증·`node:http` 실루프백 통합·실 헤드리스 Chromium 기본 `window.fetch`/CSP/iframe/TrustedTypes E2E 포함)을 Linux 및 Windows GitHub Actions CI에서 검증.
