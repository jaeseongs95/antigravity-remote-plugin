# Release Notes — v0.1.0

## English

### Overview
Initial release (`v0.1.0`) of `antigravity-remote-plugin`, establishing a vendor-independent Hexagonal (Ports & Adapters) remote web bridge that decouples remote web lifecycle and security responsibilities from desktop-native companion plugins.

### Highlights
- **Vendor-Independent Core & Security (`src/core/`, `src/security/`)**: Zero vendor or DOM sink references; enforces exact origin/subdomain allowlists, scoped TrustedTypes policies, guarded Worker/AudioWorklet Blob URLs, `<base>` and HTML sink prohibition, secret redaction, and deterministic `DisposableStore`/`EventChain`/`SingleFlight` lifecycles.
- **Standardized Companion Bridges (`src/bridges/`)**:
  - `DomOverlayBridge` for pure DOM overlays (`antigravity-ko-translator`) with least-privilege isolation and remote `local-llm` fallback.
  - `SidecarUiBridge` for official `sidecar_sdk` UI and JSON API relay (`antigravity-statusbar`: `/api/telemetry`, `/api/context-limit`, `/api/compact`, `theme-change`, `workspace-change`).
  - `McpExtensionSlot` for decoupled future MCP integration (`antigravity-mcp-manager`) with unconfirmed remote `stdio` and protected config path guards.
- **Antigravity Host Adapter (`src/adapters/antigravity/`)**: Authoritative `GetAllPlugins` and `GetSidecars` Connect RPC discovery, loopback `X-Sidecar-Token` relay, and safe read-only settings normalization.
- **Verification**: 19 automated test cases (`ARP-TC-001` through `ARP-TC-019`) verified across Linux and Windows via GitHub Actions CI.

---

## 한국어

### 개요
데스크톱 네이티브 동반 플러그인으로부터 원격 웹 수명주기 및 보안 책임을 완전히 분리하는 벤더 독립적 육각형(Ports & Adapters) 원격 브리지 `antigravity-remote-plugin`의 초기 버전(`v0.1.0`)입니다.

### 주요 변경 사항
- **벤더 독립 코어 및 보안 계층 (`src/core/`, `src/security/`)**: 벤더·DOM 싱크 참조 0건을 유지하며, 정확 오리진·서브도메인 경계 검증, 스코프 TrustedTypes 정책, Worker/AudioWorklet Blob URL 화이트리스트 가드, `<base>` 및 HTML 싱크 금지, 시크릿 마스킹, 결정적 `DisposableStore`·`EventChain`·`SingleFlight` 수명주기를 제공합니다.
- **표준 동반 브리지 (`src/bridges/`)**:
  - `DomOverlayBridge`: `antigravity-ko-translator` 등 순수 DOM 오버레이를 위한 최소 권한 격리 및 원격 `local-llm` 안전 폴백 지원.
  - `SidecarUiBridge`: `antigravity-statusbar` 등 공식 `sidecar_sdk` 기반 UI·JSON API(`/api/telemetry`, `/api/context-limit`, `/api/compact`) 중계 및 `theme-change`·`workspace-change` `postMessage` 규격 지원.
  - `McpExtensionSlot`: `antigravity-mcp-manager`를 위한 비의존 선택 확장 슬롯 및 사용자 미확인 원격 `stdio`·보호 설정 경로 차단.
- **Antigravity 호스트 어댑터 (`src/adapters/antigravity/`)**: `GetAllPlugins`·`GetSidecars` 정본 Connect RPC 탐색, 루프백 `X-Sidecar-Token` 중계, 읽기 전용 설정 정제 구현.
- **검증**: 사전 작성 테스트케이스 19건(`ARP-TC-001`~`ARP-TC-019`)을 Linux 및 Windows GitHub Actions CI에서 검증.
