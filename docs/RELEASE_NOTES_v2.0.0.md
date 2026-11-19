# Release Notes — v2.0.0 (EN / KO)

---

## English

### Breaking Changes
- **Removed `sidecars/remote-panel/` and `src/adapters/antigravity/sidecar-host.js`**: Replaced the desktop-local 3-tab diagnostic panel with true cross-device remote web distribution artifacts built for Google Antigravity's official Remote Control web interface.

### Highlights
- **Cross-Device Userscript (`dist/antigravity-remote.user.js`)**: Auto-runs on `https://antigravity.google.com/*` across iOS Safari (`Userscripts`), Android (`Firefox`/`Edge`/`Kiwi`), and Desktop (`Tampermonkey`/`Violentmonkey`), using `GM_xmlhttpRequest` for CORS/CSP-safe remote translation.
- **Zero-Install Bookmarklet (`dist/bookmarklet.txt`)**: Single-line minified `javascript:` bundle for iOS Safari, Android Chrome, and any desktop browser with idempotent tap-to-toggle behavior.
- **Real Companion Integrations**:
  - Vendor-independent `createRemoteTranslatorEngine` (`src/bridges/remote-translator-engine.js`) for live DOM translation with code/terminal/input exclusions, inline technical token protection, and instant original-text restoration.
  - Minimal mobile-first floating dock (`src/adapters/antigravity/remote-dock-ui.js`) with 1-tap Korean translation toggle and `antigravity-statusbar` / `antigravity-mcp-manager` `AUX_PANE` quick-open actions.
- **Deterministic Multi-Target `esbuild` Pipeline**: Emits ESM library, Userscript, Bookmarklet, and full SHA-256 `dist/manifest.json`.

---

## 한국어

### 주요 변경(Breaking Changes)
- **`sidecars/remote-panel/` 및 `src/adapters/antigravity/sidecar-host.js` 제거**: PC 로컬에서만 열리던 3탭 진단 패널을 제거하고, 구글 Antigravity 공식 원격 제어 웹 환경에서 전 기기 사용자가 바로 쓸 수 있는 배포 산출물로 전면 재설계했습니다.

### 주요 기능
- **전 기기 자동 실행 유저스크립트 (`dist/antigravity-remote.user.js`)**: iOS Safari(`Userscripts`), Android(`Firefox`/`Edge`/`Kiwi`), 데스크톱(`Tampermonkey`/`Violentmonkey`)에서 `https://antigravity.google.com/*` 접속 시 자동 실행되며 `GM_xmlhttpRequest`로 원격 번역을 안정적으로 수행합니다.
- **무설치 북마클릿 (`dist/bookmarklet.txt`)**: 확장 설치 없이 iOS Safari, Android Chrome, 데스크톱 전 브라우저에서 북마크 한 번 탭으로 즉시 실행·토글됩니다.
- **3개 동반 플러그인 실연동**:
  - 벤더 독립 `createRemoteTranslatorEngine`(`src/bridges/remote-translator-engine.js`) 기반 실시간 DOM 번역(코드/터미널/입력창 제외, 인라인 코드·경로·URL 보존, 끄기 시 즉시 원문 복원).
  - 모바일 우선 미니멀 플로팅 독(`src/adapters/antigravity/remote-dock-ui.js`)에서 1탭 한글 번역 토글 및 `antigravity-statusbar` · `antigravity-mcp-manager` `AUX_PANE` 빠른 열기 지원.
- **결정적 멀티 타깃 `esbuild` 빌드**: ESM 번들, Userscript, Bookmarklet 3종과 전체 SHA-256 `dist/manifest.json`을 결정적으로 생성합니다.
