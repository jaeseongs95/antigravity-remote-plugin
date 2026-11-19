# antigravity-remote-plugin

[English README](./README.md)

**버전:** `2.0.0`

`antigravity-remote-plugin`은 구글 Antigravity 공식 원격 제어(Remote Control) 웹 환경에서 **전 기기(iOS Safari · Android Chrome/Firefox/Edge · 데스크톱 전 브라우저)** 사용자가 동반 플러그인(`ko-thought-translator`, `antigravity-statusbar`, `antigravity-mcp-manager`)을 실제로 연동해 사용할 수 있도록 만든 벤더 독립적 원격 컴패니언입니다.

## 빠른 시작 (전 기기 지원)

### 방법 1 — 자동 실행 유저스크립트 (권장)
`https://antigravity.google.com/*`에 접속하면 매번 누르지 않아도 자동으로 실행됩니다.
- **iOS Safari**: 무료 **Userscripts** Safari 확장을 설치하고 `dist/antigravity-remote.user.js`를 추가합니다.
- **Android (Firefox / Edge / Kiwi)** 및 **데스크톱 (Chrome / Edge / Firefox / Safari)**: **Tampermonkey** 또는 **Violentmonkey**에 `dist/antigravity-remote.user.js`를 등록합니다.

### 방법 2 — 무설치 북마클릿 (iOS Safari · Android Chrome · 데스크톱 전 브라우저)
1. `dist/bookmarklet.txt`의 한 줄 `javascript:...` 코드를 복사합니다.
2. 브라우저 북마크로 저장합니다(예: `Antigravity Remote`).
3. 원격 제어 페이지에서 북마크를 한 번 탭하면 우하단 플로팅 독이 실행됩니다(다시 탭하면 메뉴 열기/닫기).

## 주요 기능
- **원격 실시간 한글 번역 (`ko-thought-translator`)**: 사고 과정과 정적 UI 텍스트를 실시간 번역하면서 `<code>`, `<pre>`, 터미널, 입력창, 인라인 코드·경로·URL은 원형 그대로 보존합니다. 원격 웹에서는 `local-llm`을 자동 차단하고 `GM_xmlhttpRequest`(유저스크립트) 또는 `fetch`(북마클릿)로 번역하며, 끄기 시 즉시 원문으로 복원합니다.
- **동반 사이드카 빠른 연동 (`antigravity-statusbar` · `antigravity-mcp-manager`)**: Antigravity 공식 `AUX_PANE` 게이트웨이(`antigravity-statusbar/statusbar`, `antigravity-mcp-manager/mcp_manager`)로 `toggle-aux-pane` 메시지를 전송해 보조 패널을 바로 열 수 있습니다.
- **모바일 우선 미니멀 플로팅 독**: `44x44px` 터치 영역, `safe-area-inset` 대응, `390px` 모바일 가로 오버플로 `0px`, 다크/라이트 테마 자동 동기화, `Escape` 닫기·초점 복귀, `innerHTML` 0건.

## 빌드 및 검증
Node.js `>= 20.0.0` 환경이 필요합니다.

```bash
npm ci
npm run verify
```

`scripts/build.js`(`esbuild`)가 `dist/remote_bridge.js`, `dist/antigravity-remote.user.js`, `dist/bookmarklet.txt`, `dist/manifest.json`을 생성하고 Playwright 데스크톱 + 모바일(`390x844` 터치) E2E를 포함한 26개 테스트 케이스(`ARP-TC-001`~`ARP-TC-026`)를 검증합니다.

## 릴리스 노트
- [v2.0.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v2.0.0.md)
- [v1.1.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.1.0.md)
- [v1.0.1 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.0.1.md)
- [v1.0.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.0.0.md)
