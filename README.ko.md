# antigravity-remote-plugin

[English README](./README.md)

**버전:** `2.0.0`

`antigravity-remote-plugin`은 `app.asar` 직접 패치와 동반 플러그인 내부 하드코딩 없이, **데스크톱 `AddonManifest.v1` 규격 애드온**과 **전 기기(iOS Safari · Android Chrome/Firefox/Edge · 데스크톱) 원격 웹 `RemotePlugin.v1` 선언적 슬롯 호스트**를 SOLID 헥사고날 아키텍처로 통합 제공하는 벤더 독립 플러그인입니다.

## 표준 규약
- **데스크톱 네이티브 애드온 (`AddonManifest.v1`)**: [addon-manifest.json](./addon-manifest.json) — `capabilities: ["renderer"]`, 비독점 `settings-pane` 슬롯(`antigravity-remote-plugin.settings`), `isolation.noTranslate: true`, `i18nSelfManaged: true`, `storageNamespace: "antigravity-remote-plugin"`을 선언하며, 모든 DOM·스타일·호스트 주도 해제를 `antigravity-native-addon-host`의 capability API(`addonHost.mountSlot`, `addonHost.injectStyle`, `addonHost.onDispose`)에만 위임합니다.
- **원격 웹 플러그인 표준 (`RemotePlugin.v1`)**: [docs/SPEC_REMOTE_PLUGIN_V1.md](./docs/SPEC_REMOTE_PLUGIN_V1.md) — 각 동반 플러그인이 표준 인터페이스를 구현하고 자신의 UI 슬롯(`status-bar`, `settings-pane`, `aux-pane`, `overlay`, `sidebar`, `title-bar`, `composer-toolbar`, `modal`, `theme`, `custom`)을 선언하면, 호스트가 외부 우회 훅 없는 Closed Shadow DOM 안에서 지정 배치대로 안전하게(`innerHTML` 0건) 렌더링합니다. 잠금 처리된 직접 등록과 크로스컨텍스트 `MessageChannel` RPC 브리지를 모두 지원합니다.

## 빠른 시작

### 1. 데스크톱 (`antigravity-native-addon-host` v1.0.1+)
`app.asar`를 직접 수정하지 않고 공용 네이티브 애드온 호스트로 검증 및 등록합니다:

```bash
node "<addon-host>/bin/addon-host.js" --validate addon-manifest.json
node "<addon-host>/bin/addon-host.js" --register "<설치된-플러그인-폴더>/addon-manifest.json"
```

### 2. 외부 · 모바일 브라우저 (`https://antigravity.google.com/*`)
- **유저스크립트 (권장)**: `dist/antigravity-remote.user.js`를 iOS Safari(`Userscripts`), Android(`Firefox`/`Edge`/`Kiwi`), 데스크톱(`Tampermonkey`/`Violentmonkey`)에 등록합니다 (`@grant none`).
- **무설치 북마클릿**: `dist/bookmarklet.txt`의 한 줄 `javascript:...` 코드를(또는 데스크톱 설정 패널의 1클릭 복사 버튼으로) 북마크에 저장해 탭 한 번으로 실행·토글합니다.

## 빌드 및 검증
Node.js `>= 20.0.0` 환경이 필요합니다.

```bash
npm ci
npm run verify
```

`scripts/build.js`(`esbuild`)가 `dist/remote_bridge.js`, `dist/addon-renderer.js`, `dist/antigravity-remote.user.js`, `dist/bookmarklet.txt`, `dist/manifest.json`을 결정적으로 생성하고, `addon-host --validate`, Playwright 데스크톱·모바일(`390x844` 터치) Closed Shadow DOM CDP E2E, 실 `<iframe>` `MessageChannel` RPC E2E를 포함한 30개 테스트 케이스(`ARP-TC-001`~`ARP-TC-030`)를 검증합니다.

## 릴리스 노트
- [v2.0.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v2.0.0.md)
- [v1.1.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.1.0.md)
- [v1.0.1 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.0.1.md)
- [v1.0.0 릴리스 노트 (영문 / 한글)](./docs/RELEASE_NOTES_v1.0.0.md)
