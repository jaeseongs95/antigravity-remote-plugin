# antigravity-remote-plugin

[한국어 문서 (Korean README)](./README.ko.md)

**Version:** `2.0.0`

`antigravity-remote-plugin` is a vendor-independent, SOLID hexagonal **AddonManifest.v1 Desktop companion** and **RemotePlugin.v1 cross-device declarative slot host** (**iOS Safari, Android Chrome/Firefox/Edge, and Desktop browsers**) for Google Antigravity's official Remote Control web interface — with zero `app.asar` patching and zero hardcoded companion plugin internals.

## Standards & Specifications
- **Desktop Native Addon (`AddonManifest.v1`)**: [addon-manifest.json](./addon-manifest.json) — declares `capabilities: ["renderer"]`, non-exclusive `settings-pane` slot (`antigravity-remote-plugin.settings`), `isolation.noTranslate: true`, `i18nSelfManaged: true`, and `storageNamespace: "antigravity-remote-plugin"`. Delegates 100% of DOM/style mounting to `antigravity-native-addon-host` (`addonHost.mountSlot`, `addonHost.injectStyle`, `addonHost.onDispose`).
- **Remote Web Plugin Contract (`RemotePlugin.v1`)**: [docs/SPEC_REMOTE_PLUGIN_V1.md](./docs/SPEC_REMOTE_PLUGIN_V1.md) — companion plugins implement `RemotePlugin.v1` and declare their own UI slot (`status-bar`, `settings-pane`, `aux-pane`, `overlay`, `sidebar`, `title-bar`, `composer-toolbar`, `modal`, `theme`, `custom`); the host renders each plugin declaratively inside a Closed Shadow DOM in its declared placement.

## Quick Start

### 1. Desktop (via `antigravity-native-addon-host` v1.0.1+)
Validate and register `addon-manifest.json` using the shared native addon host (never patch `app.asar` directly):

```bash
node "<addon-host>/bin/addon-host.js" --validate addon-manifest.json
node "<addon-host>/bin/addon-host.js" --register "<installed-plugin-dir>/addon-manifest.json"
```

### 2. Remote / Mobile Browsers (`https://antigravity.google.com/*`)
- **Userscript (Recommended)**: Install `dist/antigravity-remote.user.js` in iOS Safari (`Userscripts`), Android (`Firefox`/`Edge`/`Kiwi` + `Tampermonkey`/`Violentmonkey`), or Desktop (`Tampermonkey`/`Violentmonkey`). Uses `@grant none`.
- **Zero-Install Bookmarklet**: Copy the single-line `javascript:...` snippet from `dist/bookmarklet.txt` (or 1-click copy from the Desktop Settings panel) into a browser bookmark and tap once to activate/toggle.

## Architecture (SOLID Hexagonal Ports & Adapters)
- `src/core/`: Vendor- and runtime-neutral contracts (`HostSurfacePort`, `RemotePlugin.v1` contract & validator, `RemotePluginRegistry`, `DeclarativeSlotRenderer`, `DesktopCompanionView`, `RemoteOrchestrator`, lifecycle primitives, `DiagnosticsBus`). **0 vendor literals.**
- `src/security/`: Origin/subdomain allowlists, scoped TrustedTypes policies, Worker Blob guards, safe DOM creation (`0 innerHTML`), closed `MessageChannel` nonce handshake (`plugin-handshake.js`), and secret redaction. **0 vendor literals.**
- `src/bridges/`: Vendor-independent bridges (`dom-overlay-bridge.js`, `sidecar-ui-bridge.js`, `mcp-extension-slot.js`). **0 vendor literals.**
- `src/adapters/`:
  - `addon-host/addon-host-surface-adapter.js`: `HostSurfacePort` adapter strictly over `addonHost` capability API.
  - `remote-web/shadow-surface-adapter.js`: `HostSurfacePort` adapter backed by Closed Shadow DOM.
  - `antigravity/`: Antigravity RPC, frame, sidecar, settings, and theme/workspace adapters.
- `src/runtime/`: Side-effect-free library composition roots (`bootstrap.js`, `remote-host-runtime.js`) separated from auto-executing entries (`remote-web-entry.js`, `addon-renderer-entry.js`).

## Build & Verification
Requires Node.js `>= 20.0.0`.

```bash
npm ci
npm run verify
```

`scripts/build.js` (`esbuild`) deterministically emits `dist/remote_bridge.js`, `dist/addon-renderer.js`, `dist/antigravity-remote.user.js`, `dist/bookmarklet.txt`, and `dist/manifest.json`, then runs all 29 test cases (`ARP-TC-001`–`ARP-TC-029`) including `addon-host --validate` and real Playwright Desktop + Mobile (`390x844` touch) E2E.

## Release Notes
- [v2.0.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v2.0.0.md)
- [v1.1.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.1.0.md)
- [v1.0.1 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.0.1.md)
- [v1.0.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.0.0.md)
