# antigravity-remote-plugin

[한국어 문서 (Korean README)](./README.ko.md)

**Version:** `2.0.0`

`antigravity-remote-plugin` is a vendor-independent, cross-device (**iOS Safari, Android Chrome/Firefox/Edge, and Desktop browsers**) remote web companion for Google Antigravity's official Remote Control web interface. It connects your remote browser session to the companion plugin ecosystem (`ko-thought-translator`, `antigravity-statusbar`, and `antigravity-mcp-manager`) without modifying `app.asar` or running custom tunnels.

## Quick Start (All Devices)

### Option 1 — Automatic Userscript (Recommended)
Runs automatically whenever you open `https://antigravity.google.com/*`.
- **iOS Safari**: Install the free **Userscripts** Safari extension and add `dist/antigravity-remote.user.js`.
- **Android (Firefox / Edge / Kiwi)** & **Desktop (Chrome / Edge / Firefox / Safari)**: Install **Tampermonkey** or **Violentmonkey** and import `dist/antigravity-remote.user.js`.

### Option 2 — Zero-Install Bookmarklet (iOS Safari, Android Chrome, Desktop)
1. Copy the single-line `javascript:...` snippet from `dist/bookmarklet.txt`.
2. Save it as a browser bookmark (e.g., `Antigravity Remote`).
3. Open Antigravity Remote Control in your browser and tap the bookmark once to activate the floating companion dock (tap again to toggle the menu).

## Features
- **Live Remote Korean Translation (`ko-thought-translator`)**: Real-time DOM translation of visible prose and thinking blocks while strictly preserving `<code>`, `<pre>`, terminals, inputs, inline code, URLs, and file paths. Automatically blocks `local-llm` over remote web and uses `GM_xmlhttpRequest` (userscript) or `fetch` (bookmarklet). One-tap OFF immediately restores original text.
- **Companion Sidecar Quick Actions (`antigravity-statusbar` & `antigravity-mcp-manager`)**: Connects to Antigravity's official `AUX_PANE` sidecar gateway (`antigravity-statusbar/statusbar`, `antigravity-mcp-manager/mcp_manager`) via validated `toggle-aux-pane` messages.
- **Mobile-First Minimal Floating Dock**: Unobtrusive `44x44px` touch pill respecting `safe-area-inset`, `0px` horizontal overflow on `390px` mobile screens, automatic light/dark theme sync, `Escape` focus return, and zero `innerHTML`.

## Architecture
- `src/core/`: Vendor-independent orchestration (`RemoteOrchestrator`), lifecycle (`DisposableStore`, `AsyncMutex`, `EventChain`, `SingleFlight`), port contracts, and diagnostics (`DiagnosticsBus`).
- `src/security/`: Origin/subdomain allowlists, scoped TrustedTypes policies, Worker Blob guards, safe DOM creation, and secret redaction.
- `src/bridges/`: Vendor-independent bridges (`dom-overlay-bridge.js`, `sidecar-ui-bridge.js`, `mcp-extension-slot.js`, `remote-translator-engine.js`).
- `src/adapters/antigravity/`: Antigravity RPC, frame, sidecar, settings, theme/workspace, and floating companion dock (`remote-dock-ui.js`) adapters.
- `src/runtime/`: Composition roots (`bootstrap.js`, `remote-web-entry.js`).

## Build & Verification
Requires Node.js `>= 20.0.0`.

```bash
npm ci
npm run verify
```

`scripts/build.js` (`esbuild`) emits `dist/remote_bridge.js`, `dist/antigravity-remote.user.js`, `dist/bookmarklet.txt`, and `dist/manifest.json`, then runs all 26 test cases (`ARP-TC-001`–`ARP-TC-026`) including Playwright Desktop + Mobile (`390x844` touch) E2E.

## Release Notes
- [v2.0.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v2.0.0.md)
- [v1.1.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.1.0.md)
- [v1.0.1 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.0.1.md)
- [v1.0.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.0.0.md)
