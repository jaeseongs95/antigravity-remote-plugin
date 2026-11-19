# antigravity-remote-plugin

[한국어 문서 (Korean README)](./README.ko.md)

**Version:** `1.0.0`

`antigravity-remote-plugin` is a vendor-independent remote web bridge plugin designed to separate remote web control responsibilities from desktop-native Antigravity companion plugins (`antigravity-statusbar`, `antigravity-ko-translator`, and `antigravity-mcp-manager`).

## Architecture

The project follows a Hexagonal (Ports & Adapters) architecture with strict dependency boundaries:

- `src/core/`: Vendor-independent orchestration (`RemoteOrchestrator`), deterministic lifecycle management (`DisposableStore`, `EventChain`, `SingleFlight`), port validators, and structured diagnostics (`DiagnosticsBus`).
- `src/security/`: Vendor-independent security invariants — exact origin/subdomain allowlists (`origin-policy.js`), scoped TrustedTypes policy creation (`trusted-types.js`), Worker/AudioWorklet script URL guards (`script-guard.js`), safe DOM builder (`dom-guard.js`), and secret redaction (`redactor.js`).
- `src/bridges/`: Standardized, host-agnostic extension bridges:
  - `dom-overlay-bridge.js`: Least-privilege pure DOM lifecycle (`mount`/`updateSettings`/`dispose`) for overlays such as `antigravity-ko-translator`.
  - `sidecar-ui-bridge.js`: Official `sidecar_sdk`-compatible UI and JSON API relay (`/api/telemetry`, `/api/context-limit`, `/api/compact`) and validated `postMessage` synchronization (`theme-change`, `workspace-change`) for sidecar plugins such as `antigravity-statusbar`.
  - `mcp-extension-slot.js`: Decoupled optional extension slot for future remote MCP management with hard guards against unconfirmed remote `stdio` execution and protected config writes.
- `src/adapters/antigravity/`: All Antigravity-specific Connect RPC (`GetAllPlugins`, `GetSidecars`), loopback sidecar relay (`X-Sidecar-Token`), remote frame promotion, and settings sanitization adapters.
- `src/runtime/bootstrap.js`: Composition root wiring adapters and companion bridges.

## Security & Compatibility Invariants

- **Authoritative Discovery Only**: Plugin and sidecar activation is determined exclusively from host `GetAllPlugins` and `GetSidecars` responses. Legacy merged injection files and binary `app.asar` patching are permanently prohibited.
- **CSP & TrustedTypes Compliance**: Zero HTML sink assignments (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`), zero `<base>` tag injection, and zero creation of reserved TrustedTypes policies (`default`, `dompurify`, `angular`).
- **Least Privilege**: Pure DOM overlays never receive RPC clients, CSRF tokens, or sidecar tokens. Sensitive fields (`token`, `csrf`, `env`, `headers`) are redacted from diagnostics and previews.
- **No Protobuf Mutation**: Host protobuf message objects are never mutated.

## Build & Verification

Requires Node.js `>= 20.0.0`.

```bash
npm run verify
```

This runs `scripts/build.js` to emit `dist/remote_bridge.js` and `dist/manifest.json`, then executes the full `node --test` suite documented in [docs/TEST_CASES.md](./docs/TEST_CASES.md).

## Release Notes

- [v1.0.0 Release Notes (EN / KO)](./docs/RELEASE_NOTES_v1.0.0.md)
