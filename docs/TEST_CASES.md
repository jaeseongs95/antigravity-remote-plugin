# Test Cases — antigravity-remote-plugin v2.0.0

30 automated test cases (`ARP-TC-001` through `ARP-TC-030`) covering vendor independence, security invariants, concurrency safety, real loopback HTTP integration, `AddonManifest.v1` Desktop compliance (`--validate` + real `addonHost.dispose()` semantics), `RemotePlugin.v1` standard contract + registry + `MessageChannel` RPC bridge, `esbuild` deterministic 4-artifact builds, and real Playwright Chromium Desktop + Mobile (`390x844` touch) E2E.

## 1. Architecture & Vendor-Independence Boundary (`test/architecture-boundary.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-001 | Static scan of `src/core/`, `src/security/`, and `src/bridges/` for vendor literals, domain leakage, and reverse adapter->bridge imports | 0 matches across all files |
| ARP-TC-002 | Static scan of entire `src/` for direct HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) | 0 matches across all files |
| ARP-TC-003 | Static scan of entire `src/` for forbidden legacy patterns (`app.asar`, `statusbar_autoinject`, `window.__ARP_*` production test hooks, `getSlotRoot`, wildcard `postMessage('*')`) and empty catch blocks | 0 matches across all files |

## 2. Security Invariants (`test/security.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-004 | `isOriginAllowed`: exact origin, subdomain boundary, IPv6 loopback vs substring spoofing and scheme downgrades | Allows valid origins; rejects spoofs & downgrades |
| ARP-TC-005 | `createScopedTrustedTypesPolicy`: blocks reserved names (`default`, `dompurify`, `angular`) and reuses cached policy on re-init | Throws `SecurityPolicyError` for reserved names; zero duplicate policy `TypeError` |
| ARP-TC-006 | `createGuardedWorkerBlobUrl`: validates script URL and wraps resulting `blob:` URL as native `TrustedScriptURL` | Rejects untrusted URLs; preserves `TrustedScriptURL` instance |
| ARP-TC-007 | `dom-guard`: blocks `<base>`, HTML sinks, inline handlers, control-char URIs, and `{ toString: () => 'javascript:...' }` objects | Throws `SecurityPolicyError` for every bypass vector |
| ARP-TC-008 | `redactSecrets` & `redactUrl`: masks query params, `#token=` fragments, `password`, `x-sidecar-token`, `env`, `headers`, and `deepFreeze` | All secrets replaced with `[REDACTED]`; objects deeply frozen |

## 3. Lifecycle & Concurrency (`test/lifecycle.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-009 | `DisposableStore`: idempotent, reverse order, reports errors to deep-frozen `DiagnosticsBus` | All disposers run once; `detail` is deeply frozen |
| ARP-TC-010 | `EventChain`: arbitrary-order removal, host guard preservation, async rejection capture | No unhandledRejection; `EVENT_CHAIN_ASYNC_HANDLER_FAILED` emitted |
| ARP-TC-011 | `SingleFlight`: deduplicates concurrent calls and resets after settlement | Fetcher invoked once concurrently, twice sequentially |
| ARP-TC-012 | `RemoteOrchestrator`: mounts only active plugins and disposes cleanly | Skips disabled/uninstalled; disposes all mounted |
| ARP-TC-020 | `RemoteOrchestrator` concurrency: serialized `start()`, frame-change race safety, and restarted sidecar host/port/token remount | Single `onFrameChange` registration; stale sidecar unmounted & remounted on new port |

## 4. Stakeholder Bridge Contracts (`test/bridges.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-013 | `DomOverlayBridge`: validates `SettingsReadPort`, enforces least privilege, rolls back & rethrows on `start()` failure | Zero credentials passed; failed `start()` rolls back and rejects |
| ARP-TC-014 | `SidecarUiBridge`: defers initial `theme`/`workspace-change` until iframe `load`, normalizes port `80`, fails closed on `null` `contentWindow` | Zero messages before `load`; `SOURCE_UNAVAILABLE` on detached iframe |
| ARP-TC-015 | `McpExtensionSlot`: blocks NUL/control chars, `./`/`../`/`//`/`~/` traversal, `null` path, and omitted `transport` with `serverConfig.command` | Throws `SecurityPolicyError` on every bypass attempt |

## 5. Antigravity Host Adapter (`test/antigravity-adapter.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-016 | `AntigravityDiscoveryAdapter`: strips trailing slashes, rejects `file://`, synthetic CSRF, and malformed payloads | Accurate `dir`; fails closed on invalid protocol/CSRF/payload |
| ARP-TC-017 | `AntigravitySidecarAdapter`: supports IPv4 & IPv6 (`::1` -> `[::1]`), injects `X-Sidecar-Token`, and omits `?token=` from `buildUiUrl()` | Valid IPv6 URL; zero token leakage in UI URL |
| ARP-TC-018 | `AntigravitySettingsAdapter`: applies translator fallback and generic secret stripping based on `pluginName` | Safe frozen settings returned |
| ARP-TC-021 | `AntigravityFrameAdapter`: translates cross-origin `DOMException` into `CROSS_ORIGIN_IFRAME_DENIED` and validates `targetOrigin` match | Rejects cross-origin & mismatched `targetOrigin` cleanly |

## 6. Standalone Build, Real Loopback Integration & Real Chromium Browser E2E

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-019 | `test/build.test.js`: verifies all 30 source module SHA-256 digests in `dist/manifest.json`, zero `../src/` imports, and isolated `tmpdir` standalone ESM `import()` with zero auto-mount side effects | All 30 checksums match; standalone ESM imports cleanly without side effects |
| ARP-TC-022 | `test/integration-loopback.test.js`: real `node:http` loopback RPC & Sidecar servers tested against both `bootstrap.js` and standalone `dist/remote_bridge.js` | End-to-end mount, `X-Sidecar-Token` API relay, theme/workspace sync, and teardown pass |
| ARP-TC-023 | `test/browser-e2e.test.js`: real Playwright Chromium enforcing `require-trusted-types-for 'script'` CSP verifying native `window.fetch` orchestrator, TrustedTypes reuse, Worker `blob:` execution, real iframe `load` + `postMessage` round-trip, and real cross-origin `DOMException` handling | Native `TrustedScriptURL` Worker returns `'worker-pong'`, sidecar iframe receives 2 messages after `load` and replies, cross-origin throws `CROSS_ORIGIN_IFRAME_DENIED` |

## 7. v2.0.0 AddonManifest.v1 Migration & RemotePlugin.v1 Standard Host

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-024 | `test/build.test.js`: verifies deterministic `esbuild` generation AND full committed `dist/` byte-for-byte & SHA-256 equality for `dist/remote_bridge.js`, `dist/addon-renderer.js`, `dist/antigravity-remote.user.js`, `dist/bookmarklet.txt`, and `dist/manifest.json`, plus `package.json`/`plugin.json`/`addon-manifest.json` version parity and zero production test hooks | Byte-for-byte identical across isolated `--out-dir` runs AND committed `dist/`; 0 test hooks or `getSlotRoot` in any bundle |
| ARP-TC-025 | `test/remote-plugin.test.js`: verifies `RemotePlugin.v1` strict contract (including strict boolean `uiSlot.exclusive`, capability-filtered action buttons), null-prototype registry, exclusive slot collision rejection, prototype-pollution/Bidi/`javascript:`/HTML snapshot rejection, serialized action concurrency & unregister cleanup of `pendingChallenge`/`feedback`, dynamic KO/EN & inline bar feedback, TTL nonce expiry + `MessageChannel` challenge-response + `MessagePort` RPC bridge (`register`/`snapshot`/`invoke`/`dirty`/`disconnect` + port release) | All invalid inputs fail closed; concurrent actions serialize cleanly; unregister clears stale challenges/feedback; MessagePort RPC round-trips and releases ports on disconnect |
| ARP-TC-026 | `test/addon-manifest.test.js`: validates `addon-manifest.json` against strict `AddonManifest.v1` invariants (plus real `antigravity-native-addon-host/bin/addon-host.js --validate` when sibling repo is present), and executes real built `dist/addon-renderer.js` inside a strict `assertNotDisposed()` `(function(addonHost){ ... })` wrapper matching real `host-loader-builder.js` `dispose()` order (`disposed = true` before `onDispose` callbacks) | Manifest valid (`--validate exit 0` locally); `addon-renderer.js` mounts declared `antigravity-remote-plugin.settings` slot only, injects scoped style only via `addonHost`, and `addonHost.dispose()` completes with 0 exceptions and 0 remaining slots/styles |
| ARP-TC-027 | `test/addon-manifest.test.js`: verifies `HostSurfacePort` (including `listOwnedSlots`) LSP substitutability across `createAddonHostSurfaceAdapter` (strict `assertNotDisposed()` host mock) and `createShadowSurfaceAdapter` (Closed Shadow DOM), including both host-initiated `addonHost.dispose()` and consumer-initiated `surface.dispose()` | Both adapters satisfy identical `HostSurfacePort` contract, throw `ERR_SURFACE_DISPOSED` after dispose, return `false` safely on post-dispose `unmountSlot`/`removeStyle`, and run `onDispose` exactly once |
| ARP-TC-028 | `test/browser-e2e.test.js`: real Playwright Chromium Desktop (`1280x800`) + Mobile (`390x844`, `hasTouch: true`, `isMobile: true`) on real `https://antigravity.google.com/remote` (CSP) testing Userscript & real `javascript:` Bookmarklet, untrusted `https://evil.example/` fail-closed for BOTH Userscript AND Bookmarklet (even with spoofed `window.antigravityRemoteHost`), locked-down `window.antigravityRemoteHost` surface check, and real Closed Shadow DOM inspection & user mouse clicks via Chromium CDP (`DOM.getDocument({ pierce: true })` + `DOM.getBoxModel`, zero `getSlotRoot` backdoor) for `status-bar` & `settings-pane` plugins, 2-step confirmation, dynamic KO/EN feedback toggle, `>= 44px` touch targets, `0px` horizontal overflow, and `Escape` close | Untrusted origin executes zero spoofed hooks and mounts nothing; Closed Shadow DOM impenetrable from JS; CDP confirms `status-bar` & `settings-pane` slot placement, 2-step confirmation without auto-confirm, dynamic KO/EN toggle, `>= 44px` height, `0px` overflow, 0 browser errors |
| ARP-TC-029 | `test/browser-e2e.test.js`: real Playwright Chromium executing built `dist/addon-renderer.js` inside a strict `assertNotDisposed()` `antigravity-native-addon-host` `(function(addonHost){...})` sandbox on a loopback page, verifying `data-addon-host-owner`, `translate="no"`, scoped `<style>`, KO/EN toggle, and exception-free real `addonHost.dispose()` teardown | Desktop settings pane mounts cleanly, switches KO/EN, and `addonHost.dispose()` throws 0 errors while removing 100% of owned slots & styles |
| ARP-TC-030 | `test/browser-e2e.test.js`: real Playwright Chromium cross-context `<iframe>` (`https://antigravity.google.com/plugin-frame`) completing real `MessageChannel` challenge-response handshake (`handshake-request` -> `handshake-challenge` -> `handshake-init` -> `handshake-ack`), registering an `aux-pane` plugin over `MessagePort`, rendering in Closed Shadow DOM, executing 2-step confirmed action over RPC, and releasing slot & port cleanly on `disconnect` | Real iframe plugin registers over `MessagePort`, renders in `aux-pane` slot, completes 2-step confirmed RPC action, and removes slot on `disconnect` with 0 browser errors |
