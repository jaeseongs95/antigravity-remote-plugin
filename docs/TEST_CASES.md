# Test Cases — antigravity-remote-plugin v2.0.0

29 automated test cases (`ARP-TC-001` through `ARP-TC-029`) covering vendor independence, security invariants, concurrency safety, real loopback HTTP integration, `AddonManifest.v1` Desktop compliance (`--validate` + scoped `addonHost` capability API), `RemotePlugin.v1` standard contract + registry + `MessageChannel` handshake, `esbuild` deterministic 4-artifact builds, and real Playwright Chromium Desktop + Mobile (`390x844` touch) E2E.

## 1. Architecture & Vendor-Independence Boundary (`test/architecture-boundary.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-001 | Static scan of `src/core/`, `src/security/`, and `src/bridges/` for vendor literals, domain leakage, and reverse adapter->bridge imports | 0 matches across all files |
| ARP-TC-002 | Static scan of entire `src/` for direct HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) | 0 matches across all files |
| ARP-TC-003 | Static scan of entire `src/` for forbidden legacy patterns (`app.asar`, `statusbar_autoinject`, `window.__ARP_*` production test hooks) and empty catch blocks | 0 matches across all files |

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
| ARP-TC-019 | `test/build.test.js`: verifies all source module SHA-256 digests in `dist/manifest.json`, zero `../src/` imports, and isolated `tmpdir` standalone ESM `import()` with zero auto-mount side effects | All checksums match; standalone ESM imports cleanly without side effects |
| ARP-TC-022 | `test/integration-loopback.test.js`: real `node:http` loopback RPC & Sidecar servers tested against both `bootstrap.js` and standalone `dist/remote_bridge.js` | End-to-end mount, `X-Sidecar-Token` API relay, theme/workspace sync, and teardown pass |
| ARP-TC-023 | `test/browser-e2e.test.js`: real Playwright Chromium enforcing `require-trusted-types-for 'script'` CSP verifying native `window.fetch` orchestrator, TrustedTypes reuse, Worker `blob:` execution, real iframe `load` + `postMessage` round-trip, and real cross-origin `DOMException` handling | Native `TrustedScriptURL` Worker returns `'worker-pong'`, sidecar iframe receives 2 messages after `load` and replies, cross-origin throws `CROSS_ORIGIN_IFRAME_DENIED` |

## 7. v2.0.0 AddonManifest.v1 Migration & RemotePlugin.v1 Standard Host

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-024 | `test/build.test.js`: verifies deterministic `esbuild` generation AND full committed `dist/` byte-for-byte & SHA-256 equality for `dist/remote_bridge.js`, `dist/addon-renderer.js`, `dist/antigravity-remote.user.js`, `dist/bookmarklet.txt`, and `dist/manifest.json`, plus `package.json`/`plugin.json`/`addon-manifest.json` version parity | Byte-for-byte identical across isolated `--out-dir` runs AND committed `dist/`; zero `window.__ARP_*` test hooks in production bundles |
| ARP-TC-025 | `test/remote-plugin.test.js`: verifies `RemotePlugin.v1` contract validation, null-prototype registry, exclusive slot collision rejection (`ERR_EXCLUSIVE_SLOT_CONFLICT`), prototype-pollution/Bidi/`javascript:` snapshot rejection, explicit 2-step `confirmation_required` (never auto-confirmed), `conflict` CAS handling (never silently retried), redacted error propagation, and closed `MessageChannel` nonce handshake rejecting untrusted origins | All invalid inputs fail closed; valid plugins register in deterministic `(loadOrder, id)` order; 2-step confirmation & CAS invariants enforced |
| ARP-TC-026 | `test/addon-manifest.test.js`: validates `addon-manifest.json` against `AddonManifest.v1` schema (and invokes real `antigravity-native-addon-host/bin/addon-host.js --validate` when present), verifies `AddonHostSurfaceAdapter` uses strictly `addonHost.mountSlot`/`injectStyle`/`removeStyle`/`unmountSlot`/`onDispose` with zero direct `document.head` injection, and executes real built `dist/addon-renderer.js` inside `(function(addonHost){ ... })` wrapper verifying KO/EN toggle, bookmarklet copy payload, and clean `dispose()` | Manifest passes `--validate` (`exit 0`); `addon-renderer.js` mounts declared `antigravity-remote-plugin.settings` slot only, injects scoped style only via `addonHost`, and cleans up 100% on `dispose()` |
| ARP-TC-027 | `test/addon-manifest.test.js`: verifies `HostSurfacePort` LSP substitutability between `createAddonHostSurfaceAdapter` (Desktop) and `createShadowSurfaceAdapter` (Remote Web Closed Shadow DOM) | Both adapters satisfy identical `HostSurfacePort` contract, slot/style ownership semantics, and idempotent `dispose()` cleanup |
| ARP-TC-028 | `test/browser-e2e.test.js`: real Playwright Chromium Desktop (`1280x800`) + Mobile (`390x844`, `hasTouch: true`, `isMobile: true`) served at real `https://antigravity.google.com/remote` origin (with CSP, zero prod test hooks), testing BOTH `dist/antigravity-remote.user.js` AND real `javascript:` bookmarklet execution via anchor navigation + untrusted origin `https://evil.example/` fail-closed check | Untrusted origin mounts nothing; trusted origin renders multiple `RemotePlugin.v1` plugins in their own declared slots (`status-bar`, `settings-pane`, `aux-pane`, `overlay`) inside Closed Shadow DOM; 2-step confirmation dialog works without auto-confirm; KO/EN toggle switches live; `>= 44px` touch targets; `0px` horizontal overflow on `390px`; `Escape` returns focus; `dispose()` removes all DOM/styles/listeners; 0 console/page errors |
| ARP-TC-029 | `test/browser-e2e.test.js`: real Playwright Chromium executing built `dist/addon-renderer.js` inside an `antigravity-native-addon-host`-compatible `(function(addonHost){...})` sandbox on a loopback page, verifying `data-addon-host-owner="antigravity-remote-plugin"`, `translate="no"`, scoped `<style>`, KO/EN toggle, copy action, and complete `addonHost.dispose()` teardown | Desktop settings pane mounts cleanly with host attributes, switches KO/EN, removes all slots & styles on `dispose()`, 0 console/page errors |
