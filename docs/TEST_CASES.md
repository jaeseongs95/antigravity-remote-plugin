# Test Cases — antigravity-remote-plugin v2.0.0

26 automated test cases (`ARP-TC-001` through `ARP-TC-026`) covering vendor independence, security invariants, concurrency safety, real loopback HTTP integration, `esbuild` 3-artifact standalone/userscript/bookmarklet builds, remote DOM translator engine, and real Playwright Chromium Desktop + Mobile viewport E2E.

## 1. Architecture & Vendor-Independence Boundary (`test/architecture-boundary.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-001 | Static scan of `src/core/`, `src/security/`, and `src/bridges/` for vendor literals, domain leakage, and reverse adapter->bridge imports | 0 matches across all files |
| ARP-TC-002 | Static scan of entire `src/` for direct HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) | 0 matches across all files |
| ARP-TC-003 | Static scan of entire `src/` for forbidden legacy patterns and empty catch blocks (`catch {}`, `catch (e) {}`) | 0 matches across all files |

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
| ARP-TC-019 | `test/build.test.js`: verifies all 18 module SHA-256 digests in `dist/manifest.json`, zero `../src/` imports, and isolated `tmpdir` standalone `import()` | All 18 checksums match; standalone bundle imports cleanly without `src/` |
| ARP-TC-022 | `test/integration-loopback.test.js`: real `node:http` loopback RPC & Sidecar servers tested against both `bootstrap.js` and standalone `dist/remote_bridge.js` | End-to-end mount, `X-Sidecar-Token` API relay, theme/workspace sync, and teardown pass |
| ARP-TC-023 | `test/browser-e2e.test.js`: real Playwright Chromium enforcing `require-trusted-types-for 'script'` CSP verifying native `window.fetch` orchestrator, TrustedTypes reuse, Worker `blob:` execution, real iframe `load` + `postMessage` round-trip, and real cross-origin `DOMException` handling | Native `TrustedScriptURL` Worker returns `'worker-pong'`, sidecar iframe receives 2 messages after `load` and replies, cross-origin throws `CROSS_ORIGIN_IFRAME_DENIED` |

## 7. v2.0.0 Multi-Target Build (Userscript + Bookmarklet), Remote DOM Translator Engine & Cross-Device E2E

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-024 | `test/build.test.js`: verifies `esbuild` deterministic generation of `dist/remote_bridge.js`, `dist/antigravity-remote.user.js` (with `==UserScript==` metadata, `@match`, `@grant GM_xmlhttpRequest`), `dist/bookmarklet.txt` (`javascript:` prefix), and `dist/manifest.json` SHA-256 digests | Byte-for-byte deterministic across isolated `--out-dir` runs; all 3 artifact digests match `dist/manifest.json`; standalone ESM import exposes `BUILD_VERSION === '2.0.0'` |
| ARP-TC-025 | `test/remote-translator.test.js`: verifies vendor-independent `createRemoteTranslatorEngine` against a real `node:http` translation endpoint — translates visible text nodes, excludes `pre`/`code`/`textarea`/`input`/`[contenteditable]`, preserves inline code/paths/URLs, blocks unsafe non-HTTPS endpoints, translates dynamically added nodes, and restores original text on disable/`dispose()` | All prose nodes translated via real HTTP; 0 code/input nodes mutated; original text 100% restored on OFF/`dispose()` |
| ARP-TC-026 | `test/browser-e2e.test.js`: real Playwright Chromium E2E on both Desktop (`1280x800`) and Mobile (`390x844`, `hasTouch: true`, `isMobile: true`) injecting BOTH real `dist/antigravity-remote.user.js` and real `dist/bookmarklet.txt` into a mock Antigravity remote web page | Floating companion dock mounts with `>= 44px` touch target and `0px` horizontal overflow; 1-tap Korean translation translates real DOM prose while preserving `<code>`/`<pre>` and restores originals on OFF; Statusbar & MCP Manager buttons emit validated `toggle-aux-pane` messages; `Escape` closes popover and returns focus; 0 console/page errors |
