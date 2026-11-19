# Test Cases — antigravity-remote-plugin v0.1.0

Written prior to implementation and expanded with audit regression cases (`ARP-TC-020` through `ARP-TC-030`) to verify vendor independence, security invariants, concurrency safety, real loopback HTTP integration, and standalone bundle execution.

## 1. Architecture & Vendor-Independence Boundary (`test/architecture-boundary.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-001 | Static scan of `src/core/`, `src/security/`, and `src/bridges/` for vendor literals and domain leakage (`translateThinking`, `local-llm`, reverse adapter->bridge imports) | 0 matches across all files |
| ARP-TC-002 | Static scan of entire `src/` for direct HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) | 0 matches across all files |
| ARP-TC-003 | Static scan of entire `src/` for forbidden legacy patterns and empty catch blocks (`catch {}`, `catch (e) {}`) | 0 matches across all files |

## 2. Security Invariants (`test/security.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-004 | `isOriginAllowed`: exact origin, subdomain boundary, IPv6 loopback vs substring spoofing and scheme downgrades | Allows valid origins; rejects spoofs & downgrades |
| ARP-TC-005 | `createScopedTrustedTypesPolicy`: blocks reserved names (`default`, `dompurify`, `angular`) and enforces URL allowlist | Throws `SecurityPolicyError` for reserved names |
| ARP-TC-006 | `createGuardedWorkerBlobUrl`: fails closed on untrusted URLs and preserves native `TrustedScriptURL` object identity (no `String()` coercion) | Rejects untrusted URLs; passes `TrustedScriptURL` instance intact |
| ARP-TC-007 | `dom-guard`: blocks `<base>`, HTML sinks, inline handlers, `java\tscript:`, `vbscript:`, and `data:text/html` URIs | Throws `SecurityPolicyError` for every bypass vector |
| ARP-TC-008 | `redactSecrets` & `redactUrl`: masks query params, `#token=` fragments, `password`, `x-sidecar-token`, `env`, `headers`, and `deepFreeze` | All secrets replaced with `[REDACTED]`; objects deeply frozen |

## 3. Lifecycle & Concurrency (`test/lifecycle.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-009 | `DisposableStore`: idempotent, reverse order, reports errors to deep-frozen `DiagnosticsBus` | All disposers run once; `detail` is deeply frozen |
| ARP-TC-010 | `EventChain`: arbitrary-order removal, host guard preservation, async rejection capture | No unhandledRejection; `EVENT_CHAIN_ASYNC_HANDLER_FAILED` emitted |
| ARP-TC-011 | `SingleFlight`: deduplicates concurrent calls and resets after settlement | Fetcher invoked once concurrently, twice sequentially |
| ARP-TC-012 | `RemoteOrchestrator`: mounts only active plugins and disposes cleanly | Skips disabled/uninstalled; disposes all mounted |
| ARP-TC-020 | `RemoteOrchestrator` concurrency: parallel `reconcile()` prevents duplicate mount; mid-mount `dispose()` prevents zombie mount; restart after `dispose()` works | Mount count === 1; zombie count === 0; restart mounts cleanly |

## 4. Stakeholder Bridge Contracts (`test/bridges.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-013 | `DomOverlayBridge`: least privilege, parallel `mount()` serialization, `start()` failure rollback & rethrow, `dispose()` | Zero credentials passed; failed `start()` rolls back and rejects |
| ARP-TC-014 | `SidecarUiBridge`: relays allowed APIs, wires `ThemeWorkspaceSyncPort` + `message` listener, enforces exact `activeSidecar` port origin & `expectedSource` | Rejects different localhost port (`9999`) & wrong `event.source`; pushes theme/workspace live |
| ARP-TC-015 | `McpExtensionSlot`: canonicalizes `./`, `../`, `//`, `~/` paths; rejects `null` path, `~/.gemini/antigravity/mcp_config.json`, and omitted `transport` with `serverConfig.command` | Throws `SecurityPolicyError` on every bypass attempt |

## 5. Antigravity Host Adapter (`test/antigravity-adapter.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-016 | `AntigravityDiscoveryAdapter`: queries `GetAllPlugins`/`GetSidecars`, rejects `file://localhost`, rejects synthetic CSRF, throws on malformed payloads without `plugins`/`sidecars` arrays | Accurate inventory; fails closed on invalid protocol/CSRF/payload |
| ARP-TC-017 | `AntigravitySidecarAdapter`: supports IPv4 & IPv6 (`::1` -> `[::1]`), injects `X-Sidecar-Token`, and omits `?token=` from `buildUiUrl()` | Valid IPv6 URL; zero token leakage in UI URL |
| ARP-TC-018 | `AntigravitySettingsAdapter`: sanitizes translator settings & applies remote `local-llm` fallback (`google-translate` or HTTPS `customEndpoint`) | Safe frozen settings returned |
| ARP-TC-021 | `AntigravityFrameAdapter`: fail-closed on missing `.origin`; real `promoteRemoteIframe()` promotes accessible iframe & blocks cross-origin/untrusted origins | Throws `SecurityPolicyError` on missing/untrusted origin; dispatches promoted frame |

## 6. Deterministic Standalone Build & Real Loopback Integration (`test/build.test.js`, `test/integration-loopback.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-019 | `scripts/build.js`: verifies all 18 module SHA-256 digests in `dist/manifest.json`, zero `../src/` imports in `dist/remote_bridge.js`, and isolated `tmpdir` standalone `import()` | All module checksums match; standalone bundle imports cleanly without `src/` |
| ARP-TC-022 | Real `node:http` loopback integration: `bootstrapAntigravityRemoteBridge` (and standalone `dist/remote_bridge.js`) against real HTTP RPC & Sidecar servers with live iframe promotion, `ThemeWorkspaceSyncPort`, and `X-Sidecar-Token` verification | End-to-end mount, API relay, theme/workspace sync, and clean teardown pass |
