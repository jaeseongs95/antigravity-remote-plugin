# Test Cases — antigravity-remote-plugin v0.1.0

Written prior to implementation to verify vendor independence, security invariants, lifecycle determinism, and all three stakeholder bridge contracts (`antigravity-ko-translator`, `antigravity-statusbar`, `antigravity-mcp-manager`).

## 1. Architecture & Vendor-Independence Boundary (`test/architecture-boundary.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-001 | Static scan of `src/core/`, `src/security/`, and `src/bridges/` for vendor literals (`antigravity`, `google`, `codeium`, `angular`, `electron`, `boq-jetski`, `app.asar`, `statusbar_autoinject`) | 0 matches across all files |
| ARP-TC-002 | Static scan of `src/core/` and `src/security/` for direct DOM/HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) | 0 matches across all files |
| ARP-TC-003 | Static scan of entire `src/` for forbidden legacy patterns (`app.asar`, `statusbar_autoinject`, `agy-statusbar-code`, `window.agyMcpManager`, synthetic `'csrf_token'`, empty `catch {}`) | 0 matches across all files |

## 2. Security Invariants (`test/security.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-004 | `isOriginAllowed`: exact origin match and explicit subdomain boundary match vs substring spoofing (`evil-example.com`, `example.com.attacker.test`, `http:` downgrade) | Allows exact/valid subdomain over `https:` (or explicit loopback `127.0.0.1`), rejects substring spoofs and scheme downgrades |
| ARP-TC-005 | `createScopedTrustedTypesPolicy`: rejects reserved policy names (`default`, `dompurify`, `angular`) and uses scoped policy name with URL guard | Throws `SecurityPolicyError` for reserved names; creates/returns scoped policy when allowed |
| ARP-TC-006 | `isTrustedScriptUrl` & `createGuardedWorkerBlobUrl`: rejects untrusted script URLs, `javascript:`, `data:`, and non-allowlisted origins before Blob/Worker creation | Fails closed with `SecurityPolicyError`; permits only allowlisted URLs |
| ARP-TC-007 | `dom-guard`: rejects `<base>` element creation and rejects unsafe HTML sink properties (`innerHTML`, `outerHTML`, `insertAdjacentHTML`) | Throws `SecurityPolicyError`; safe `createSafeElement` sets attributes/textContent cleanly |
| ARP-TC-008 | `redactSecrets`: strips/masks `token`, `csrf`, `authorization`, `x-sidecar-token`, `x-codeium-csrf-token`, `env`, `headers`, and URL query `?token=...` | All sensitive values replaced with `[REDACTED]`; non-sensitive fields preserved |

## 3. Lifecycle & Concurrency (`test/lifecycle.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-009 | `DisposableStore`: idempotent `dispose()`, reverse-order cleanup, continues cleanup if one disposer throws and reports via `DiagnosticsBus` | All disposers invoked exactly once; errors emitted to diagnostics without swallowing |
| ARP-TC-010 | `EventChain`: arbitrary-order registration and removal of multiple plugin handlers preserves remaining handlers and host guard return value | Removing middle/first/last handler never breaks others; host guard result preserved |
| ARP-TC-011 | `SingleFlight`: concurrent discovery calls share one in-flight promise and settle identically; subsequent call after settlement runs fresh | Underlying fetcher invoked once for concurrent callers, twice after completion |
| ARP-TC-012 | `RemoteOrchestrator`: mounts only plugins reported as installed & enabled by `HostDiscoveryPort`, skips disabled/uninstalled without loading external resources, and disposes cleanly on teardown | Zero external loads for disabled/missing plugins; `dispose()` invoked on every mounted bridge |

## 4. Stakeholder Bridge Contracts (`test/bridges.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-013 | `DomOverlayBridge` (`ko-translator` contract): passes ONLY `{ win, doc, settings, onStatus }` to `createOverlay`; strips RPC/tokens; falls back `local-llm` -> `google-translate` (or HTTPS `customEndpoint`); invokes `dispose()` on unmount | Factory receives zero credentials/RPC; `local-llm` sanitized; `updateSettings` and `dispose` called cleanly |
| ARP-TC-014 | `SidecarUiBridge` (`statusbar` contract): discovers active sidecar via `HostDiscoveryPort`, relays `/api/telemetry`, `/api/context-limit`, `/api/compact` via `SidecarRelayPort` with `X-Sidecar-Token`, forwards `theme-change`/`workspace-change` and validates incoming `postMessage` origin/source | API responses returned accurately; untrusted `postMessage` origins dropped with diagnostic warning; sidecar UI URL includes `conversationId` without leaking token to logs |
| ARP-TC-015 | `McpExtensionSlot` (`mcp-manager` contract): independent lifecycle with zero legacy globals; blocks unconfirmed remote `stdio` command execution/creation; blocks writes to host `config.json` or `plugins/*/mcp_config.json`; redacts `env`/`headers` | Unconfirmed `stdio` throws `SecurityPolicyError`; protected config paths rejected; secrets never exposed |

## 5. Antigravity Host Adapter (`test/antigravity-adapter.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-016 | `AntigravityDiscoveryAdapter`: queries `GetAllPlugins` & `GetSidecars` via Connect RPC with real host CSRF header; treats `disabled: true` as inactive; rejects missing/synthetic CSRF token | Accurate plugin/sidecar inventory; fails closed when CSRF token is absent |
| ARP-TC-017 | `AntigravitySidecarAdapter`: communicates with loopback `127.0.0.1` sidecar using `X-Sidecar-Token` header; rejects non-loopback sidecar hosts | Loopback requests succeed with token header; remote/non-loopback target rejected |
| ARP-TC-018 | `AntigravitySettingsAdapter`: reads sanitized read-only translator settings and applies remote `local-llm` fallback (`google-translate` or valid `https://` `customEndpoint`, rejecting `http://` custom endpoints) | Safe settings object returned; insecure `http://` custom endpoint rejected to `google-translate` |

## 6. Deterministic Build & Manifest (`test/build.test.js`)

| ID | Case | Expected Oracle |
|---|---|---|
| ARP-TC-019 | `scripts/build.js`: produces `dist/remote_bridge.js` and `dist/manifest.json` matching `package.json` and `plugin.json` version (`0.1.0`) with deterministic SHA-256 checksum | Build exits 0; artifacts exist; versions and checksums match; zero forbidden legacy markers in bundle |
