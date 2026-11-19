# RemotePlugin.v1 Standard Contract Specification

## 1. Purpose

`RemotePlugin.v1` defines the standard, vendor-neutral interface that companion plugins MUST implement to appear in remote/mobile browser sessions hosted by `antigravity-remote-plugin`. The host NEVER hardcodes plugin-specific internals, DOM scrapers, or loopback tokens; instead, each plugin declares its own UI slot placement (aligned with `AddonManifest.v1`) and returns strictly declarative view snapshots.

## 2. Core Invariants

1. **Declarative-Only UI (`0 innerHTML`) & Impenetrable Closed Shadow DOM**: Plugins NEVER receive raw host DOM handles (`mount(el)` is forbidden). All remote UI is rendered inside a Closed Shadow DOM (`mode: 'closed'`) using safe DOM creation + `textContent` only, with zero `getSlotRoot()` or internal renderer/registry backdoors exposed on `window`.
2. **Slot Placement Parity with `AddonManifest.v1`**: Every plugin declares `uiSlot: { slot, slotId, exclusive? }` (`exclusive` MUST be a boolean when provided) using the standard slot vocabulary:
   - `title-bar`, `sidebar`, `status-bar`, `composer-toolbar`, `settings-pane`, `aux-pane`, `modal`, `overlay`, `theme`, `custom`
   - Exclusive slot collisions (`exclusive: true`) are rejected fail-closed (`ERR_EXCLUSIVE_SLOT_CONFLICT`).
3. **Zero Spoofing & Prototype Pollution Defense**:
   - `id` MUST match `/^[a-z0-9][a-z0-9._-]{1,63}$/` and MUST NOT be `__proto__`, `constructor`, or `prototype`.
   - `slotId` MUST match `/^[a-z0-9][a-z0-9._-]{1,95}$/`.
   - Snapshots reject Bidi override characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`), `javascript:` / `vbscript:` / `data:` URIs, raw HTML/SVG strings, and prototype-polluting keys.
   - Origin allowlist verification executes BEFORE reading or invoking any `window` property; repeated bookmarklet invocations identify mounted hosts via module-private `WeakMap`.
4. **Explicit 2-Step Confirmation, Serialized Actions & Optimistic Concurrency (CAS)**:
   - Action invocations are serialized with generation guards and pass `{ params?, expectedRevision?, challengeResponse? }`.
   - When a plugin returns `{ status: 'confirmation_required', challengeId, message, confirmLabel? }`, the host renders an explicit user confirmation prompt and NEVER auto-confirms. Unregistering a plugin immediately clears its pending challenges and feedback.
   - When a plugin returns `{ status: 'conflict', message, currentRevision? }`, the host displays the conflict state and NEVER silently retries.
   - Interactive action buttons are rendered ONLY when the plugin declares `'actions'` in `capabilities`.
5. **Self-Managed Localization**: Both the host and plugins support `LocalizedText` (`string | { ko: string, en: string }`) with an independent host KO/EN switcher that dynamically updates chrome, cards, inline bars, and action feedback.

## 3. Plugin Contract (`RemotePluginV1`)

```ts
type LocalizedText = string | { ko: string; en: string };

interface RemotePluginV1 {
  contractVersion: 'remote-plugin.v1';
  id: string;
  version: string;
  displayName: LocalizedText;
  uiSlot: {
    slot:
      | 'title-bar'
      | 'sidebar'
      | 'status-bar'
      | 'composer-toolbar'
      | 'settings-pane'
      | 'aux-pane'
      | 'modal'
      | 'overlay'
      | 'theme'
      | 'custom';
    slotId: string;
    exclusive?: boolean;
  };
  capabilities: Array<'badge' | 'panel' | 'actions' | 'subscribe'>;
  loadOrder?: number; // 0..1000, default 100
  getSnapshot(ctx: { locale: 'ko' | 'en' }): PluginSnapshotV1 | Promise<PluginSnapshotV1>;
  invoke?(
    actionId: string,
    invocation: {
      params?: Record<string, string | number | boolean>;
      expectedRevision?: string;
      challengeResponse?: { challengeId: string; confirmed: boolean };
    },
    ctx: { locale: 'ko' | 'en' }
  ): ActionResultV1 | Promise<ActionResultV1>;
  subscribe?(onDirty: () => void, ctx: { locale: 'ko' | 'en' }): (() => void) | void;
  dispose?(): void;
}
```

## 4. Declarative Snapshot (`PluginSnapshotV1`)

- `revision?: string` — opaque version token for CAS checks.
- `badge?: { text: LocalizedText; tone?: 'neutral' | 'ok' | 'warn' | 'error' }`
- `notice?: { text: LocalizedText; tone?: 'info' | 'warn' | 'error' }`
- `sections?: Array<DeclarativeSectionV1>`:
  - `{ kind: 'notice', text: LocalizedText, tone?: 'info' | 'warn' | 'error' }`
  - `{ kind: 'metrics', items: Array<{ label: LocalizedText, value: string, tone?: 'neutral' | 'ok' | 'warn' | 'error' }> }`
  - `{ kind: 'list', title?: LocalizedText, items: Array<{ id: string, primary: LocalizedText, secondary?: LocalizedText, badge?: LocalizedText }> }`
  - `{ kind: 'key-value', title?: LocalizedText, entries: Array<{ key: LocalizedText, value: string }> }`
  - `{ kind: 'actions', title?: LocalizedText, items: Array<{ id: string, label: LocalizedText, style?: 'primary' | 'secondary' | 'danger', disabled?: boolean }> }`

## 5. Runtime Registration Channels

### 5.1 Locked-Down Direct Registration (`window.antigravityRemoteHost`)
Exposes ONLY a non-writable, frozen public facade:
- `contractVersion`, `version`, `register(plugin)` (returns ONLY that plugin's own private unregister function), `listSlots()`, `toggleDock()`, `setLocale(locale)`, `getLocale()`.
- NEVER exposes `renderer`, `getSlotRoot`, `registry`, `diagnostics`, cross-plugin `unregister`, `issueHandshakeNonce`, or `dispose`.

### 5.2 Cross-Context `MessageChannel` RPC Bridge (`src/security/plugin-handshake.js` + `src/bridges/remote-plugin-port-bridge.js`)
1. Peer posts `{ type: 'remote-plugin-v1:handshake-request', requestId }` to the verified host origin (NEVER `postMessage('*')`).
2. Host validates `event.origin` against `allowedOrigins`, generates an origin+source-bound single-use TTL nonce (`30s`), and replies `{ type: 'remote-plugin-v1:handshake-challenge', requestId, nonce }` directly to `event.source` at `event.origin`.
3. Peer creates a `MessageChannel`, posts `{ type: 'remote-plugin-v1:handshake-init', nonce, pluginId }` transferring `[port2]` to the verified host origin.
4. Host verifies origin, source, and unexpired single-use nonce, consumes the nonce, sends `{ type: 'remote-plugin-v1:handshake-ack', accepted: true }` over `port2`, and attaches `RemotePluginPortBridge` supporting `register`, `snapshot-req`/`snapshot-res`, `invoke-req`/`invoke-res`, `dirty`, `list`, `unregister`, and `disconnect` (which unregisters the proxy and closes/releases the `MessagePort`).
