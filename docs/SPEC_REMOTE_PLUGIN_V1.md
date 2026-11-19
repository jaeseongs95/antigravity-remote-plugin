# RemotePlugin.v1 Standard Contract Specification

## 1. Purpose

`RemotePlugin.v1` defines the standard, vendor-neutral interface that companion plugins MUST implement to appear in remote/mobile browser sessions hosted by `antigravity-remote-plugin`. The host NEVER hardcodes plugin-specific internals, DOM scrapers, or loopback tokens; instead, each plugin declares its own UI slot placement (aligned with `AddonManifest.v1`) and returns strictly declarative view snapshots.

## 2. Core Invariants

1. **Declarative-Only UI (`0 innerHTML`)**: Plugins NEVER receive raw host DOM handles (`mount(el)` is forbidden). All UI is rendered by the host inside a Closed Shadow DOM (remote web) or scoped `addonHost.mountSlot(...)` container (desktop) using safe DOM creation + `textContent` only.
2. **Slot Placement Parity with `AddonManifest.v1`**: Every plugin declares `uiSlot: { slot, slotId, exclusive? }` using the standard slot vocabulary:
   - `title-bar`, `sidebar`, `status-bar`, `composer-toolbar`, `settings-pane`, `aux-pane`, `modal`, `overlay`, `theme`, `custom`
   - Exclusive slot collisions (`exclusive: true`) are rejected fail-closed (`ERR_EXCLUSIVE_SLOT_CONFLICT`).
3. **Zero Spoofing & Prototype Pollution Defense**:
   - `id` MUST match `/^[a-z0-9][a-z0-9._-]{1,63}$/` and MUST NOT be `__proto__`, `constructor`, or `prototype`.
   - `slotId` MUST match `/^[a-z0-9][a-z0-9._-]{1,95}$/`.
   - Snapshots reject Bidi override characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`), `javascript:` / `vbscript:` / `data:` URIs, raw HTML/SVG strings, and prototype-polluting keys.
4. **Explicit 2-Step Confirmation & Optimistic Concurrency (CAS)**:
   - Action invocations pass `{ params?, expectedRevision?, challengeResponse? }`.
   - When a plugin returns `{ status: 'confirmation_required', challengeId, message, confirmLabel? }`, the host renders an explicit user confirmation prompt and NEVER auto-confirms.
   - When a plugin returns `{ status: 'conflict', message, currentRevision? }`, the host displays the conflict state and NEVER silently retries.
5. **Self-Managed Localization**: Both the host and plugins support `LocalizedText` (`string | { ko: string, en: string }`) with an independent host KO/EN switcher.

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

## 5. Runtime Registration

1. Direct registration through the frozen host handle (`window.antigravityRemoteHost.register(plugin)`).
2. Closed `MessageChannel` nonce handshake (`src/security/plugin-handshake.js`) for isolated-world / cross-context registration without `postMessage('*')` or `window.__*` test hooks.
