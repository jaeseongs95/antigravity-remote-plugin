import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAddonHostSurfaceAdapter } from '../src/adapters/addon-host/addon-host-surface-adapter.js';
import { createShadowSurfaceAdapter } from '../src/adapters/remote-web/shadow-surface-adapter.js';
import { validateHostSurfacePort } from '../src/core/ports.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ADDON_HOST_CLI = resolve(ROOT, '..', 'antigravity-native-addon-host', 'bin', 'addon-host.js');

const ALLOWED_ADDON_SLOTS = new Set([
  'title-bar',
  'sidebar',
  'status-bar',
  'composer-toolbar',
  'settings-pane',
  'aux-pane',
  'modal',
  'overlay',
  'theme',
  'document-transform',
  'custom',
]);

function createMiniDom() {
  const makeEl = (tagName) => {
    const attrs = new Map();
    const listeners = new Map();
    return {
      tagName: tagName.toUpperCase(),
      childNodes: [],
      parentNode: null,
      textContent: '',
      get firstChild() {
        return this.childNodes[0] || null;
      },
      setAttribute(k, v) {
        attrs.set(k, String(v));
      },
      getAttribute(k) {
        return attrs.has(k) ? attrs.get(k) : null;
      },
      appendChild(child) {
        child.parentNode = this;
        this.childNodes.push(child);
        return child;
      },
      removeChild(child) {
        const idx = this.childNodes.indexOf(child);
        if (idx !== -1) {
          this.childNodes.splice(idx, 1);
          child.parentNode = null;
        }
        return child;
      },
      addEventListener(type, fn) {
        if (!listeners.has(type)) {
          listeners.set(type, new Set());
        }
        listeners.get(type).add(fn);
      },
      removeEventListener(type, fn) {
        listeners.get(type)?.delete(fn);
      },
    };
  };
  const body = makeEl('body');
  const head = makeEl('head');
  return {
    head,
    body,
    documentElement: body,
    createElement: makeEl,
  };
}

/**
 * Strict mock mirroring real antigravity-native-addon-host (`host-loader-builder.js:183-334`):
 * - Every mutating method calls `assertNotDisposed()` throwing `ERR_HANDLE_DISPOSED:<pluginId>`.
 * - `dispose()` sets `disposed = true` FIRST before invoking `onDispose` callbacks, and captures
 *   any callback throw in `disposerErrors` so tests detect LSP violations immediately.
 */
function createStrictScopedMockAddonHost(doc, declaredSlotIds = ['antigravity-remote-plugin.settings']) {
  const allowed = new Set(declaredSlotIds);
  const slots = new Map();
  const styles = new Map();
  const disposers = [];
  const calls = [];
  const disposerErrors = [];
  let disposed = false;

  function assertNotDisposed() {
    if (disposed) {
      throw new Error('ERR_HANDLE_DISPOSED:antigravity-remote-plugin');
    }
  }

  return {
    calls,
    slots,
    styles,
    disposerErrors,
    handle: Object.freeze({
      pluginId: 'antigravity-remote-plugin',
      hostVersion: '1.0.1',
      hostProfileId: 'antigravity-desktop',
      storageNamespace: 'antigravity-remote-plugin',
      ipcChannelPrefix: null,
      getNoTranslateSelector() {
        return '[data-addon-host-owner], [translate="no"], [data-agy-no-translate="true"]';
      },
      mountSlot(slotId, parentEl) {
        assertNotDisposed();
        if (!allowed.has(slotId)) throw new Error(`ERR_UNDECLARED_SLOT:${slotId}`);
        calls.push(['mountSlot', slotId]);
        if (!slots.has(slotId)) {
          const el = doc.createElement('div');
          el.setAttribute('translate', 'no');
          el.setAttribute('data-addon-host-owner', 'antigravity-remote-plugin');
          el.setAttribute('data-addon-host-slot', slotId);
          (parentEl || doc.body).appendChild(el);
          slots.set(slotId, el);
        }
        return slots.get(slotId);
      },
      unmountSlot(slotId) {
        assertNotDisposed();
        calls.push(['unmountSlot', slotId]);
        const el = slots.get(slotId);
        if (!el) return false;
        el.parentNode?.removeChild(el);
        slots.delete(slotId);
        return true;
      },
      injectStyle(styleId, cssText) {
        assertNotDisposed();
        calls.push(['injectStyle', styleId]);
        let st = styles.get(styleId);
        if (!st) {
          st = doc.createElement('style');
          st.setAttribute('data-addon-host-owner', 'antigravity-remote-plugin');
          st.setAttribute('data-addon-host-style', `antigravity-remote-plugin:${styleId}`);
          styles.set(styleId, st);
        }
        st.textContent = cssText;
        return st;
      },
      removeStyle(styleId) {
        assertNotDisposed();
        calls.push(['removeStyle', styleId]);
        return styles.delete(styleId);
      },
      listOwnedSlots() {
        return [...slots.keys()];
      },
      onDispose(fn) {
        assertNotDisposed();
        if (typeof fn === 'function') disposers.push(fn);
      },
      dispose() {
        if (disposed) return;
        // Exact host-loader-builder.js ordering: set disposed = true BEFORE invoking disposers.
        disposed = true;
        calls.push(['dispose']);
        for (const fn of disposers.splice(0, disposers.length)) {
          try {
            fn();
          } catch (err) {
            disposerErrors.push(err);
          }
        }
        for (const [k, el] of slots.entries()) {
          el.parentNode?.removeChild(el);
          slots.delete(k);
        }
        styles.clear();
      },
    }),
  };
}

test('ARP-TC-026: addon-manifest.json satisfies AddonManifest.v1 invariants (+ real addon-host --validate when present) and dist/addon-renderer.js survives real host-initiated addonHost.dispose() with zero ERR_HANDLE_DISPOSED throws', () => {
  const manifestPath = join(ROOT, 'addon-manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  // Always enforce strict AddonManifest.v1 schema invariants (works in both standalone CI and local dev)
  assert.equal(manifest.schemaVersion, 1);
  assert.match(manifest.pluginId, /^[a-z0-9][a-z0-9._-]{1,63}$/);
  assert.equal(manifest.pluginId, 'antigravity-remote-plugin');
  assert.match(manifest.version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  assert.deepEqual(manifest.capabilities, ['renderer']);
  assert.equal(manifest.entry.rendererScript, 'dist/addon-renderer.js');
  assert.equal(manifest.entry.mainHookScript ?? null, null);
  assert.ok(!manifest.entry.rendererScript.includes('..'));
  assert.ok(existsSync(join(ROOT, manifest.entry.rendererScript)));
  assert.equal(manifest.uiSlots.length, 1);
  assert.ok(ALLOWED_ADDON_SLOTS.has(manifest.uiSlots[0].slot));
  assert.equal(manifest.uiSlots[0].slot, 'settings-pane');
  assert.equal(manifest.uiSlots[0].slotId, 'antigravity-remote-plugin.settings');
  assert.equal(manifest.uiSlots[0].exclusive, false);
  assert.equal(manifest.uiSlots[0].scope, 'addon-owned-slot');
  assert.equal(manifest.isolation.noTranslate, true);
  assert.equal(manifest.isolation.i18nSelfManaged, true);
  assert.equal(manifest.isolation.respectsNoTranslate, true);
  assert.equal(manifest.isolation.storageNamespace, 'antigravity-remote-plugin');

  // Run real antigravity-native-addon-host CLI --validate when sibling host repo is present
  if (existsSync(ADDON_HOST_CLI)) {
    const out = execFileSync(process.execPath, [ADDON_HOST_CLI, '--validate', manifestPath], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    const parsed = JSON.parse(out);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.pluginId, 'antigravity-remote-plugin');
  }

  // Execute real built dist/addon-renderer.js inside strict host wrapper matching host-loader-builder.js
  const rendererSource = readFileSync(join(ROOT, 'dist/addon-renderer.js'), 'utf8');
  const doc = createMiniDom();
  const mockHost = createStrictScopedMockAddonHost(doc);
  const fakeNav = { clipboard: { async writeText() {} } };

  const runner = new Function('addonHost', 'document', 'navigator', rendererSource);
  runner(mockHost.handle, doc, fakeNav);

  assert.equal(doc.head.childNodes.length, 0);
  assert.deepEqual(mockHost.handle.listOwnedSlots(), ['antigravity-remote-plugin.settings']);
  assert.equal(mockHost.styles.size, 1);

  // F4: Host-initiated addonHost.dispose() MUST NOT throw ERR_HANDLE_DISPOSED inside onDispose!
  mockHost.handle.dispose();
  assert.deepEqual(mockHost.disposerErrors, [], 'addonHost.dispose() must not trigger ERR_HANDLE_DISPOSED in consumer disposers');
  assert.equal(mockHost.slots.size, 0);
  assert.equal(mockHost.styles.size, 0);
  assert.equal(doc.body.childNodes.length, 0);
});

test('ARP-TC-027: HostSurfacePort (including listOwnedSlots) LSP substitutability holds across AddonHostSurfaceAdapter (both host & consumer dispose) and ShadowSurfaceAdapter', () => {
  // 1) Consumer-initiated dispose parity across both adapters
  const docDesktopA = createMiniDom();
  const mockHostA = createStrictScopedMockAddonHost(docDesktopA, ['slot.alpha']);
  const desktopSurfaceA = createAddonHostSurfaceAdapter(mockHostA.handle);

  const docWeb = createMiniDom();
  const webSurface = createShadowSurfaceAdapter({ doc: docWeb, ownerId: 'test-owner' });

  for (const surface of [desktopSurfaceA, webSurface]) {
    validateHostSurfacePort(surface);

    let disposeCalled = 0;
    surface.onDispose(() => {
      disposeCalled += 1;
      assert.equal(surface.removeStyle('theme'), false);
      assert.equal(surface.unmountSlot('slot.alpha'), false);
    });

    const el = surface.mountSlot('slot.alpha');
    assert.ok(el);
    assert.deepEqual(surface.listOwnedSlots(), ['slot.alpha']);

    const st = surface.injectStyle('theme', '.x { color: red; }');
    assert.ok(st);

    surface.dispose();
    surface.dispose(); // idempotent
    assert.equal(disposeCalled, 1);
    assert.deepEqual(surface.listOwnedSlots(), []);
    assert.equal(surface.removeStyle('theme'), false);
    assert.equal(surface.unmountSlot('slot.alpha'), false);
    assert.throws(() => surface.mountSlot('slot.alpha'), (err) => err.code === 'ERR_SURFACE_DISPOSED');
  }
  assert.deepEqual(mockHostA.disposerErrors, []);

  // 2) Host-initiated addonHost.dispose() parity
  const docDesktopB = createMiniDom();
  const mockHostB = createStrictScopedMockAddonHost(docDesktopB, ['slot.beta']);
  const desktopSurfaceB = createAddonHostSurfaceAdapter(mockHostB.handle);
  let consumerDisposeCount = 0;
  desktopSurfaceB.mountSlot('slot.beta');
  desktopSurfaceB.injectStyle('s1', '.b{}');
  desktopSurfaceB.onDispose(() => {
    consumerDisposeCount += 1;
    assert.equal(desktopSurfaceB.removeStyle('s1'), false);
    assert.equal(desktopSurfaceB.unmountSlot('slot.beta'), false);
  });
  mockHostB.handle.dispose();
  assert.equal(consumerDisposeCount, 1);
  assert.deepEqual(mockHostB.disposerErrors, []);
  assert.deepEqual(desktopSurfaceB.listOwnedSlots(), []);
  assert.throws(() => desktopSurfaceB.mountSlot('slot.beta'), (err) => err.code === 'ERR_SURFACE_DISPOSED');
});
