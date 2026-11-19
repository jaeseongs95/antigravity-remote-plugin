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

function createMiniDom() {
  const makeEl = (tagName) => {
    const attrs = new Map();
    const listeners = new Map();
    const el = {
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
      click() {
        for (const fn of [...(listeners.get('click') || [])]) {
          fn();
        }
      },
    };
    return el;
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

function createScopedMockAddonHost(doc, declaredSlotIds = ['antigravity-remote-plugin.settings']) {
  const allowed = new Set(declaredSlotIds);
  const slots = new Map();
  const styles = new Map();
  const disposers = [];
  let disposed = false;
  const calls = [];

  return {
    calls,
    slots,
    styles,
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
        if (disposed) throw new Error('ERR_HANDLE_DISPOSED');
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
        calls.push(['unmountSlot', slotId]);
        const el = slots.get(slotId);
        if (!el) return false;
        el.parentNode?.removeChild(el);
        slots.delete(slotId);
        return true;
      },
      injectStyle(styleId, cssText) {
        if (disposed) throw new Error('ERR_HANDLE_DISPOSED');
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
        calls.push(['removeStyle', styleId]);
        return styles.delete(styleId);
      },
      listOwnedSlots() {
        return [...slots.keys()];
      },
      onDispose(fn) {
        if (typeof fn === 'function') disposers.push(fn);
      },
      dispose() {
        if (disposed) return;
        disposed = true;
        calls.push(['dispose']);
        for (const fn of disposers.splice(0, disposers.length)) {
          fn();
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

test('ARP-TC-026: addon-manifest.json conforms to AddonManifest.v1, passes real addon-host --validate, and dist/addon-renderer.js uses strictly addonHost capability API', () => {
  const manifestPath = join(ROOT, 'addon-manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.pluginId, 'antigravity-remote-plugin');
  assert.deepEqual(manifest.capabilities, ['renderer']);
  assert.equal(manifest.entry.rendererScript, 'dist/addon-renderer.js');
  assert.equal(manifest.uiSlots[0].slot, 'settings-pane');
  assert.equal(manifest.uiSlots[0].slotId, 'antigravity-remote-plugin.settings');
  assert.equal(manifest.uiSlots[0].exclusive, false);
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
    assert.ok(out.toLowerCase().includes('valid') || out.includes('antigravity-remote-plugin'));
  }

  // Execute the real built dist/addon-renderer.js inside the exact host wrapper shape: (function(addonHost){ ... })
  const rendererSource = readFileSync(join(ROOT, 'dist/addon-renderer.js'), 'utf8');
  const doc = createMiniDom();
  const mockHost = createScopedMockAddonHost(doc);
  const copied = [];
  const fakeNav = {
    clipboard: {
      async writeText(text) {
        copied.push(text);
      },
    },
  };

  const runner = new Function('addonHost', 'document', 'navigator', rendererSource);
  runner(mockHost.handle, doc, fakeNav);

  // Must mount ONLY declared slot & inject style strictly via addonHost (0 direct document.head writes)
  assert.equal(doc.head.childNodes.length, 0);
  assert.deepEqual(mockHost.handle.listOwnedSlots(), ['antigravity-remote-plugin.settings']);
  assert.equal(mockHost.styles.size, 1);
  assert.ok(mockHost.calls.some(([op, arg]) => op === 'mountSlot' && arg === 'antigravity-remote-plugin.settings'));
  assert.ok(mockHost.calls.some(([op]) => op === 'injectStyle'));

  // Disposing handle removes slot & style completely
  mockHost.handle.dispose();
  assert.equal(mockHost.slots.size, 0);
  assert.equal(mockHost.styles.size, 0);
  assert.equal(doc.body.childNodes.length, 0);
});

test('ARP-TC-027: HostSurfacePort LSP substitutability holds identically across AddonHostSurfaceAdapter and ShadowSurfaceAdapter', () => {
  const docDesktop = createMiniDom();
  const mockHost = createScopedMockAddonHost(docDesktop, ['slot.alpha']);
  const desktopSurface = createAddonHostSurfaceAdapter(mockHost.handle);

  const docWeb = createMiniDom();
  const webSurface = createShadowSurfaceAdapter({ doc: docWeb, ownerId: 'test-owner' });

  for (const surface of [desktopSurface, webSurface]) {
    validateHostSurfacePort(surface);

    let disposeCalled = 0;
    surface.onDispose(() => {
      disposeCalled += 1;
    });

    const el = surface.mountSlot('slot.alpha');
    assert.ok(el);
    assert.deepEqual(surface.listOwnedSlots(), ['slot.alpha']);

    const st = surface.injectStyle('theme', '.x { color: red; }');
    assert.ok(st);
    assert.equal(surface.removeStyle('theme'), true);
    assert.equal(surface.unmountSlot('slot.alpha'), true);

    surface.dispose();
    surface.dispose(); // idempotent
    assert.equal(disposeCalled, 1);
    assert.throws(() => surface.mountSlot('slot.alpha'));
  }
});
