import test from 'node:test';
import assert from 'node:assert/strict';
import { createShadowSurfaceAdapter } from '../src/adapters/remote-web/shadow-surface-adapter.js';
import {
  attachRemotePluginPortBridge,
  serveRemotePluginOverPort,
} from '../src/bridges/remote-plugin-port-bridge.js';
import { createDeclarativeSlotRenderer } from '../src/core/declarative-slot-renderer.js';
import {
  REMOTE_PLUGIN_CONTRACT_VERSION,
  validateActionResult,
  validatePluginSnapshot,
  validateRemotePlugin,
} from '../src/core/remote-plugin-contract.js';
import { RemotePluginRegistry } from '../src/core/remote-plugin-registry.js';
import {
  connectPluginHandshake,
  createPluginHandshakeHost,
  initiatePluginHandshake,
} from '../src/security/plugin-handshake.js';

function createMiniDom() {
  const makeEl = (tagName) => {
    const attrs = new Map();
    const listeners = new Map();
    return {
      tagName: tagName.toUpperCase(),
      childNodes: [],
      parentNode: null,
      hidden: false,
      textContent: '',
      get firstChild() {
        return this.childNodes[0] || null;
      },
      setAttribute(k, v) {
        attrs.set(k, String(v));
        if (k === 'hidden') this.hidden = true;
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
        if (!listeners.has(type)) listeners.set(type, new Set());
        listeners.get(type).add(fn);
      },
      removeEventListener(type, fn) {
        listeners.get(type)?.delete(fn);
      },
    };
  };
  const body = makeEl('body');
  return { body, documentElement: body, createElement: makeEl };
}

function collectNodes(root, predicate, out = []) {
  if (!root) return out;
  if (predicate(root)) out.push(root);
  for (const child of root.childNodes || []) {
    collectNodes(child, predicate, out);
  }
  return out;
}

function collectText(root) {
  let text = root?.textContent || '';
  for (const child of root?.childNodes || []) {
    text += ' ' + collectText(child);
  }
  return text;
}

function makeValidPlugin(overrides = {}) {
  return {
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    id: 'sample-status-plugin',
    version: '1.0.0',
    displayName: { ko: '샘플 상태', en: 'Sample Status' },
    uiSlot: {
      slot: 'status-bar',
      slotId: 'sample-status-plugin.bar',
      exclusive: true,
    },
    capabilities: ['badge', 'panel', 'actions', 'subscribe'],
    loadOrder: 50,
    getSnapshot() {
      return {
        revision: 'rev-1',
        badge: { text: { ko: '정상', en: 'OK' }, tone: 'ok' },
        sections: [
          {
            kind: 'metrics',
            items: [{ label: { ko: '토큰', en: 'Tokens' }, value: '12,000 / 200,000', tone: 'ok' }],
          },
          {
            kind: 'actions',
            items: [{ id: 'run-risky', label: { ko: '실행', en: 'Execute' }, style: 'danger' }],
          },
        ],
      };
    },
    invoke(actionId, invocation) {
      if (actionId === 'run-risky' && invocation.challengeResponse?.confirmed !== true) {
        return {
          status: 'confirmation_required',
          challengeId: 'chg-001',
          message: { ko: '정말 실행하시겠습니까?', en: 'Confirm execution?' },
          confirmLabel: { ko: '승인', en: 'Approve' },
        };
      }
      if (actionId === 'cas-update' && invocation.expectedRevision !== 'rev-2') {
        return {
          status: 'conflict',
          currentRevision: 'rev-2',
          message: { ko: '리비전 충돌', en: 'Revision conflict' },
        };
      }
      return { status: 'ok', revision: 'rev-2', message: { ko: '완료', en: 'Done' } };
    },
    subscribe() {
      return () => {};
    },
    ...overrides,
  };
}

test('ARP-TC-025a: RemotePlugin.v1 contract blocks imperative mount(), non-boolean exclusive, forbidden prototype keys, Bidi overrides, dangerous URIs, and raw markup', () => {
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ mount() {} })),
    (err) => err.code === 'ERR_IMPERATIVE_MOUNT_FORBIDDEN',
  );
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ id: '__proto__' })),
    (err) => err.code === 'ERR_INVALID_PLUGIN_ID',
  );
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ uiSlot: { slot: 'status-bar', slotId: 'a.b', exclusive: 'true' } })),
    (err) => err.code === 'ERR_INVALID_EXCLUSIVE_FLAG',
  );
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ uiSlot: { slot: 'document-transform', slotId: 'bad.slot' } })),
    (err) => err.code === 'ERR_UNSUPPORTED_UI_SLOT',
  );

  assert.throws(
    () => validatePluginSnapshot({ notice: { text: 'spoof \u202E reversed', tone: 'warn' } }),
    (err) => err.code === 'ERR_FORBIDDEN_BIDI_CONTROL',
  );
  assert.throws(
    () => validatePluginSnapshot({ notice: { text: 'javascript:alert(1)', tone: 'info' } }),
    (err) => err.code === 'ERR_FORBIDDEN_URI_SCHEME',
  );
  assert.throws(
    () => validatePluginSnapshot({ notice: { text: '<svg onload=alert(1)>', tone: 'info' } }),
    (err) => err.code === 'ERR_FORBIDDEN_MARKUP',
  );

  const polluter = JSON.parse('{"__proto__":{"polluted":true},"sections":[]}');
  assert.throws(
    () => validatePluginSnapshot(polluter),
    (err) => err.code === 'ERR_FORBIDDEN_KEY',
  );

  const redacted = validateActionResult({
    status: 'error',
    message: 'Failed calling https://api.example/run?token=supersecret123',
  });
  assert.ok(!redacted.message.includes('supersecret123'));
  assert.ok(redacted.message.includes('%5BREDACTED%5D') || redacted.message.includes('[REDACTED]'));
});

test('ARP-TC-025b: DeclarativeSlotRenderer serializes actions, clears pendingChallenge/feedback on unregister, translates feedback dynamically, surfaces inline bar feedback, and filters buttons by capabilities', async () => {
  const doc = createMiniDom();
  const win = { addEventListener() {}, removeEventListener() {} };
  const surface = createShadowSurfaceAdapter({ doc, ownerId: 'test-host' });
  const registry = new RemotePluginRegistry();
  const renderer = createDeclarativeSlotRenderer({ win, doc, surface, registry, initialLocale: 'ko' });

  // F2: getSlotRoot must NOT exist on renderer
  assert.equal('getSlotRoot' in renderer, false);

  // NB3: plugin without 'actions' capability must NOT render interactive action buttons
  registry.register(
    makeValidPlugin({
      id: 'readonly-panel',
      uiSlot: { slot: 'settings-pane', slotId: 'readonly-panel.pane', exclusive: false },
      capabilities: ['panel'],
      invoke: undefined,
      subscribe: undefined,
    }),
  );

  let releaseSlow = null;
  let markSlowStarted = null;
  const slowStarted = new Promise((r) => {
    markSlowStarted = r;
  });
  let callIndex = 0;
  const unregStatus = registry.register(
    makeValidPlugin({
      id: 'live-status',
      uiSlot: { slot: 'status-bar', slotId: 'live-status.bar', exclusive: true },
      async invoke(actionId) {
        callIndex += 1;
        if (actionId === 'slow-fail') {
          markSlowStarted();
          await new Promise((r) => {
            releaseSlow = r;
          });
          return { status: 'error', message: { ko: '느린 오류', en: 'Slow error' } };
        }
        if (actionId === 'fast-ok') {
          return { status: 'ok', message: { ko: '빠른 완료', en: 'Fast done' } };
        }
        return {
          status: 'confirmation_required',
          challengeId: 'chg-stale',
          message: { ko: '삭제 확인', en: 'Confirm delete' },
        };
      },
    }),
  );

  await renderer.render();

  // Verify readonly-panel rendered zero action buttons while live-status rendered action button
  const readonlyBtns = collectNodes(
    surface.hostElement,
    (n) => n.tagName === 'BUTTON' && n.getAttribute('data-plugin-id') === 'readonly-panel',
  );
  assert.equal(readonlyBtns.length, 0);

  // F5: Real in-flight slow action superseded by rapid second action must NOT overwrite feedback
  const slowPromise = renderer.executePluginAction('live-status', 'slow-fail', {});
  await slowStarted;
  const fastPromise = renderer.executePluginAction('live-status', 'fast-ok', {});
  releaseSlow();
  await Promise.all([slowPromise, fastPromise]);
  await renderer.render();

  const statusBarNode = collectNodes(
    surface.hostElement,
    (n) => n.getAttribute('data-remote-slot') === 'status-bar',
  )[0];
  assert.ok(collectText(statusBarNode).includes('빠른 완료'), 'Inline status-bar must display KO feedback');

  // NB2: Switching KO -> EN dynamically re-renders existing feedback banner in English
  await renderer.setLocale('en');
  assert.ok(collectText(statusBarNode).includes('Fast done'), 'Feedback must translate dynamically on locale switch');

  // F5: Pending 2-step confirmation must be cleared immediately when plugin unregisters
  await renderer.executePluginAction('live-status', 'run-risky', {});
  const confirmBox = collectNodes(
    surface.hostElement,
    (n) => n.getAttribute('data-rph-control') === 'confirm-box',
  )[0];
  assert.equal(confirmBox.hidden, false);

  unregStatus();
  await renderer.render();
  assert.equal(confirmBox.hidden, true, 'pendingChallenge must clear immediately on plugin unregister');
  assert.equal(callIndex, 3);

  surface.dispose();
  registry.dispose();
});

test('ARP-TC-025c: MessageChannel challenge-response enforces TTL/origin/source binding and MessagePort RPC bridge supports register/snapshot/invoke/dirty/disconnect with port release', async () => {
  const hostListeners = new Set();
  const peerListeners = new Set();
  const hostOrigin = 'https://antigravity.google.com';

  const peerWindow = {
    addEventListener(type, fn) {
      if (type === 'message') peerListeners.add(fn);
    },
    removeEventListener(type, fn) {
      if (type === 'message') peerListeners.delete(fn);
    },
    postMessage(data, targetOrigin, transfer = []) {
      for (const fn of [...peerListeners]) {
        fn({ origin: targetOrigin, source: hostWindow, data, ports: transfer });
      }
    },
  };
  const hostWindow = {
    addEventListener(type, fn) {
      if (type === 'message') hostListeners.add(fn);
    },
    removeEventListener(type, fn) {
      if (type === 'message') hostListeners.delete(fn);
    },
    postMessage(data, targetOrigin, transfer = []) {
      for (const fn of [...hostListeners]) {
        fn({ origin: targetOrigin, source: peerWindow, data, ports: transfer });
      }
    },
  };

  let fakeNow = 1000;
  const registry = new RemotePluginRegistry();
  const bridges = [];
  const host = createPluginHandshakeHost({
    win: hostWindow,
    allowedOrigins: [hostOrigin],
    nonceTtlMs: 500,
    now: () => fakeNow,
    onPortConnected({ port, close }) {
      bridges.push(attachRemotePluginPortBridge({ port, registry, onClose: close }));
    },
  });

  // NB4: Expired nonce is pruned and fails closed
  const expiringNonce = host.issueNonce();
  assert.equal(host.pendingCount(), 1);
  fakeNow += 600;
  assert.equal(host.pendingCount(), 0);
  const expiredPort = initiatePluginHandshake({
    targetWindow: hostWindow,
    targetOrigin: hostOrigin,
    allowedOrigins: [hostOrigin],
    nonce: expiringNonce,
    pluginId: 'expired-plugin',
  });
  assert.equal(host.activePortCount(), 0);
  expiredPort.close();

  // Untrusted origin is rejected cleanly
  await assert.rejects(
    () =>
      connectPluginHandshake({
        selfWindow: peerWindow,
        targetWindow: hostWindow,
        targetOrigin: 'https://evil.example',
        allowedOrigins: [hostOrigin],
        pluginId: 'evil-plugin',
      }),
    (err) => err.code === 'ORIGIN_NOT_ALLOWED',
  );

  // Full cross-context challenge-response handshake + MessagePort RPC register/snapshot/invoke/dirty/disconnect
  const clientPort = await connectPluginHandshake({
    selfWindow: peerWindow,
    targetWindow: hostWindow,
    targetOrigin: hostOrigin,
    allowedOrigins: [hostOrigin],
    pluginId: 'remote-iframe-plugin',
  });
  assert.equal(host.activePortCount(), 1);

  let dirtyEvents = 0;
  registry.onChange((evt) => {
    if (evt.type === 'dirty') dirtyEvents += 1;
  });

  const server = serveRemotePluginOverPort({
    port: clientPort,
    plugin: makeValidPlugin({
      id: 'remote-iframe-plugin',
      uiSlot: { slot: 'aux-pane', slotId: 'remote-iframe-plugin.aux', exclusive: false },
    }),
  });
  const regRes = await server.ready;
  assert.equal(regRes.ok, true);
  assert.ok(registry.get('remote-iframe-plugin'));

  const snap = await registry.readSnapshot('remote-iframe-plugin', { locale: 'en' });
  assert.equal(snap.ok, true);
  assert.equal(snap.snapshot.revision, 'rev-1');

  const chg = await registry.invokeAction('remote-iframe-plugin', 'run-risky', { expectedRevision: 'rev-1' });
  assert.equal(chg.status, 'confirmation_required');

  const okRes = await registry.invokeAction('remote-iframe-plugin', 'run-risky', {
    expectedRevision: 'rev-1',
    challengeResponse: { challengeId: chg.challengeId, confirmed: true },
  });
  assert.equal(okRes.status, 'ok');

  server.notifyDirty();
  await new Promise((r) => setTimeout(r, 25));
  assert.ok(dirtyEvents >= 1);

  // Disconnect must unregister proxy plugin AND release activePort on host
  server.disconnect();
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(registry.get('remote-iframe-plugin'), null);
  assert.equal(host.activePortCount(), 0);

  host.dispose();
  registry.dispose();
});
