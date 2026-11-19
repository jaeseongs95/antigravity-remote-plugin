import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REMOTE_PLUGIN_CONTRACT_VERSION,
  validateActionResult,
  validatePluginSnapshot,
  validateRemotePlugin,
} from '../src/core/remote-plugin-contract.js';
import { RemotePluginRegistry } from '../src/core/remote-plugin-registry.js';
import {
  createPluginHandshakeHost,
  HANDSHAKE_ACK_TYPE,
  initiatePluginHandshake,
} from '../src/security/plugin-handshake.js';

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

test('ARP-TC-025a: RemotePlugin.v1 contract blocks imperative mount(), forbidden prototype keys, Bidi overrides, dangerous URIs, and raw markup', () => {
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ mount() {} })),
    (err) => err.code === 'ERR_IMPERATIVE_MOUNT_FORBIDDEN',
  );
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ id: '__proto__' })),
    (err) => err.code === 'ERR_INVALID_PLUGIN_ID',
  );
  assert.throws(
    () => validateRemotePlugin(makeValidPlugin({ uiSlot: { slot: 'document-transform', slotId: 'bad.slot' } })),
    (err) => err.code === 'ERR_UNSUPPORTED_UI_SLOT',
  );

  // Snapshot security validation
  assert.throws(
    () =>
      validatePluginSnapshot({
        notice: { text: 'spoof \u202E reversed', tone: 'warn' },
      }),
    (err) => err.code === 'ERR_FORBIDDEN_BIDI_CONTROL',
  );
  assert.throws(
    () =>
      validatePluginSnapshot({
        notice: { text: 'javascript:alert(1)', tone: 'info' },
      }),
    (err) => err.code === 'ERR_FORBIDDEN_URI_SCHEME',
  );
  assert.throws(
    () =>
      validatePluginSnapshot({
        notice: { text: '<svg onload=alert(1)>', tone: 'info' },
      }),
    (err) => err.code === 'ERR_FORBIDDEN_MARKUP',
  );

  const polluter = JSON.parse('{"__proto__":{"polluted":true},"sections":[]}');
  assert.throws(
    () => validatePluginSnapshot(polluter),
    (err) => err.code === 'ERR_FORBIDDEN_KEY',
  );

  // Action result redacts secret URL parameters
  const redacted = validateActionResult({
    status: 'error',
    message: 'Failed calling https://api.example/run?token=supersecret123',
  });
  assert.ok(!redacted.message.includes('supersecret123'));
  assert.ok(redacted.message.includes('%5BREDACTED%5D') || redacted.message.includes('[REDACTED]'));
});

test('ARP-TC-025b: RemotePluginRegistry enforces deterministic loadOrder, exclusive slot conflict rejection, 2-step confirmation, and CAS conflict without auto-confirm or silent retry', async () => {
  const registry = new RemotePluginRegistry();
  let disposed = false;

  const unregA = registry.register(
    makeValidPlugin({
      id: 'z-status',
      loadOrder: 100,
      uiSlot: { slot: 'status-bar', slotId: 'z-status.bar', exclusive: true },
      dispose() {
        disposed = true;
      },
    }),
  );
  registry.register(
    makeValidPlugin({
      id: 'a-settings',
      loadOrder: 20,
      uiSlot: { slot: 'settings-pane', slotId: 'a-settings.pane', exclusive: false },
    }),
  );

  // Exclusive slot collision must fail closed
  assert.throws(
    () =>
      registry.register(
        makeValidPlugin({
          id: 'intruder-status',
          uiSlot: { slot: 'status-bar', slotId: 'intruder.bar', exclusive: false },
        }),
      ),
    (err) => err.code === 'ERR_EXCLUSIVE_SLOT_CONFLICT',
  );

  // Deterministic ordering by (loadOrder, id)
  assert.deepEqual(
    registry.list().map((p) => p.id),
    ['a-settings', 'z-status'],
  );

  // Snapshot read works & validates
  const snap = await registry.readSnapshot('z-status', { locale: 'ko' });
  assert.equal(snap.ok, true);
  assert.equal(snap.snapshot.revision, 'rev-1');

  // 2-step confirmation: initial invoke returns confirmation_required, never auto-confirmed
  const step1 = await registry.invokeAction('z-status', 'run-risky', { expectedRevision: 'rev-1' });
  assert.equal(step1.status, 'confirmation_required');
  assert.equal(step1.challengeId, 'chg-001');

  // Explicit user confirmation succeeds
  const step2 = await registry.invokeAction('z-status', 'run-risky', {
    expectedRevision: 'rev-1',
    challengeResponse: { challengeId: 'chg-001', confirmed: true },
  });
  assert.equal(step2.status, 'ok');

  // CAS conflict returns conflict cleanly without retrying
  const casRes = await registry.invokeAction('z-status', 'cas-update', { expectedRevision: 'rev-1' });
  assert.equal(casRes.status, 'conflict');
  assert.equal(casRes.currentRevision, 'rev-2');

  unregA();
  assert.equal(disposed, true);
  assert.equal(registry.get('z-status'), null);
  registry.dispose();
});

test('ARP-TC-025c: closed MessageChannel handshake rejects untrusted origins and nonce replays, and accepts valid single-use nonce', async () => {
  const listeners = new Set();
  const fakeWindow = {
    addEventListener(type, fn) {
      if (type === 'message') {
        listeners.add(fn);
      }
    },
    removeEventListener(type, fn) {
      if (type === 'message') {
        listeners.delete(fn);
      }
    },
    postMessage(data, targetOrigin, transfer = []) {
      for (const fn of [...listeners]) {
        fn({ origin: targetOrigin, data, ports: transfer });
      }
    },
  };

  const connected = [];
  const allowedOrigins = ['https://antigravity.google.com'];
  const host = createPluginHandshakeHost({
    win: fakeWindow,
    allowedOrigins,
    onPortConnected(info) {
      connected.push(info);
    },
  });

  const nonce = host.issueNonce();
  assert.equal(host.pendingCount(), 1);

  // Untrusted origin is rejected cleanly
  assert.throws(
    () =>
      initiatePluginHandshake({
        targetWindow: fakeWindow,
        targetOrigin: 'https://evil.example',
        allowedOrigins,
        nonce,
        pluginId: 'evil-plugin',
      }),
    (err) => err.code === 'ORIGIN_NOT_ALLOWED',
  );
  assert.equal(connected.length, 0);

  // Valid origin + valid single-use nonce succeeds and receives ACK over MessagePort
  const clientPort = initiatePluginHandshake({
    targetWindow: fakeWindow,
    targetOrigin: 'https://antigravity.google.com',
    allowedOrigins,
    nonce,
    pluginId: 'trusted-plugin',
  });
  const ack = await new Promise((resolveAck) => {
    clientPort.onmessage = (ev) => resolveAck(ev.data);
  });
  assert.equal(ack.type, HANDSHAKE_ACK_TYPE);
  assert.equal(ack.accepted, true);
  assert.equal(connected.length, 1);
  assert.equal(host.pendingCount(), 0);

  // Replaying the same nonce fails closed
  const replayPort = initiatePluginHandshake({
    targetWindow: fakeWindow,
    targetOrigin: 'https://antigravity.google.com',
    allowedOrigins,
    nonce,
    pluginId: 'replay-plugin',
  });
  assert.equal(connected.length, 1);

  clientPort.close();
  replayPort.close();
  host.dispose();
  assert.equal(host.activePortCount(), 0);
});
