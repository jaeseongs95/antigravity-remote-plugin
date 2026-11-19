import test from 'node:test';
import assert from 'node:assert/strict';
import { createAntigravityDiscoveryAdapter } from '../src/adapters/antigravity/discovery-adapter.js';
import { createAntigravityFrameAdapter } from '../src/adapters/antigravity/frame-adapter.js';
import { createAntigravitySidecarAdapter } from '../src/adapters/antigravity/sidecar-adapter.js';
import { createAntigravitySettingsAdapter } from '../src/adapters/antigravity/settings-adapter.js';
import { SecurityPolicyError } from '../src/security/origin-policy.js';

test('ARP-TC-016: AntigravityDiscoveryAdapter rejects file://, synthetic CSRF, and malformed payloads without silent fallback', async () => {
  assert.throws(
    () => createAntigravityDiscoveryAdapter({ lsAddress: '127.0.0.1:5387', csrfToken: 'csrf_token' }),
    (err) => err instanceof SecurityPolicyError && err.code === 'SYNTHETIC_CSRF_TOKEN',
  );
  assert.throws(
    () => createAntigravityDiscoveryAdapter({ lsAddress: 'file://localhost/etc/passwd', csrfToken: 'real-csrf-123456' }),
    (err) => err instanceof SecurityPolicyError && err.code === 'INVALID_LS_PROTOCOL',
  );
  assert.throws(
    () => createAntigravityDiscoveryAdapter({ lsAddress: 'https://remote.evil.test:5387', csrfToken: 'real-csrf-123456' }),
    (err) => err instanceof SecurityPolicyError && err.code === 'NON_LOOPBACK_LS_ADDRESS',
  );

  // Malformed payload missing `plugins` array must throw (no silent `[]` fallback).
  const malformedAdapter = createAntigravityDiscoveryAdapter({
    lsAddress: '127.0.0.1:5387',
    csrfToken: 'real-host-csrf-token-9999',
    async fetchImpl() {
      return { ok: true, async json() { return { unexpected: true }; } };
    },
  });
  await assert.rejects(() => malformedAdapter.listPlugins(), /missing "plugins" array/);
  await assert.rejects(() => malformedAdapter.listSidecars(), /missing "sidecars" array/);
});

test('ARP-TC-017: AntigravitySidecarAdapter supports IPv6 ::1, injects X-Sidecar-Token, and omits ?token= from buildUiUrl', async () => {
  const seen = [];
  const adapter = createAntigravitySidecarAdapter({
    async fetchImpl(url, opts) {
      seen.push({ url, opts });
      return { ok: true, async json() { return { usedTokens: 12000 }; } };
    },
  });

  await assert.rejects(
    () => adapter.requestJson({
      sidecar: { host: '10.0.0.5', port: 45123, token: 't1' },
      path: '/api/telemetry',
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'NON_LOOPBACK_SIDECAR',
  );

  // IPv6 loopback ::1 must be bracketed as [::1].
  const uiUrl = adapter.buildUiUrl({
    sidecar: { host: '::1', port: 45123, token: 'secret-should-not-be-in-url' },
    conversationId: 'conv-ipv6',
  });
  assert.equal(uiUrl, 'http://[::1]:45123/?conversationId=conv-ipv6');
  assert.ok(!uiUrl.includes('secret-should-not-be-in-url'));

  const res = await adapter.requestJson({
    sidecar: { host: '::1', port: 45123, token: 'real-sidecar-token' },
    path: '/api/telemetry',
    body: { conversationId: 'conv-ipv6' },
  });
  assert.equal(res.usedTokens, 12000);
  assert.equal(seen[0].url, 'http://[::1]:45123/api/telemetry');
  assert.equal(seen[0].opts.headers['X-Sidecar-Token'], 'real-sidecar-token');
});

test('ARP-TC-018: AntigravitySettingsAdapter applies remote local-llm fallback safely', async () => {
  const adapter = createAntigravitySettingsAdapter({
    async readSettingsFile() {
      return {
        enabled: true,
        provider: 'local-llm',
        customEndpoint: 'http://localhost:11434/v1',
      };
    },
  });

  const safe = await adapter.readPluginSettings('antigravity-ko-translator');
  assert.equal(safe.provider, 'google-translate');
  assert.equal(safe.customEndpoint, null);
});

test('ARP-TC-021: AntigravityFrameAdapter fails closed on missing origin and promotes accessible iframes', async () => {
  assert.throws(
    () => createAntigravityFrameAdapter({ initialFrame: { win: {}, doc: {} } }),
    (err) => err instanceof SecurityPolicyError && err.code === 'ORIGIN_NOT_ALLOWED',
  );

  const adapter = createAntigravityFrameAdapter();
  const seenFrames = [];
  adapter.onFrameChange((f) => seenFrames.push(f));

  assert.throws(
    () => adapter.notifyFramePromoted({ win: {}, doc: {} }),
    (err) => err instanceof SecurityPolicyError && err.code === 'ORIGIN_NOT_ALLOWED',
  );

  const fakeIframe = {
    contentWindow: { location: { origin: 'https://antigravity.google.com' }, name: 'remote-win' },
    contentDocument: { nodeType: 9 },
  };
  const promoted = adapter.promoteRemoteIframe(fakeIframe, { conversationId: 'conv-7' });
  assert.equal(promoted.origin, 'https://antigravity.google.com');
  assert.equal(promoted.win, fakeIframe.contentWindow);
  assert.equal(promoted.doc, fakeIframe.contentDocument);
  assert.equal(seenFrames.length, 1);

  const acquired = await adapter.acquireActiveFrame();
  assert.equal(acquired, promoted);
});
