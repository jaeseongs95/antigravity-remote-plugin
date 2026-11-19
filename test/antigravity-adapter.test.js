import test from 'node:test';
import assert from 'node:assert/strict';
import { createAntigravityDiscoveryAdapter } from '../src/adapters/antigravity/discovery-adapter.js';
import { createAntigravityFrameAdapter } from '../src/adapters/antigravity/frame-adapter.js';
import { createAntigravitySidecarAdapter } from '../src/adapters/antigravity/sidecar-adapter.js';
import { createAntigravitySettingsAdapter } from '../src/adapters/antigravity/settings-adapter.js';
import { SecurityPolicyError } from '../src/security/origin-policy.js';

test('ARP-TC-016: AntigravityDiscoveryAdapter strips trailing slashes, rejects file://, synthetic CSRF, and malformed payloads', async () => {
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

  const validAdapter = createAntigravityDiscoveryAdapter({
    lsAddress: '127.0.0.1:5387',
    csrfToken: 'real-host-csrf-token-9999',
    async fetchImpl() {
      return {
        ok: true,
        async json() {
          return {
            plugins: [{ name: 'antigravity-ko-translator', path: '/plugins/ko-thought-translator///', disabled: false }],
          };
        },
      };
    },
  });
  const plugins = await validAdapter.listPlugins();
  assert.equal(plugins[0].dir, 'ko-thought-translator');

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

test('ARP-TC-018: AntigravitySettingsAdapter applies translator fallback and generic secret stripping by pluginName', async () => {
  const adapter = createAntigravitySettingsAdapter({
    async readSettingsFile(pluginName) {
      if (pluginName === 'antigravity-ko-translator') {
        return { enabled: true, provider: 'local-llm', customEndpoint: 'https://user:pass@api.example.com/v1' };
      }
      return { refreshMs: 1000, api_key: 'secret-val', nested: { token: 'nested-secret', ok: true } };
    },
  });

  const safeTranslator = await adapter.readPluginSettings('antigravity-ko-translator');
  assert.equal(safeTranslator.provider, 'google-translate');
  assert.equal(safeTranslator.customEndpoint, null);

  const safeOther = await adapter.readPluginSettings('antigravity-statusbar');
  assert.equal(safeOther.refreshMs, 1000);
  assert.equal('api_key' in safeOther, false);
  assert.equal('token' in safeOther.nested, false);
  assert.equal(safeOther.nested.ok, true);
});

test('ARP-TC-021: AntigravityFrameAdapter translates cross-origin DOMException and validates targetOrigin match', async () => {
  assert.throws(
    () => createAntigravityFrameAdapter({ initialFrame: { win: {}, doc: {} } }),
    (err) => err instanceof SecurityPolicyError && err.code === 'ORIGIN_NOT_ALLOWED',
  );

  const adapter = createAntigravityFrameAdapter();
  const seenFrames = [];
  adapter.onFrameChange((f) => seenFrames.push(f));

  // Cross-origin getter throwing DOMException on location.origin must become CROSS_ORIGIN_IFRAME_DENIED.
  const crossOriginIframe = {
    contentWindow: {
      get location() {
        throw new Error('Blocked a frame with origin from accessing a cross-origin frame.');
      },
    },
  };
  assert.throws(
    () => adapter.promoteRemoteIframe(crossOriginIframe),
    (err) => err instanceof SecurityPolicyError && err.code === 'CROSS_ORIGIN_IFRAME_DENIED',
  );

  // Mismatched targetOrigin vs actual location.origin must throw ORIGIN_MISMATCH.
  const fakeIframe = {
    contentWindow: { location: { origin: 'https://antigravity.google.com' }, name: 'remote-win' },
    contentDocument: { nodeType: 9 },
  };
  assert.throws(
    () => adapter.promoteRemoteIframe(fakeIframe, { targetOrigin: 'https://sub.antigravity.google.com' }),
    (err) => err instanceof SecurityPolicyError && err.code === 'ORIGIN_MISMATCH',
  );

  const promoted = adapter.promoteRemoteIframe(fakeIframe, {
    targetOrigin: 'https://antigravity.google.com',
    conversationId: 'conv-7',
  });
  assert.equal(promoted.origin, 'https://antigravity.google.com');
  assert.equal(seenFrames.length, 1);

  const acquired = await adapter.acquireActiveFrame();
  assert.equal(acquired, promoted);
});
