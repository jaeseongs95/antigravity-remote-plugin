import test from 'node:test';
import assert from 'node:assert/strict';
import { createAntigravityDiscoveryAdapter } from '../src/adapters/antigravity/discovery-adapter.js';
import { createAntigravitySidecarAdapter } from '../src/adapters/antigravity/sidecar-adapter.js';
import { createAntigravitySettingsAdapter } from '../src/adapters/antigravity/settings-adapter.js';
import { SecurityPolicyError } from '../src/security/origin-policy.js';

test('ARP-TC-016: AntigravityDiscoveryAdapter queries GetAllPlugins/GetSidecars and rejects synthetic CSRF', async () => {
  assert.throws(
    () => createAntigravityDiscoveryAdapter({ lsAddress: '127.0.0.1:5387', csrfToken: 'csrf_token' }),
    (err) => err instanceof SecurityPolicyError && err.code === 'SYNTHETIC_CSRF_TOKEN',
  );
  assert.throws(
    () => createAntigravityDiscoveryAdapter({ lsAddress: 'https://remote.evil.test:5387', csrfToken: 'real-csrf-123456' }),
    (err) => err instanceof SecurityPolicyError && err.code === 'NON_LOOPBACK_LS_ADDRESS',
  );

  const calls = [];
  const adapter = createAntigravityDiscoveryAdapter({
    lsAddress: '127.0.0.1:5387',
    csrfToken: 'real-host-csrf-token-9999',
    async fetchImpl(url, opts) {
      calls.push({ url, headers: opts.headers });
      if (url.endsWith('/GetAllPlugins')) {
        return {
          ok: true,
          async json() {
            return {
              plugins: [
                { name: 'antigravity-statusbar', path: '/p/antigravity-statusbar', disabled: false },
                { name: 'ko-thought-translator', path: '/p/ko-thought-translator', disabled: true },
              ],
            };
          },
        };
      }
      return {
        ok: true,
        async json() {
          return {
            sidecars: [
              { sidecarId: 'antigravity-statusbar/statusbar', port: 45123, token: 'sc-tok', running: true },
            ],
          };
        },
      };
    },
  });

  const plugins = await adapter.listPlugins();
  const sidecars = await adapter.listSidecars();

  assert.equal(plugins.length, 2);
  assert.equal(plugins[0].enabled, true);
  assert.equal(plugins[1].enabled, false);
  assert.equal(sidecars[0].sidecarId, 'antigravity-statusbar/statusbar');
  assert.equal(calls[0].headers['x-codeium-csrf-token'], 'real-host-csrf-token-9999');
});

test('ARP-TC-017: AntigravitySidecarAdapter enforces loopback and injects X-Sidecar-Token', async () => {
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

  const res = await adapter.requestJson({
    sidecar: { host: '127.0.0.1', port: 45123, token: 'real-sidecar-token' },
    path: '/api/telemetry',
    body: { conversationId: 'conv-1' },
  });
  assert.equal(res.usedTokens, 12000);
  assert.equal(seen[0].url, 'http://127.0.0.1:45123/api/telemetry');
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

  const safe = await adapter.readPluginSettings('ko-thought-translator');
  assert.equal(safe.provider, 'google-translate');
  assert.equal(safe.customEndpoint, null);
});
