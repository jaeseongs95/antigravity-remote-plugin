import test from 'node:test';
import assert from 'node:assert/strict';
import { DiagnosticsBus } from '../src/core/diagnostics.js';
import { createDomOverlayBridge } from '../src/bridges/dom-overlay-bridge.js';
import { createSidecarUiBridge } from '../src/bridges/sidecar-ui-bridge.js';
import { createMcpExtensionSlot } from '../src/bridges/mcp-extension-slot.js';
import { SecurityPolicyError } from '../src/security/origin-policy.js';
import { REDACTED } from '../src/security/redactor.js';

test('ARP-TC-013: DomOverlayBridge enforces least privilege, remote fallback, and dispose lifecycle', async () => {
  let receivedArgs = null;
  let started = false;
  let updated = null;
  let disposed = false;

  const bridge = createDomOverlayBridge({
    id: 'ko-overlay',
    pluginName: 'ko-thought-translator',
    remoteFallbackProvider: 'google-translate',
    settingsPort: {
      async readPluginSettings() {
        return {
          enabled: true,
          translateThinking: true,
          translateStaticUi: true,
          provider: 'local-llm',
          customEndpoint: 'http://insecure.local/api',
          csrfToken: 'should-never-pass',
          lsClient: { send() {} },
        };
      },
    },
    createOverlay(args) {
      receivedArgs = args;
      return {
        start() { started = true; },
        updateSettings(next) { updated = next; },
        dispose() { disposed = true; },
      };
    },
  });

  const frame = { win: { name: 'promoted' }, doc: { nodeType: 9 } };
  await bridge.mount({ frame, diagnostics: new DiagnosticsBus() });

  assert.equal(started, true);
  assert.deepEqual(Object.keys(receivedArgs).sort(), ['doc', 'onStatus', 'settings', 'win']);
  assert.equal(receivedArgs.settings.provider, 'google-translate');
  assert.equal(receivedArgs.settings.customEndpoint, null);
  assert.equal('csrfToken' in receivedArgs.settings, false);
  assert.equal('lsClient' in receivedArgs.settings, false);

  bridge.updateSettings({ provider: 'local-llm', customEndpoint: 'https://api.example.com/tr' });
  assert.equal(updated.provider, 'custom-https');
  assert.equal(updated.customEndpoint, 'https://api.example.com/tr');

  bridge.dispose();
  assert.equal(disposed, true);
});

test('ARP-TC-014: SidecarUiBridge relays allowed APIs and validates postMessage origins', async () => {
  const relayCalls = [];
  const posted = [];
  const inboundSeen = [];
  const diagnostics = new DiagnosticsBus();

  const bridge = createSidecarUiBridge({
    id: 'statusbar-ui',
    pluginName: 'antigravity-statusbar',
    sidecarId: 'antigravity-statusbar/statusbar',
    allowedOrigins: ['https://remote.example.com', 'http://127.0.0.1:*'],
    relayPort: {
      buildUiUrl({ sidecar, conversationId }) {
        return `http://127.0.0.1:${sidecar.port}/?conversationId=${conversationId}`;
      },
      async requestJson(req) {
        relayCalls.push(req);
        return { ok: true, path: req.path };
      },
    },
    onInboundEvent(evt) {
      inboundSeen.push(evt);
    },
  });

  await bridge.mount({
    sidecar: { sidecarId: 'antigravity-statusbar/statusbar', port: 41234, token: 'tok-1' },
    diagnostics,
  });

  const telemetry = await bridge.relayApi('/api/telemetry', { conversationId: 'c1' });
  assert.equal(telemetry.ok, true);
  await bridge.relayApi('/api/context-limit', { conversationId: 'c1', contextWindow: 384000 });
  await bridge.relayApi('/api/compact', { conversationId: 'c1' });
  assert.equal(relayCalls.length, 3);

  await assert.rejects(
    () => bridge.relayApi('/api/forbidden-endpoint', {}),
    (err) => err instanceof SecurityPolicyError && err.code === 'API_PATH_NOT_ALLOWED',
  );

  const fakeWin = {
    postMessage(msg, origin) { posted.push({ msg, origin }); },
  };
  bridge.postThemeChange(fakeWin, 'http://127.0.0.1:41234', { '--background': '#111' });
  bridge.postWorkspaceChange(fakeWin, 'http://127.0.0.1:41234', ['file:///workspace']);
  assert.equal(posted.length, 2);
  assert.equal(posted[0].msg.type, 'theme-change');
  assert.equal(posted[1].msg.type, 'workspace-change');

  const dropped = bridge.handleInboundMessage({
    origin: 'https://attacker.test',
    data: { type: 'toggle-aux-pane', payload: {} },
  });
  assert.equal(dropped.accepted, false);
  assert.equal(dropped.reason, 'UNTRUSTED_ORIGIN');

  const accepted = bridge.handleInboundMessage({
    origin: 'http://127.0.0.1:41234',
    data: { type: 'toggle-aux-pane', payload: { open: true } },
  });
  assert.equal(accepted.accepted, true);
  assert.equal(inboundSeen.length, 1);

  bridge.dispose();
});

test('ARP-TC-015: McpExtensionSlot blocks unconfirmed remote stdio, protected configs, and secret leakage', async () => {
  const slot = createMcpExtensionSlot({
    id: 'mcp-slot',
    pluginName: 'antigravity-mcp-manager',
  });
  await slot.mount({ diagnostics: new DiagnosticsBus() });

  await assert.rejects(
    () => slot.requestServerMutation({
      transport: 'stdio',
      userConfirmed: false,
      serverConfig: { command: 'npx', args: ['-y', 'evil'] },
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'UNCONFIRMED_REMOTE_STDIO',
  );

  await assert.rejects(
    () => slot.requestServerMutation({
      targetConfigPath: '/home/user/.gemini/config/config.json',
      transport: 'http',
      userConfirmed: true,
      serverConfig: { url: 'https://mcp.example.com' },
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'PROTECTED_CONFIG_PATH',
  );

  await assert.rejects(
    () => slot.requestServerMutation({
      targetConfigPath: '/home/user/.gemini/config/plugins/foo/mcp_config.json',
      transport: 'http',
      userConfirmed: true,
      serverConfig: { url: 'https://mcp.example.com' },
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'PROTECTED_CONFIG_PATH',
  );

  const preview = await slot.requestServerMutation({
    targetConfigPath: '/home/user/workspace/custom-mcp.json',
    transport: 'stdio',
    userConfirmed: true,
    serverConfig: { command: 'node', env: { SECRET_KEY: '123' }, headers: { Authorization: 'Bearer abc' } },
  });
  assert.equal(preview.applied, false);
  assert.equal(preview.sanitizedPreview.env, REDACTED);
  assert.equal(preview.sanitizedPreview.headers, REDACTED);

  slot.dispose();
});
