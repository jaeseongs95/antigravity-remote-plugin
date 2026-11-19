import test from 'node:test';
import assert from 'node:assert/strict';
import { DiagnosticsBus } from '../src/core/diagnostics.js';
import { createDomOverlayBridge } from '../src/bridges/dom-overlay-bridge.js';
import { createSidecarUiBridge } from '../src/bridges/sidecar-ui-bridge.js';
import { createMcpExtensionSlot } from '../src/bridges/mcp-extension-slot.js';
import { sanitizeTranslatorSettings } from '../src/adapters/antigravity/settings-adapter.js';
import { createAntigravityThemeWorkspaceAdapter } from '../src/adapters/antigravity/theme-workspace-adapter.js';
import { SecurityPolicyError } from '../src/security/origin-policy.js';
import { REDACTED } from '../src/security/redactor.js';

test('ARP-TC-013: DomOverlayBridge enforces least privilege, rolls back failed start(), and serializes mount()', async () => {
  let receivedArgs = null;
  let started = false;
  let updated = null;
  let disposedCount = 0;

  const bridge = createDomOverlayBridge({
    id: 'ko-overlay',
    pluginName: 'antigravity-ko-translator',
    sanitizeSettings: sanitizeTranslatorSettings,
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
        dispose() { disposedCount += 1; },
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
  assert.equal(disposedCount, 1);

  // start() failure must roll back (dispose) and rethrow.
  let failedDisposed = false;
  const failingBridge = createDomOverlayBridge({
    id: 'ko-fail',
    pluginName: 'antigravity-ko-translator',
    createOverlay() {
      return {
        async start() { throw new Error('mount start failed'); },
        dispose() { failedDisposed = true; },
      };
    },
  });
  await assert.rejects(
    () => failingBridge.mount({ frame, diagnostics: new DiagnosticsBus() }),
    /mount start failed/,
  );
  assert.equal(failedDisposed, true);
});

test('ARP-TC-014: SidecarUiBridge wires ThemeWorkspaceSyncPort + message listener and enforces exact port & source', async () => {
  const relayCalls = [];
  const postedToIframe = [];
  const inboundSeen = [];
  const winListeners = new Map();
  const diagnostics = new DiagnosticsBus();

  const iframeWindow = {
    postMessage(msg, origin) { postedToIframe.push({ msg, origin }); },
  };
  let removedFromParent = false;
  const fakeDoc = {
    createElement(tag) {
      const attrs = {};
      return {
        tagName: tag.toUpperCase(),
        attrs,
        contentWindow: iframeWindow,
        setAttribute(k, v) { attrs[k] = v; },
        remove() { removedFromParent = true; },
      };
    },
    body: {
      children: [],
      appendChild(el) { this.children.push(el); },
    },
  };
  const fakeHostWin = {
    addEventListener(type, fn) { winListeners.set(type, fn); },
    removeEventListener(type, fn) {
      if (winListeners.get(type) === fn) winListeners.delete(type);
    },
  };

  const themeWorkspacePort = createAntigravityThemeWorkspaceAdapter({
    initialThemeVariables: { '--background': '#111' },
    initialWorkspaceUris: ['file:///workspace/a'],
  });

  const bridge = createSidecarUiBridge({
    id: 'statusbar-ui',
    pluginName: 'antigravity-statusbar',
    sidecarId: 'antigravity-statusbar/statusbar',
    themeWorkspacePort,
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
    frame: { win: fakeHostWin, doc: fakeDoc, conversationId: 'conv-1' },
    sidecar: { sidecarId: 'antigravity-statusbar/statusbar', host: '127.0.0.1', port: 41234, token: 'tok-1' },
    diagnostics,
  });

  // Initial theme + workspace pushed automatically on mount.
  assert.equal(postedToIframe.length, 2);
  assert.equal(postedToIframe[0].msg.type, 'theme-change');
  assert.equal(postedToIframe[0].origin, 'http://127.0.0.1:41234');
  assert.equal(postedToIframe[1].msg.type, 'workspace-change');

  // Live theme update propagates automatically.
  themeWorkspacePort.updateTheme({ '--background': '#222' });
  assert.equal(postedToIframe.length, 3);
  assert.equal(postedToIframe[2].msg.payload.cssVariables['--background'], '#222');

  // API relay works for allowlisted endpoints and blocks others.
  await bridge.relayApi('/api/telemetry', { conversationId: 'conv-1' });
  await bridge.relayApi('/api/context-limit', { conversationId: 'conv-1', contextWindow: 384000 });
  await bridge.relayApi('/api/compact', { conversationId: 'conv-1' });
  assert.equal(relayCalls.length, 3);

  await assert.rejects(
    () => bridge.relayApi('/api/forbidden-endpoint', {}),
    (err) => err instanceof SecurityPolicyError && err.code === 'API_PATH_NOT_ALLOWED',
  );

  // Different localhost port (spoofing) must be rejected!
  const onMsg = winListeners.get('message');
  assert.equal(typeof onMsg, 'function');
  onMsg({
    origin: 'http://127.0.0.1:9999',
    source: iframeWindow,
    data: { type: 'toggle-aux-pane', payload: {} },
  });
  assert.equal(inboundSeen.length, 0);

  // Wrong window source on same origin must be rejected!
  onMsg({
    origin: 'http://127.0.0.1:41234',
    source: { fake: true },
    data: { type: 'toggle-aux-pane', payload: {} },
  });
  assert.equal(inboundSeen.length, 0);

  // Exact activeSidecar origin + exact iframe source is accepted.
  onMsg({
    origin: 'http://127.0.0.1:41234',
    source: iframeWindow,
    data: { type: 'toggle-aux-pane', payload: { open: true } },
  });
  assert.equal(inboundSeen.length, 1);

  bridge.dispose();
  assert.equal(removedFromParent, true);
  assert.equal(winListeners.has('message'), false);
});

test('ARP-TC-015: McpExtensionSlot canonicalizes paths, rejects null/traversal/omitted-transport stdio', async () => {
  const slot = createMcpExtensionSlot({
    id: 'mcp-slot',
    pluginName: 'antigravity-mcp-manager',
    protectedConfigPatterns: [/(?:^|\/)\.gemini\/antigravity\/mcp_config\.json$/i],
  });
  await slot.mount({ diagnostics: new DiagnosticsBus() });

  // Omitted transport + serverConfig.command must be blocked as unconfirmed stdio.
  await assert.rejects(
    () => slot.requestServerMutation({
      targetConfigPath: '/home/user/workspace/custom-mcp.json',
      userConfirmed: false,
      serverConfig: { command: 'npx', args: ['-y', 'evil'] },
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'UNCONFIRMED_REMOTE_STDIO',
  );

  // Null / empty targetConfigPath must be rejected.
  await assert.rejects(
    () => slot.requestServerMutation({
      targetConfigPath: null,
      transport: 'http',
      userConfirmed: true,
      serverConfig: { url: 'https://mcp.example.com' },
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'INVALID_CONFIG_PATH',
  );

  // Path traversal, duplicate slashes, tilde, and ~/.gemini/antigravity/mcp_config.json must all be blocked.
  const blockedPaths = [
    '/home/user/.gemini/config/./config.json',
    '/home/user/.gemini/config/sub/../config.json',
    '/home/user/.gemini//config//config.json',
    '~/.gemini/antigravity/mcp_config.json',
    '/home/user/.gemini/config/plugins/foo/../bar/mcp_config.json',
  ];
  for (const badPath of blockedPaths) {
    await assert.rejects(
      () => slot.requestServerMutation({
        targetConfigPath: badPath,
        transport: 'http',
        userConfirmed: true,
        serverConfig: { url: 'https://mcp.example.com' },
      }),
      (err) => err instanceof SecurityPolicyError && err.code === 'PROTECTED_CONFIG_PATH',
    );
  }

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
