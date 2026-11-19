import test from 'node:test';
import assert from 'node:assert/strict';
import { DiagnosticsBus } from '../src/core/diagnostics.js';
import { createDomOverlayBridge } from '../src/bridges/dom-overlay-bridge.js';
import { createSidecarUiBridge, deriveSidecarOrigin } from '../src/bridges/sidecar-ui-bridge.js';
import { createMcpExtensionSlot } from '../src/bridges/mcp-extension-slot.js';
import { sanitizeTranslatorSettings } from '../src/adapters/antigravity/settings-adapter.js';
import { createAntigravityThemeWorkspaceAdapter } from '../src/adapters/antigravity/theme-workspace-adapter.js';
import {
  ANTIGRAVITY_PROTECTED_MCP_PATHS,
  ANTIGRAVITY_SIDECAR_INBOUND_EVENTS,
  ANTIGRAVITY_STATUSBAR_API_PATHS,
} from '../src/runtime/bootstrap.js';
import { SecurityPolicyError } from '../src/security/origin-policy.js';
import { REDACTED } from '../src/security/redactor.js';

test('ARP-TC-013: DomOverlayBridge validates SettingsReadPort, enforces least privilege, and rolls back failed start()', async () => {
  assert.throws(
    () => createDomOverlayBridge({
      id: 'bad-settings-port',
      pluginName: 'p',
      createOverlay: () => ({ start() {}, dispose() {} }),
      settingsPort: {},
    }),
    /SettingsReadPort/,
  );

  let receivedArgs = null;
  let started = false;
  let updated = null;
  let disposedCount = 0;

  let requestedPluginName = null;
  const bridge = createDomOverlayBridge({
    id: 'ko-overlay',
    pluginName: 'antigravity-ko-translator',
    pluginAliases: ['ko-thought-translator'],
    sanitizeSettings: sanitizeTranslatorSettings,
    settingsPort: {
      async readPluginSettings(name) {
        requestedPluginName = name;
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
  await bridge.mount({ frame, plugin: { name: 'ko-thought-translator' }, diagnostics: new DiagnosticsBus() });

  assert.equal(requestedPluginName, 'ko-thought-translator');
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

test('ARP-TC-014: SidecarUiBridge defers postMessage until iframe load, normalizes port 80, and fails closed on null contentWindow', async () => {
  // deriveSidecarOrigin normalizes port 80 and rejects non-loopback hosts.
  assert.equal(deriveSidecarOrigin({ host: '127.0.0.1', port: 80 }), 'http://127.0.0.1');
  assert.throws(
    () => deriveSidecarOrigin({ host: 'evil.example.com', port: 41234 }),
    (err) => err instanceof SecurityPolicyError && err.code === 'NON_LOOPBACK_SIDECAR',
  );

  const relayCalls = [];
  const postedToIframe = [];
  const inboundSeen = [];
  const winListeners = new Map();
  let iframeLoadHandler = null;
  const diagnostics = new DiagnosticsBus();

  const iframeWindow = {
    postMessage(msg, origin) { postedToIframe.push({ msg, origin }); },
  };
  let removedFromParent = false;
  let currentIframeObj = null;
  const fakeDoc = {
    createElement(tag) {
      const attrs = {};
      currentIframeObj = {
        tagName: tag.toUpperCase(),
        attrs,
        contentWindow: iframeWindow,
        setAttribute(k, v) { attrs[k] = v; },
        addEventListener(type, fn) { if (type === 'load') iframeLoadHandler = fn; },
        removeEventListener(type, fn) { if (type === 'load' && iframeLoadHandler === fn) iframeLoadHandler = null; },
        remove() { removedFromParent = true; },
      };
      return currentIframeObj;
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
    allowedApiPaths: ANTIGRAVITY_STATUSBAR_API_PATHS,
    allowedInboundEvents: ANTIGRAVITY_SIDECAR_INBOUND_EVENTS,
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

  // Before iframe `load`, nothing should be posted to about:blank.
  assert.equal(postedToIframe.length, 0);
  assert.equal(typeof iframeLoadHandler, 'function');

  // Fire `load` -> initial theme + workspace delivered.
  iframeLoadHandler();
  assert.equal(postedToIframe.length, 2);
  assert.equal(postedToIframe[0].msg.type, 'theme-change');
  assert.equal(postedToIframe[1].msg.type, 'workspace-change');

  // Live theme update propagates after load.
  themeWorkspacePort.updateTheme({ '--background': '#222' });
  assert.equal(postedToIframe.length, 3);

  // API relay works for allowlisted endpoints and blocks forbidden endpoints (API_PATH_NOT_ALLOWED).
  const telemetry = await bridge.relayApi('/api/telemetry', { conversationId: 'conv-1' });
  assert.equal(telemetry.ok, true);
  await bridge.relayApi('/api/context-limit', { conversationId: 'conv-1', contextWindow: 384000 });
  await bridge.relayApi('/api/compact', { conversationId: 'conv-1' });
  assert.equal(relayCalls.length, 3);

  await assert.rejects(
    () => bridge.relayApi('/api/forbidden-endpoint', {}),
    (err) => err instanceof SecurityPolicyError && err.code === 'API_PATH_NOT_ALLOWED',
  );

  // Port spoofing (different loopback port 9999) must be rejected.
  const onMsg = winListeners.get('message');
  assert.equal(typeof onMsg, 'function');
  onMsg({
    origin: 'http://127.0.0.1:9999',
    source: iframeWindow,
    data: { type: 'toggle-aux-pane', payload: {} },
  });
  assert.equal(inboundSeen.length, 0);

  // Detached iframe (contentWindow === null) must fail closed on inbound messages.
  currentIframeObj.contentWindow = null;
  const detachedRes = bridge.handleInboundMessage({
    origin: 'http://127.0.0.1:41234',
    source: iframeWindow,
    data: { type: 'toggle-aux-pane', payload: {} },
  });
  assert.equal(detachedRes.accepted, false);
  assert.equal(detachedRes.reason, 'SOURCE_UNAVAILABLE');
  currentIframeObj.contentWindow = iframeWindow;

  // Exact origin + exact source accepted.
  onMsg({
    origin: 'http://127.0.0.1:41234',
    source: iframeWindow,
    data: { type: 'toggle-aux-pane', payload: { open: true } },
  });
  assert.equal(inboundSeen.length, 1);

  bridge.dispose();
  assert.equal(removedFromParent, true);
  assert.equal(iframeLoadHandler, null);
  assert.equal(winListeners.has('message'), false);
});

test('ARP-TC-015: McpExtensionSlot rejects NUL/control chars, traversal, null path, and omitted-transport stdio', async () => {
  const slot = createMcpExtensionSlot({
    id: 'mcp-slot',
    pluginName: 'antigravity-mcp-manager',
    protectedConfigPatterns: ANTIGRAVITY_PROTECTED_MCP_PATHS,
  });
  await slot.mount({ diagnostics: new DiagnosticsBus() });

  await assert.rejects(
    () => slot.requestServerMutation({
      targetConfigPath: '/home/user/workspace/custom-mcp.json',
      userConfirmed: false,
      serverConfig: { command: 'npx', args: ['-y', 'evil'] },
    }),
    (err) => err instanceof SecurityPolicyError && err.code === 'UNCONFIRMED_REMOTE_STDIO',
  );

  for (const invalidPath of [null, '', 'C:.gemini/config/config.json', '/home/user/.gemini/config/config.json\u0000', '/home/user/mcp.json\n']) {
    await assert.rejects(
      () => slot.requestServerMutation({
        targetConfigPath: invalidPath,
        transport: 'http',
        userConfirmed: true,
        serverConfig: { url: 'https://mcp.example.com' },
      }),
      (err) => err instanceof SecurityPolicyError && err.code === 'INVALID_CONFIG_PATH',
    );
  }

  for (const badPath of [
    '/home/user/.gemini/config/./config.json',
    '/home/user/.gemini/config/sub/../config.json',
    '/home/user/.gemini//config//config.json',
    '~/.gemini/config/mcp_config.json',
    '~/.gemini/antigravity/mcp_config.json',
    '~/.gemini/config/plugins/my-plugin/config.json',
    '/home/user/.gemini/config/plugins/foo/../bar/mcp_config.json',
  ]) {
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
