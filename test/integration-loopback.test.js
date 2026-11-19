import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { bootstrapAntigravityRemoteBridge } from '../src/runtime/bootstrap.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function startJsonServer(handler) {
  return new Promise((resolveServer) => {
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const parsed = body ? JSON.parse(body) : {};
        const result = handler({ method: req.method, url: req.url, headers: req.headers, body: parsed });
        res.writeHead(result.status || 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result.json ?? {}));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolveServer({ server, port });
    });
  });
}

test('ARP-TC-022: real node:http loopback integration for bootstrap.js and standalone dist/remote_bridge.js', async () => {
  const REAL_CSRF = 'real-live-csrf-token-8888';
  const REAL_SIDECAR_TOKEN = 'real-sidecar-secret-7777';

  const sidecarSrv = await startJsonServer(({ url, headers, body }) => {
    if (headers['x-sidecar-token'] !== REAL_SIDECAR_TOKEN) {
      return { status: 401, json: { error: 'unauthorized' } };
    }
    if (url === '/api/telemetry') {
      return { status: 200, json: { conversationId: body.conversationId, usedTokens: 42000, maxTokenLimit: 384000 } };
    }
    if (url === '/api/context-limit') {
      return { status: 200, json: { saved: true, contextWindow: body.contextWindow } };
    }
    if (url === '/api/compact') {
      return { status: 200, json: { dispatched: true } };
    }
    return { status: 404, json: { error: 'not found' } };
  });

  const lsSrv = await startJsonServer(({ url, headers }) => {
    if (headers['x-codeium-csrf-token'] !== REAL_CSRF) {
      return { status: 403, json: { error: 'forbidden' } };
    }
    if (url === '/exa.language_server_pb.LanguageServerService/GetAllPlugins') {
      return {
        status: 200,
        json: {
          plugins: [
            { name: 'antigravity-statusbar', path: '/p/antigravity-statusbar', disabled: false },
            { name: 'antigravity-ko-translator', path: '/p/ko-thought-translator', disabled: false },
            { name: 'antigravity-mcp-manager', path: '/p/antigravity-mcp-manager', disabled: true },
          ],
        },
      };
    }
    if (url === '/exa.language_server_pb.LanguageServerService/GetSidecars') {
      return {
        status: 200,
        json: {
          sidecars: [
            {
              sidecarId: 'antigravity-statusbar/statusbar',
              pluginName: 'antigravity-statusbar',
              host: '127.0.0.1',
              port: sidecarSrv.port,
              token: REAL_SIDECAR_TOKEN,
              running: true,
            },
          ],
        },
      };
    }
    return { status: 404, json: { error: 'unknown rpc' } };
  });

  const isolatedDir = mkdtempSync(join(tmpdir(), 'arp-loopback-'));

  try {
    // Copy standalone dist/remote_bridge.js to isolated dir and run both direct & standalone entrypoints.
    const copiedBundle = join(isolatedDir, 'remote_bridge.mjs');
    copyFileSync(join(ROOT, 'dist/remote_bridge.js'), copiedBundle);
    const standalone = await import(pathToFileURL(copiedBundle).href);

    for (const bootstrapFn of [bootstrapAntigravityRemoteBridge, standalone.bootstrapAntigravityRemoteBridge]) {
      const overlayEvents = [];
      const iframeMessages = [];
      const hostListeners = new Map();
      const inboundEvents = [];

      const sidecarIframeWin = {
        postMessage(msg, origin) { iframeMessages.push({ msg, origin }); },
      };
      const fakeRemoteDoc = {
        createElement(tag) {
          const attrs = {};
          return {
            tagName: tag.toUpperCase(),
            attrs,
            contentWindow: sidecarIframeWin,
            setAttribute(k, v) { attrs[k] = v; },
            remove() {},
          };
        },
        body: { appendChild() {} },
      };
      const fakeRemoteWin = {
        location: { origin: 'https://antigravity.google.com' },
        addEventListener(type, fn) { hostListeners.set(type, fn); },
        removeEventListener(type, fn) {
          if (hostListeners.get(type) === fn) hostListeners.delete(type);
        },
      };

      const app = bootstrapFn({
        lsAddress: `127.0.0.1:${lsSrv.port}`,
        csrfToken: REAL_CSRF,
        readSettingsFile: async () => ({ provider: 'local-llm', translateThinking: true }),
        initialThemeVariables: { '--background': '#0d1117' },
        initialWorkspaceUris: ['file:///d:/project'],
        createKoTranslator({ win, doc, settings }) {
          return {
            start() { overlayEvents.push({ type: 'start', provider: settings.provider, hasWin: Boolean(win && doc) }); },
            dispose() { overlayEvents.push({ type: 'dispose' }); },
          };
        },
        onSidecarEvent(evt) { inboundEvents.push(evt); },
      });

      // Promote real iframe descriptor before starting.
      app.framePort.promoteRemoteIframe(
        { contentWindow: fakeRemoteWin, contentDocument: fakeRemoteDoc },
        { conversationId: 'conv-live-1' },
      );

      const startRes = await app.orchestrator.start();
      assert.deepEqual(startRes.mountedIds.sort(), ['ko-translator-overlay', 'statusbar-sidecar']);
      assert.deepEqual(startRes.skippedIds, ['mcp-manager-slot']);

      // Verify ko-translator least-privilege mount & local-llm fallback.
      assert.equal(overlayEvents[0].provider, 'google-translate');
      assert.equal(overlayEvents[0].hasWin, true);

      // Verify real loopback HTTP sidecar API relay with X-Sidecar-Token.
      const telemetry = await app.bridges.statusbar.relayApi('/api/telemetry', { conversationId: 'conv-live-1' });
      assert.equal(telemetry.usedTokens, 42000);
      const limit = await app.bridges.statusbar.relayApi('/api/context-limit', { conversationId: 'conv-live-1', contextWindow: 384000 });
      assert.equal(limit.saved, true);
      const compact = await app.bridges.statusbar.relayApi('/api/compact', { conversationId: 'conv-live-1' });
      assert.equal(compact.dispatched, true);

      // Verify buildUiUrl omits ?token= secret.
      const uiUrl = app.bridges.statusbar.buildUiUrl({ conversationId: 'conv-live-1' });
      assert.equal(uiUrl, `http://127.0.0.1:${sidecarSrv.port}/?conversationId=conv-live-1`);
      assert.ok(!uiUrl.includes(REAL_SIDECAR_TOKEN));

      // Verify live theme/workspace sync & exact-port postMessage validation.
      app.themeWorkspacePort.updateWorkspaces(['file:///d:/project', 'file:///d:/project-b']);
      assert.ok(iframeMessages.some((m) => m.msg.type === 'theme-change' && m.origin === `http://127.0.0.1:${sidecarSrv.port}`));
      assert.ok(iframeMessages.some((m) => m.msg.type === 'workspace-change' && m.msg.payload.workspaceUris.length === 2));

      const msgHandler = hostListeners.get('message');
      msgHandler({
        origin: `http://127.0.0.1:${sidecarSrv.port + 1}`,
        source: sidecarIframeWin,
        data: { type: 'toggle-aux-pane', payload: {} },
      });
      assert.equal(inboundEvents.length, 0);

      msgHandler({
        origin: `http://127.0.0.1:${sidecarSrv.port}`,
        source: sidecarIframeWin,
        data: { type: 'toggle-aux-pane', payload: { open: true } },
      });
      assert.equal(inboundEvents.length, 1);

      app.orchestrator.dispose();
      assert.equal(overlayEvents[overlayEvents.length - 1].type, 'dispose');
      assert.equal(hostListeners.has('message'), false);
    }
  } finally {
    rmSync(isolatedDir, { recursive: true, force: true });
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => sidecarSrv.server.close(r));
  }
});
