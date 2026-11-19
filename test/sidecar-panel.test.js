import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRemotePanelHandlers } from '../src/adapters/antigravity/sidecar-host.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function startServer(handler) {
  return new Promise((resolveSrv) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      resolveSrv({ server, port: server.address().port });
    });
  });
}

function readJsonBody(req) {
  return new Promise((resolveBody) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      resolveBody(raw ? JSON.parse(raw) : {});
    });
  });
}

test('ARP-TC-025: Official sidecar.json manifest and real loopback sidecar-host handlers relay statusbar & redact secrets', async () => {
  const sidecarJson = JSON.parse(
    readFileSync(join(ROOT, 'sidecars/remote-panel/sidecar.json'), 'utf8'),
  );
  assert.equal(sidecarJson.command, 'node');
  assert.deepEqual(sidecarJson.args, ['server.mjs']);
  assert.equal(sidecarJson.has_web_ui, true);
  assert.equal(sidecarJson.ui_config?.views?.[0]?.path, '/');
  assert.equal(sidecarJson.ui_config?.views?.[0]?.entrypoint, 'SIDECAR_UI_ENTRYPOINT_AUX_PANE');

  const REAL_CSRF = 'real-sidecar-host-csrf-9999';
  const REAL_SIDECAR_TOKEN = 'secret-statusbar-token-8888';
  let statusbarRunning = true;
  let compactCalls = 0;

  const statusbarSrv = await startServer(async (req, res) => {
    if (req.headers['x-sidecar-token'] !== REAL_SIDECAR_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    const body = await readJsonBody(req);
    if (req.url === '/api/telemetry') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ usedTokens: 42000, maxTokenLimit: 200000, csrfToken: 'leak-check' }));
      return;
    }
    if (req.url === '/api/context-limit') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ maxTokenLimit: 200000 }));
      return;
    }
    if (req.url === '/api/compact') {
      compactCalls += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ compacted: true, workspaceCount: (body.workspaceUris || []).length }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const lsSrv = await startServer(async (req, res) => {
    if (req.headers['x-codeium-csrf-token'] !== REAL_CSRF) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'forbidden' }));
      return;
    }
    if (req.url.endsWith('/GetAllPlugins')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        plugins: [
          { name: 'antigravity-statusbar', path: '/plugins/antigravity-statusbar', disabled: false, isGlobal: true },
          { name: 'antigravity-mcp-manager', path: '/plugins/antigravity-mcp-manager', disabled: false, isGlobal: true },
          { name: 'disabled-plugin', path: '/plugins/disabled-plugin', disabled: true, isGlobal: false },
        ],
      }));
      return;
    }
    if (req.url.endsWith('/GetSidecars')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        sidecars: statusbarRunning
          ? [{
              sidecarId: 'antigravity-statusbar/statusbar',
              pluginName: 'antigravity-statusbar',
              host: '127.0.0.1',
              port: statusbarSrv.port,
              token: REAL_SIDECAR_TOKEN,
              running: true,
            }]
          : [],
      }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const handlers = createRemotePanelHandlers({
    lsAddress: `127.0.0.1:${lsSrv.port}`,
    csrfToken: REAL_CSRF,
    version: '1.1.0',
  });

  try {
    const health = handlers.getHealth();
    assert.equal(health.ok, true);
    assert.equal(health.version, '1.1.0');

    const state = await handlers.getState({ workspaceUris: ['file:///workspace/demo'] });
    assert.equal(state.ok, true);
    assert.equal(state.statusbarAvailable, true);
    assert.equal(state.plugins.length, 2);
    assert.equal(state.sidecars.length, 1);
    assert.ok(!JSON.stringify(state).includes(REAL_SIDECAR_TOKEN), 'sidecar token must never leak in /api/state');
    assert.ok(!JSON.stringify(state).includes(REAL_CSRF), 'CSRF token must never leak in /api/state');

    const telemetry = await handlers.relayStatusbar('/api/telemetry', {});
    assert.equal(telemetry.ok, true);
    assert.equal(telemetry.data.usedTokens, 42000);
    assert.equal(telemetry.data.csrfToken, '[REDACTED]');

    const limit = await handlers.relayStatusbar('/api/context-limit', {});
    assert.equal(limit.data.maxTokenLimit, 200000);

    const compact = await handlers.relayStatusbar('/api/compact', { workspaceUris: ['file:///workspace/demo'] });
    assert.equal(compact.data.compacted, true);
    assert.equal(compactCalls, 1);

    await assert.rejects(
      () => handlers.relayStatusbar('/api/forbidden', {}),
      (err) => err.statusCode === 403,
    );

    const mcp = await handlers.getMcpSummary();
    assert.equal(mcp.slotMounted, true);
    assert.equal(mcp.mcpPluginActive, true);
    assert.equal(mcp.remoteStdioPolicy, 'explicit-confirmation-required');

    // When statusbar sidecar stops, relay must fail cleanly with 503 STATUSBAR_UNAVAILABLE.
    statusbarRunning = false;
    await assert.rejects(
      () => handlers.relayStatusbar('/api/telemetry', {}),
      (err) => err.statusCode === 503 && err.code === 'STATUSBAR_UNAVAILABLE',
    );
  } finally {
    handlers.dispose();
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => statusbarSrv.server.close(r));
  }
});
