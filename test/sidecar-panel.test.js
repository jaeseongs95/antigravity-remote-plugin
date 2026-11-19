import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRemotePanelHandlers } from '../src/adapters/antigravity/sidecar-host.js';
import { createSidecarServer } from '../sidecars/remote-panel/server.mjs';
import { RemoteOrchestrator } from '../src/core/orchestrator.js';
import { createAntigravityFrameAdapter } from '../src/adapters/antigravity/frame-adapter.js';

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

function findRealSidecarSdkNodePath() {
  const candidates = [
    process.env.ANTIGRAVITY_SIDECAR_SDK_NODE_PATH,
    join(homedir(), '.gemini', 'antigravity', 'lib', 'node_modules'),
  ].filter(Boolean);
  for (const dir of candidates) {
    if (existsSync(join(dir, 'sidecar_sdk', 'index.mjs'))) {
      return dir;
    }
  }
  return null;
}

class InMemoryResponse {
  constructor(body, { contentType = 'text/plain', status = 200, headers = {} } = {}) {
    this.body = body;
    this.contentType = contentType;
    this.status = status;
    this.headers = headers;
  }
}

function createTestSidecarAppClass({ port = 0, token = 'test-ui-token' } = {}) {
  return class TestSidecarApp {
    #pages = new Map();
    #apis = new Map();
    #server = null;
    port = port;

    page(path, handler) {
      this.#pages.set(path, handler);
    }

    api(path, handler, method = 'POST') {
      if (!this.#apis.has(path)) {
        this.#apis.set(path, new Map());
      }
      this.#apis.get(path).set(method.toUpperCase(), handler);
    }

    async run() {
      const server = createServer(async (req, res) => {
        const url = new URL(req.url, 'http://127.0.0.1');
        if (req.method !== 'GET' && token) {
          const provided = req.headers['x-sidecar-token'] || url.searchParams.get('token');
          if (provided !== token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'unauthorized' }));
            return;
          }
        }
        if (req.method === 'GET' && this.#pages.has(url.pathname)) {
          const out = await this.#pages.get(url.pathname)();
          res.writeHead(out.status || 200, { 'Content-Type': out.contentType, ...(out.headers || {}) });
          res.end(out.body);
          return;
        }
        if (this.#apis.has(url.pathname) && this.#apis.get(url.pathname).has(req.method)) {
          const body = req.method === 'GET' ? {} : await readJsonBody(req);
          const out = await this.#apis.get(url.pathname).get(req.method)(body);
          res.writeHead(out.status || 200, { 'Content-Type': out.contentType, ...(out.headers || {}) });
          res.end(out.body);
          return;
        }
        res.writeHead(404);
        res.end('Not found');
      });
      await new Promise((res) => {
        this.#server = server.listen(0, '127.0.0.1', () => {
          this.port = server.address().port;
          res();
        });
      });
      return server;
    }

    async close() {
      if (this.#server) {
        this.#server.closeAllConnections?.();
        await new Promise((res) => this.#server.close(res));
        this.#server = null;
      }
    }
  };
}

test('ARP-TC-025: Official sidecar.json, SingleFlight context isolation, real server.mjs routes/error sanitization, and real sidecar_sdk spawn', async () => {
  const sidecarJson = JSON.parse(
    readFileSync(join(ROOT, 'sidecars/remote-panel/sidecar.json'), 'utf8'),
  );
  assert.equal(sidecarJson.command, 'node');
  assert.deepEqual(sidecarJson.args, ['server.mjs']);
  assert.equal(sidecarJson.has_web_ui, true);
  assert.equal(sidecarJson.ui_config?.views?.[0]?.path, '/');
  assert.equal(sidecarJson.ui_config?.views?.[0]?.entrypoint, 'SIDECAR_UI_ENTRYPOINT_AUX_PANE');

  // F3: Verify RemoteOrchestrator SingleFlight isolates concurrent discovery by workspaceUris.
  let wsCalls = [];
  const isolatedOrch = new RemoteOrchestrator({
    discoveryPort: {
      async listPlugins(ctx) {
        const ws = (ctx.workspaceUris || []).join(',');
        wsCalls.push(ws);
        await new Promise((r) => setTimeout(r, 25));
        return [{ name: `plugin-${ws}`, path: `/p/${ws}`, disabled: false }];
      },
      async listSidecars() {
        return [];
      },
    },
    framePort: createAntigravityFrameAdapter({ allowedOrigins: ['https://host.example'] }),
  });
  const [snapA, snapB] = await Promise.all([
    isolatedOrch.discoverAuthoritativeState({ workspaceUris: ['file:///ws-a'] }),
    isolatedOrch.discoverAuthoritativeState({ workspaceUris: ['file:///ws-b'] }),
  ]);
  assert.equal(snapA.activePlugins.has('plugin-file:///ws-a'), true);
  assert.equal(snapA.activePlugins.has('plugin-file:///ws-b'), false);
  assert.equal(snapB.activePlugins.has('plugin-file:///ws-b'), true);
  assert.equal(snapB.activePlugins.has('plugin-file:///ws-a'), false);
  assert.equal(wsCalls.length, 2);
  isolatedOrch.dispose();

  const REAL_CSRF = 'real-sidecar-host-csrf-9999';
  const REAL_SIDECAR_TOKEN = 'secret-statusbar-token-8888';
  const UI_TOKEN = 'sidecar-ui-token-5555';
  let statusbarRunning = true;
  let compactCalls = 0;
  let getAllPluginsCalls = 0;
  let forceLsError = false;

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
    if (forceLsError) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'failed at http://u:p@127.0.0.1/?token=supersecret' }));
      return;
    }
    if (req.url.endsWith('/GetAllPlugins')) {
      getAllPluginsCalls += 1;
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

  // 1) Verify sidecar-host handlers make ONLY 1 discovery RPC pass per getState() and redact secrets cleanly.
  const handlers = createRemotePanelHandlers({
    lsAddress: `127.0.0.1:${lsSrv.port}`,
    csrfToken: REAL_CSRF,
    version: '1.1.0',
  });

  try {
    const beforeCalls = getAllPluginsCalls;
    const state = await handlers.getState({ workspaceUris: ['file:///workspace/demo'] });
    assert.equal(getAllPluginsCalls - beforeCalls, 1, 'getState must not perform duplicate GetAllPlugins RPC');
    assert.equal(state.ok, true);
    assert.equal(state.statusbarAvailable, true);
    assert.equal(state.plugins.length, 2);
    assert.equal(state.sidecars.length, 1);
    assert.ok(!JSON.stringify(state).includes(REAL_SIDECAR_TOKEN));
    assert.ok(!JSON.stringify(state).includes(REAL_CSRF));

    const telemetry = await handlers.relayStatusbar('/api/telemetry', {});
    assert.equal(telemetry.ok, true);
    assert.equal(telemetry.data.usedTokens, 42000);
    assert.equal(telemetry.data.maxTokenLimit, 200000);
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

    statusbarRunning = false;
    await assert.rejects(
      () => handlers.relayStatusbar('/api/telemetry', {}),
      (err) => err.statusCode === 503 && err.code === 'STATUSBAR_UNAVAILABLE',
    );
    statusbarRunning = true;
  } finally {
    handlers.dispose();
  }

  // 2) Verify real server.mjs createSidecarServer: degraded boot (missing env) + try/catch error sanitization.
  const degradedSrv = await createSidecarServer({
    SidecarAppClass: createTestSidecarAppClass({ token: UI_TOKEN }),
    ResponseClass: InMemoryResponse,
    env: {},
  });
  await degradedSrv.start();
  try {
    const healthRes = await fetch(`http://127.0.0.1:${degradedSrv.app.port}/api/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = await healthRes.json();
    assert.equal(healthJson.ok, true);
    assert.equal(healthJson.degraded, true);

    const stateRes = await fetch(`http://127.0.0.1:${degradedSrv.app.port}/api/state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': UI_TOKEN },
      body: JSON.stringify({}),
    });
    assert.equal(stateRes.status, 503);
    const stateJson = await stateRes.json();
    assert.equal(stateJson.code, 'HOST_NOT_CONFIGURED');
  } finally {
    await degradedSrv.close();
  }

  const liveSrv = await createSidecarServer({
    SidecarAppClass: createTestSidecarAppClass({ token: UI_TOKEN }),
    ResponseClass: InMemoryResponse,
    env: {
      ANTIGRAVITY_LS_ADDRESS: `127.0.0.1:${lsSrv.port}`,
      ANTIGRAVITY_CSRF_TOKEN: REAL_CSRF,
    },
  });
  await liveSrv.start();
  try {
    forceLsError = true;
    const errStateRes = await fetch(`http://127.0.0.1:${liveSrv.app.port}/api/state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': UI_TOKEN },
      body: JSON.stringify({}),
    });
    assert.equal(errStateRes.status, 502);
    const errStateJson = await errStateRes.json();
    assert.equal(errStateJson.ok, false);
    assert.ok(!JSON.stringify(errStateJson).includes('supersecret'));

    const errMcpRes = await fetch(`http://127.0.0.1:${liveSrv.app.port}/api/mcp/summary`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': UI_TOKEN },
      body: JSON.stringify({}),
    });
    assert.equal(errMcpRes.status, 502);
    forceLsError = false;
  } finally {
    await liveSrv.close();
  }

  // 3) If Antigravity's real sidecar_sdk is installed on this host, spawn real server.mjs process!
  const realSdkNodePath = findRealSidecarSdkNodePath();
  if (realSdkNodePath) {
    const child = spawn(process.execPath, [join(ROOT, 'sidecars/remote-panel/server.mjs')], {
      cwd: dirname(join(ROOT, 'sidecars/remote-panel/server.mjs')),
      env: {
        ...process.env,
        NODE_PATH: realSdkNodePath,
        ANTIGRAVITY_LS_ADDRESS: `127.0.0.1:${lsSrv.port}`,
        ANTIGRAVITY_CSRF_TOKEN: REAL_CSRF,
        ANTIGRAVITY_SIDECAR_WEB_PORT: '0',
        ANTIGRAVITY_SIDECAR_UI_TOKEN: UI_TOKEN,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    try {
      const boundPort = await new Promise((resolvePort, rejectPort) => {
        let out = '';
        let errOut = '';
        const timer = setTimeout(() => {
          rejectPort(new Error(`Timed out waiting for real sidecar_sdk server.mjs. stdout=${out} stderr=${errOut}`));
        }, 10000);
        child.stdout.on('data', (chunk) => {
          out += chunk.toString('utf8');
          const match = out.match(/listening on 127\.0\.0\.1:(\d+)/);
          if (match) {
            clearTimeout(timer);
            resolvePort(Number(match[1]));
          }
        });
        child.stderr.on('data', (chunk) => {
          errOut += chunk.toString('utf8');
        });
        child.on('exit', (code) => {
          clearTimeout(timer);
          rejectPort(new Error(`server.mjs exited early with code ${code}. stderr=${errOut}`));
        });
      });

      const preloadRes = await fetch(`http://127.0.0.1:${boundPort}/preload.js`);
      assert.equal(preloadRes.status, 200);
      assert.ok((await preloadRes.text()).includes('window.sidecar'));

      const unauthRes = await fetch(`http://127.0.0.1:${boundPort}/api/state`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(unauthRes.status, 401);

      const authRes = await fetch(`http://127.0.0.1:${boundPort}/api/state`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': UI_TOKEN },
        body: JSON.stringify({ workspaceUris: ['file:///real-sdk-ws'] }),
      });
      assert.equal(authRes.status, 200);
      const authJson = await authRes.json();
      assert.equal(authJson.ok, true);
      assert.equal(authJson.statusbarAvailable, true);
    } finally {
      child.kill();
    }
  }

  lsSrv.server.closeAllConnections?.();
  statusbarSrv.server.closeAllConnections?.();
  await new Promise((r) => lsSrv.server.close(r));
  await new Promise((r) => statusbarSrv.server.close(r));
});
