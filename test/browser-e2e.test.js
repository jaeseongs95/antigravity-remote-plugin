import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function findBrowserExecutable() {
  const envBin = process.env.CHROME_BIN || process.env.CHROMIUM_BIN;
  if (envBin && existsSync(envBin)) {
    return envBin;
  }
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
          'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        ]
      : [
          '/usr/bin/google-chrome',
          '/usr/bin/google-chrome-stable',
          '/usr/bin/chromium',
          '/usr/bin/chromium-browser',
          '/snap/bin/chromium',
        ];
  for (const bin of candidates) {
    if (existsSync(bin)) {
      return bin;
    }
  }
  return null;
}

function startHttpServer(handler) {
  return new Promise((resolveSrv) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      resolveSrv({ server, port: server.address().port });
    });
  });
}

function launchHeadlessChromium(binPath, userDataDir) {
  return new Promise((resolveProc, rejectProc) => {
    const args = [
      '--headless=new',
      '--remote-debugging-port=0',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--disable-extensions',
      '--disable-background-networking',
      `--user-data-dir=${userDataDir}`,
    ];
    if (process.platform === 'linux') {
      args.push('--no-sandbox', '--disable-dev-shm-usage');
    }
    args.push('about:blank');

    const child = spawn(binPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderrBuf = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill();
        rejectProc(new Error(`Timed out waiting for Chromium DevTools URL. stderr=${stderrBuf}`));
      }
    }, 15000);

    child.stderr.on('data', (chunk) => {
      stderrBuf += chunk.toString('utf8');
      const match = stderrBuf.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match && !settled) {
        settled = true;
        clearTimeout(timer);
        resolveProc({ child, wsUrl: match[1] });
      }
    });

    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        rejectProc(new Error(`Chromium exited early with code ${code}. stderr=${stderrBuf}`));
      }
    });
  });
}

async function createCdpSession(pageWsUrl) {
  const ws = new WebSocket(pageWsUrl);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res, { once: true });
    ws.addEventListener('error', (e) => rej(new Error(`CDP WS error: ${e.message || e}`)), { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  const eventWaiters = [];

  ws.addEventListener('message', (evt) => {
    const msg = JSON.parse(String(evt.data));
    if (msg.id && pending.has(msg.id)) {
      const { resolve: res, reject: rej } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) {
        rej(new Error(`CDP ${msg.error.code}: ${msg.error.message}`));
      } else {
        res(msg.result);
      }
      return;
    }
    if (msg.method) {
      for (let i = eventWaiters.length - 1; i >= 0; i -= 1) {
        if (eventWaiters[i].method === msg.method) {
          const waiter = eventWaiters.splice(i, 1)[0];
          waiter.resolve(msg.params);
        }
      }
    }
  });

  function send(method, params = {}) {
    const id = nextId++;
    return new Promise((res, rej) => {
      pending.set(id, { resolve: res, reject: rej });
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  function waitForEvent(method, timeoutMs = 10000) {
    return new Promise((res, rej) => {
      const entry = { method, resolve: (p) => { clearTimeout(t); res(p); } };
      const t = setTimeout(() => {
        const idx = eventWaiters.indexOf(entry);
        if (idx !== -1) eventWaiters.splice(idx, 1);
        rej(new Error(`Timed out waiting for CDP event ${method}`));
      }, timeoutMs);
      eventWaiters.push(entry);
    });
  }

  return { send, waitForEvent, close: () => ws.close() };
}

test('ARP-TC-023: Real Chromium E2E verifies default window.fetch orchestrator.start/relayApi/DomOverlay, TrustedTypes CSP, Worker Blob, iframe load postMessage, and cross-origin DOMException', async () => {
  const browserBin = findBrowserExecutable();
  assert.ok(browserBin, 'A Chromium/Chrome/Edge executable is required for ARP-TC-023 browser E2E');

  const bundleSource = readFileSync(join(ROOT, 'dist/remote_bridge.js'), 'utf8');
  const REAL_CSRF = 'real-browser-csrf-token-1234';
  const REAL_SIDECAR_TOKEN = 'sc-browser-tok-9999';

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-codeium-csrf-token, X-Sidecar-Token',
  };

  // 1) Sidecar server (different loopback port) serving both real iframe HTML and JSON APIs.
  const sidecarSrv = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders);
      res.end();
      return;
    }
    if (req.url === '/api/telemetry') {
      if (req.headers['x-sidecar-token'] !== REAL_SIDECAR_TOKEN) {
        res.writeHead(401, { ...corsHeaders, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ usedTokens: 54321, maxTokenLimit: 384000 }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><html><body><script>
      window.__received = [];
      window.addEventListener('message', (e) => {
        window.__received.push({ origin: e.origin, data: e.data });
        if (e.data && e.data.type === 'workspace-change') {
          window.parent.postMessage({
            type: 'toggle-aux-pane',
            payload: { open: true, receivedCount: window.__received.length }
          }, e.origin);
        }
      });
    </script></body></html>`);
  });

  // 2) Real LanguageServer Connect RPC server for Chromium default window.fetch discovery.
  const lsSrv = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders);
      res.end();
      return;
    }
    if (req.headers['x-codeium-csrf-token'] !== REAL_CSRF) {
      res.writeHead(403, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'forbidden' }));
      return;
    }
    if (req.url === '/exa.language_server_pb.LanguageServerService/GetAllPlugins') {
      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        plugins: [
          { name: 'antigravity-statusbar', path: '/p/antigravity-statusbar', disabled: false },
          { name: 'antigravity-ko-translator', path: '/p/ko-thought-translator', disabled: false },
        ],
      }));
      return;
    }
    if (req.url === '/exa.language_server_pb.LanguageServerService/GetSidecars') {
      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
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
      }));
      return;
    }
    res.writeHead(404, { ...corsHeaders, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  // 3) Cross-origin server (accessed via http://localhost:<port>, different origin from 127.0.0.1).
  const crossOriginSrv = await startHttpServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><html><body>cross-origin-frame</body></html>');
  });

  // 4) Host server enforcing strict TrustedTypes CSP & serving dist/remote_bridge.js.
  const hostSrv = await startHttpServer((req, res) => {
    if (req.url === '/remote_bridge.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end(bundleSource);
      return;
    }
    if (req.url === '/same-origin-frame.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><html><body><div id="inner">same-origin</div></body></html>');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy':
        "require-trusted-types-for 'script'; trusted-types antigravity-remote-bridge-v1; base-uri 'self'",
    });
    res.end('<!doctype html><html><body><div id="root"></div></body></html>');
  });

  const userDataDir = mkdtempSync(join(tmpdir(), 'arp-chrome-e2e-'));
  let child = null;
  let cdp = null;

  try {
    const launched = await launchHeadlessChromium(browserBin, userDataDir);
    child = launched.child;

    const debugPort = new URL(launched.wsUrl).port;
    const targetsRes = await fetch(`http://127.0.0.1:${debugPort}/json`);
    const targets = await targetsRes.json();
    const pageTarget = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    assert.ok(pageTarget, 'Expected a Chromium page target');

    cdp = await createCdpSession(pageTarget.webSocketDebuggerUrl);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');

    const loadPromise = cdp.waitForEvent('Page.loadEventFired');
    await cdp.send('Page.navigate', { url: `http://127.0.0.1:${hostSrv.port}/` });
    await loadPromise;

    const evalExpr = `(async () => {
      const mod = await import('/remote_bridge.js');
      const hostOrigin = window.location.origin;
      const lsPort = ${lsSrv.port};
      const sidecarPort = ${sidecarSrv.port};
      const crossPort = ${crossOriginSrv.port};

      const inbound = [];
      const overlayLog = [];

      // IMPORTANT (C2): Do NOT pass fetchImpl -> exercises real Chromium window.fetch!
      const app1 = mod.bootstrapAntigravityRemoteBridge({
        lsAddress: '127.0.0.1:' + lsPort,
        csrfToken: '${REAL_CSRF}',
        allowedOrigins: [hostOrigin, 'https://antigravity.google.com'],
        readSettingsFile: async () => ({ provider: 'local-llm', translateThinking: true }),
        initialThemeVariables: { '--background': '#101418' },
        initialWorkspaceUris: ['file:///workspace/e2e'],
        initialFrame: { win: window, doc: document, origin: hostOrigin, conversationId: 'conv-browser-1' },
        createKoTranslator: ({ win, doc, settings }) => ({
          start() { overlayLog.push({ event: 'start', provider: settings.provider, hasDom: Boolean(win && doc) }); },
          dispose() { overlayLog.push({ event: 'dispose' }); },
        }),
        onSidecarEvent: (evt) => inbound.push(evt),
      });

      // Re-initialization with the same fixed policy name must reuse cached policy (no duplicate TypeError).
      const app2 = mod.bootstrapAntigravityRemoteBridge({
        lsAddress: '127.0.0.1:' + lsPort,
        csrfToken: '${REAL_CSRF}',
        allowedOrigins: [hostOrigin],
      });

      const isNativeTT = app1.framePort.trustedTypesPolicy.isNative === true
        && app2.framePort.trustedTypesPolicy.isNative === true;

      // Worker Blob URL under strict require-trusted-types-for 'script' CSP.
      const trustedBlobUrl = app1.framePort.createSafeWorkerBlobUrl({
        scriptUrl: hostOrigin + '/remote_bridge.js',
        createBlobUrl: () => URL.createObjectURL(new Blob(['self.postMessage("worker-pong");'], { type: 'application/javascript' })),
      });
      const isTrustedScriptUrl = window.trustedTypes.isScriptURL(trustedBlobUrl);
      const workerReply = await new Promise((resolve, reject) => {
        const w = new Worker(trustedBlobUrl);
        w.onmessage = (e) => { w.terminate(); resolve(e.data); };
        w.onerror = (e) => { w.terminate(); reject(new Error(e.message || 'worker error')); };
      });

      // Real orchestrator.start() using Chromium's default window.fetch (must NOT throw Illegal invocation).
      const startResult = await app1.orchestrator.start();

      // Real relayApi() using Chromium's default window.fetch + X-Sidecar-Token.
      const telemetry = await app1.bridges.statusbar.relayApi('/api/telemetry', { conversationId: 'conv-browser-1' });

      // Wait for real sidecar iframe load -> theme-change + workspace-change -> inbound toggle-aux-pane.
      const deadline = Date.now() + 5000;
      while (inbound.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }

      // Spoofed message with wrong source on the sidecar origin must be rejected.
      const spoofedResult = app1.bridges.statusbar.handleInboundMessage({
        origin: 'http://127.0.0.1:' + sidecarPort,
        source: window,
        data: { type: 'toggle-aux-pane', payload: { spoof: true } },
      });

      // Cross-origin iframe must throw SecurityPolicyError(CROSS_ORIGIN_IFRAME_DENIED), NOT raw DOMException.
      const crossIframe = document.createElement('iframe');
      crossIframe.src = 'http://localhost:' + crossPort + '/';
      await new Promise((resolve) => { crossIframe.addEventListener('load', resolve, { once: true }); document.body.appendChild(crossIframe); });
      let crossErrCode = null;
      try {
        app1.framePort.promoteRemoteIframe(crossIframe);
      } catch (err) {
        crossErrCode = err.code || err.name;
      }

      // Same-origin iframe with mismatched targetOrigin must throw ORIGIN_MISMATCH.
      const sameIframe = document.createElement('iframe');
      sameIframe.src = hostOrigin + '/same-origin-frame.html';
      await new Promise((resolve) => { sameIframe.addEventListener('load', resolve, { once: true }); document.body.appendChild(sameIframe); });
      let mismatchErrCode = null;
      try {
        app1.framePort.promoteRemoteIframe(sameIframe, { targetOrigin: 'https://antigravity.google.com' });
      } catch (err) {
        mismatchErrCode = err.code || err.name;
      }
      const promotedSame = app1.framePort.promoteRemoteIframe(sameIframe, { targetOrigin: hostOrigin });

      app1.orchestrator.dispose();
      app2.orchestrator.dispose();

      return {
        isNativeTT,
        isTrustedScriptUrl,
        workerReply,
        mountedIds: startResult.mountedIds,
        telemetryUsedTokens: telemetry.usedTokens,
        overlayLog,
        crossErrCode,
        mismatchErrCode,
        promotedOrigin: promotedSame.origin,
        inbound,
        spoofedResult,
      };
    })()`;

    const evalRes = await cdp.send('Runtime.evaluate', {
      expression: evalExpr,
      awaitPromise: true,
      returnByValue: true,
    });

    assert.equal(evalRes.exceptionDetails, undefined, `Browser eval threw: ${JSON.stringify(evalRes.exceptionDetails)}`);
    const result = evalRes.result.value;

    assert.equal(result.isNativeTT, true);
    assert.equal(result.isTrustedScriptUrl, true);
    assert.equal(result.workerReply, 'worker-pong');
    assert.deepEqual(result.mountedIds.sort(), ['ko-translator-overlay', 'statusbar-sidecar']);
    assert.equal(result.telemetryUsedTokens, 54321);
    assert.equal(result.overlayLog[0].event, 'start');
    assert.equal(result.overlayLog[0].provider, 'google-translate');
    assert.equal(result.overlayLog[0].hasDom, true);
    assert.equal(result.overlayLog[result.overlayLog.length - 1].event, 'dispose');
    assert.equal(result.crossErrCode, 'CROSS_ORIGIN_IFRAME_DENIED');
    assert.equal(result.mismatchErrCode, 'ORIGIN_MISMATCH');
    assert.equal(result.promotedOrigin, `http://127.0.0.1:${hostSrv.port}`);
    assert.equal(result.inbound.length, 1);
    assert.equal(result.inbound[0].type, 'toggle-aux-pane');
    assert.equal(result.inbound[0].payload.receivedCount, 2);
    assert.equal(result.spoofedResult.accepted, false);
    assert.equal(result.spoofedResult.reason, 'SOURCE_MISMATCH');
  } finally {
    if (cdp) {
      cdp.close();
    }
    if (child) {
      child.kill();
      await new Promise((r) => setTimeout(r, 200));
    }
    rmSync(userDataDir, { recursive: true, force: true });
    await new Promise((r) => hostSrv.server.close(r));
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => sidecarSrv.server.close(r));
    await new Promise((r) => crossOriginSrv.server.close(r));
  }
});
