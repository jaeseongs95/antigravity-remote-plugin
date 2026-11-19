import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { createSidecarServer } from '../sidecars/remote-panel/server.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function findSystemBrowserExecutable() {
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

async function launchChromium() {
  const pwExec = chromium.executablePath();
  const launchOptions = {
    headless: true,
    args: process.platform === 'linux' ? ['--no-sandbox', '--disable-dev-shm-usage'] : [],
  };
  if (pwExec && existsSync(pwExec)) {
    return chromium.launch(launchOptions);
  }
  const systemBin = findSystemBrowserExecutable();
  assert.ok(systemBin, 'Playwright Chromium or system Chrome/Edge executable is required for E2E tests');
  return chromium.launch({ ...launchOptions, executablePath: systemBin });
}

function startHttpServer(handler) {
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

class E2EResponse {
  constructor(body, { contentType = 'text/plain', status = 200, headers = {} } = {}) {
    this.body = body;
    this.contentType = contentType;
    this.status = status;
    this.headers = headers;
  }
}

function createE2ESidecarAppClass({ token, preloadJs }) {
  return class E2ESidecarApp {
    #pages = new Map();
    #apis = new Map();
    #server = null;
    port = 0;

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
      this.#pages.set('/preload.js', () => new E2EResponse(preloadJs, {
        contentType: 'application/javascript; charset=utf-8',
      }));
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
        await new Promise((res) => this.#server.close(res));
        this.#server = null;
      }
    }
  };
}

test('ARP-TC-023: Playwright Chromium E2E verifies default window.fetch orchestrator, TrustedTypes reuse, Worker Blob, iframe load/postMessage/SOURCE_MISMATCH, same-origin ORIGIN_MISMATCH & promotion, dispose(), and cross-origin DOMException', async () => {
  const bundleSource = readFileSync(join(ROOT, 'dist/remote_bridge.js'), 'utf8');
  const REAL_CSRF = 'real-browser-csrf-token-1234';
  const REAL_SIDECAR_TOKEN = 'sc-browser-tok-9999';

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-codeium-csrf-token, X-Sidecar-Token',
  };

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

  const lsSrv = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders);
      res.end();
      return;
    }
    if (req.headers['x-codeium-csrf-token'] !== REAL_CSRF) {
      res.writeHead(403, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid csrf' }));
      return;
    }
    if (req.url.endsWith('/GetAllPlugins')) {
      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        plugins: [
          { name: 'antigravity-ko-translator', path: '/plugins/antigravity-ko-translator', disabled: false },
          { name: 'antigravity-statusbar', path: '/plugins/antigravity-statusbar', disabled: false },
          { name: 'antigravity-mcp-manager', path: '/plugins/antigravity-mcp-manager', disabled: false },
        ],
      }));
      return;
    }
    if (req.url.endsWith('/GetSidecars')) {
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
    res.writeHead(404, corsHeaders);
    res.end();
  });

  let hostPort = 0;
  const hostSrv = await startHttpServer((req, res) => {
    if (req.url === '/remote_bridge.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end(bundleSource);
      return;
    }
    if (req.url === '/same-origin-frame') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><html><body><div id="same-frame">ok</div></body></html>');
      return;
    }
    if (req.url === '/harness.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end(`
        import {
          bootstrapAntigravityRemoteBridge,
          createAntigravityFrameAdapter,
        } from '/remote_bridge.js';

        window.__runE2E = async ({ sidecarPort, lsPort, csrfToken, hostOrigin }) => {
          const results = {};

          const adapterA = createAntigravityFrameAdapter({
            allowedOrigins: [hostOrigin, 'https://other.allowed.example'],
            policyName: 'arp-e2e-tt-policy',
          });
          const adapterB = createAntigravityFrameAdapter({
            allowedOrigins: [hostOrigin, 'https://other.allowed.example'],
            policyName: 'arp-e2e-tt-policy',
          });
          results.trustedTypesReused = Boolean(
            adapterA.trustedTypesPolicy &&
            adapterB.trustedTypesPolicy &&
            adapterA.trustedTypesPolicy.isNative === true &&
            adapterB.trustedTypesPolicy.isNative === true &&
            adapterA.trustedTypesPolicy.name === 'arp-e2e-tt-policy' &&
            adapterB.trustedTypesPolicy.name === 'arp-e2e-tt-policy'
          );

          const guardedBlobUrl = adapterA.createSafeWorkerBlobUrl({
            scriptUrl: hostOrigin + '/worker.js',
            createBlobUrl: () => URL.createObjectURL(
              new Blob(["self.onmessage = (e) => self.postMessage('worker-pong:' + e.data);"], { type: 'application/javascript' })
            ),
          });
          results.isTrustedScriptURL =
            typeof window.TrustedScriptURL === 'function' && guardedBlobUrl instanceof window.TrustedScriptURL;

          const workerReply = await new Promise((resolveWorker, rejectWorker) => {
            const w = new Worker(guardedBlobUrl);
            w.onmessage = (e) => { w.terminate(); resolveWorker(e.data); };
            w.onerror = (e) => { w.terminate(); rejectWorker(new Error(e.message || 'Worker error')); };
            w.postMessage('ping');
          });
          results.workerReply = workerReply;

          const receivedInbound = [];
          let koOverlayStarted = false;
          let koOverlaySettings = null;
          const runtime = bootstrapAntigravityRemoteBridge({
            lsAddress: '127.0.0.1:' + lsPort,
            csrfToken,
            allowedOrigins: [hostOrigin],
            initialFrame: { win: window, doc: document, origin: hostOrigin },
            initialThemeVariables: { '--bg': '#111' },
            initialWorkspaceUris: ['file:///e2e-ws'],
            readSettingsFile: async () => ({ provider: 'local-llm', apiKey: 'secret-should-strip' }),
            createKoTranslator: ({ settings }) => ({
              start() { koOverlayStarted = true; koOverlaySettings = settings; },
              dispose() { koOverlayStarted = false; },
            }),
            onSidecarEvent: (evt) => receivedInbound.push(evt),
          });

          // F4-4: Second bootstrapAntigravityRemoteBridge reuses default policy 'antigravity-remote-bridge-v1' without TypeError.
          const runtimeSecond = bootstrapAntigravityRemoteBridge({
            lsAddress: '127.0.0.1:' + lsPort,
            csrfToken,
            allowedOrigins: [hostOrigin],
          });
          results.defaultPolicyReused = Boolean(
            runtime.framePort.trustedTypesPolicy.name === 'antigravity-remote-bridge-v1' &&
            runtimeSecond.framePort.trustedTypesPolicy.name === 'antigravity-remote-bridge-v1' &&
            runtimeSecond.framePort.trustedTypesPolicy.isNative === true
          );
          runtimeSecond.orchestrator.dispose();

          const startResult = await runtime.orchestrator.start();
          results.mountedBridgeIds = [...startResult.mountedIds].sort();
          results.koOverlayStarted = koOverlayStarted;
          results.koOverlayFallbackProvider = koOverlaySettings?.provider || null;
          results.koOverlayStrippedApiKey = !('apiKey' in (koOverlaySettings || {}));

          const telemetry = await runtime.bridges.statusbar.relayApi('/api/telemetry', {});
          results.telemetryUsedTokens = telemetry.usedTokens;
          results.telemetryMaxLimit = telemetry.maxTokenLimit;

          const deadline = Date.now() + 5000;
          while (receivedInbound.length === 0 && Date.now() < deadline) {
            await new Promise((r) => setTimeout(r, 25));
          }
          results.inboundCount = receivedInbound.length;
          results.inboundType = receivedInbound[0]?.type || null;
          results.inboundReceivedCount = receivedInbound[0]?.payload?.receivedCount || 0;

          // F4-1: Spoofed source postMessage must be blocked with SOURCE_MISMATCH.
          const spoofRes = runtime.bridges.statusbar.handleInboundMessage({
            origin: 'http://127.0.0.1:' + sidecarPort,
            source: window,
            data: { type: 'toggle-aux-pane', payload: { spoofed: true } },
          });
          results.spoofBlockedReason = spoofRes.reason;

          // F4-2: Same-origin iframe ORIGIN_MISMATCH rejection and valid promotion.
          const sameIframe = document.createElement('iframe');
          sameIframe.src = hostOrigin + '/same-origin-frame';
          await new Promise((r) => {
            sameIframe.addEventListener('load', r, { once: true });
            document.body.appendChild(sameIframe);
          });
          let mismatchCode = null;
          try {
            adapterA.promoteRemoteIframe(sameIframe, { targetOrigin: 'https://other.allowed.example' });
          } catch (err) {
            mismatchCode = err.code || err.name;
          }
          results.sameOriginMismatchCode = mismatchCode;
          const promotedSame = adapterA.promoteRemoteIframe(sameIframe, { targetOrigin: hostOrigin });
          results.sameOriginPromoted = Boolean(promotedSame && promotedSame.origin === hostOrigin && promotedSame.doc);

          const crossIframe = document.createElement('iframe');
          crossIframe.src = 'http://127.0.0.1:' + sidecarPort + '/';
          await new Promise((r) => {
            crossIframe.addEventListener('load', r, { once: true });
            document.body.appendChild(crossIframe);
          });
          let crossErrorCode = null;
          try {
            adapterA.promoteRemoteIframe(crossIframe, { targetOrigin: 'http://127.0.0.1:' + sidecarPort });
          } catch (err) {
            crossErrorCode = err.code || err.name;
          }
          results.crossOriginErrorCode = crossErrorCode;

          // F4-3: dispose() must tear down overlay (koOverlayStarted === false).
          runtime.orchestrator.dispose();
          results.koOverlayAfterDispose = koOverlayStarted;

          sameIframe.remove();
          crossIframe.remove();
          return results;
        };
      `);
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy':
        "require-trusted-types-for 'script'; trusted-types arp-e2e-tt-policy antigravity-remote-bridge-v1; base-uri 'self'",
    });
    res.end('<!doctype html><html><head><script type="module" src="/harness.js"></script></head><body></body></html>');
  });
  hostPort = hostSrv.port;

  const browser = await launchChromium();
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', (err) => pageErrors.push(err.message));

    const hostOrigin = `http://localhost:${hostPort}`;
    await page.goto(`${hostOrigin}/`, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => typeof window.__runE2E === 'function');

    const e2eResult = await page.evaluate(
      (params) => window.__runE2E(params),
      { sidecarPort: sidecarSrv.port, lsPort: lsSrv.port, csrfToken: REAL_CSRF, hostOrigin },
    );

    assert.deepEqual(pageErrors, []);
    assert.equal(e2eResult.trustedTypesReused, true);
    assert.equal(e2eResult.defaultPolicyReused, true);
    assert.equal(e2eResult.isTrustedScriptURL, true);
    assert.equal(e2eResult.workerReply, 'worker-pong:ping');
    assert.deepEqual(e2eResult.mountedBridgeIds, [
      'ko-translator-overlay',
      'mcp-manager-slot',
      'statusbar-sidecar',
    ]);
    assert.equal(e2eResult.koOverlayStarted, true);
    assert.equal(e2eResult.koOverlayAfterDispose, false);
    assert.equal(e2eResult.koOverlayFallbackProvider, 'google-translate');
    assert.equal(e2eResult.koOverlayStrippedApiKey, true);
    assert.equal(e2eResult.telemetryUsedTokens, 54321);
    assert.equal(e2eResult.telemetryMaxLimit, 384000);
    assert.equal(e2eResult.inboundCount, 1);
    assert.equal(e2eResult.inboundType, 'toggle-aux-pane');
    assert.equal(e2eResult.inboundReceivedCount, 2);
    assert.equal(e2eResult.spoofBlockedReason, 'SOURCE_MISMATCH');
    assert.equal(e2eResult.sameOriginMismatchCode, 'ORIGIN_MISMATCH');
    assert.equal(e2eResult.sameOriginPromoted, true);
    assert.equal(e2eResult.crossOriginErrorCode, 'CROSS_ORIGIN_IFRAME_DENIED');

    await context.close();
  } finally {
    await browser.close();
    await new Promise((r) => hostSrv.server.close(r));
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => sidecarSrv.server.close(r));
  }
});

test('ARP-TC-026: Playwright Desktop & Mobile (390x844 touch) E2E via real server.mjs verifies CSP, all-tab overflow, 44px touch targets, initial workspaceUris, keyboard tabs, compact disabled guard, and retry', async () => {
  const REAL_CSRF = 'e2e-real-server-csrf-1234';
  const REAL_SIDECAR_TOKEN = 'e2e-statusbar-tok-9999';
  const UI_TOKEN = 'pw-mobile-sidecar-token-7777';

  let statusbarRunning = true;
  let disableStatusbarAfterCompact = false;
  let failNextLs = false;
  let compactCalls = 0;
  const seenStateRequests = [];

  const statusbarSrv = await startHttpServer(async (req, res) => {
    if (req.headers['x-sidecar-token'] !== REAL_SIDECAR_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    await readJsonBody(req);
    if (req.url === '/api/telemetry') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ usedTokens: 60000, maxTokenLimit: 200000 }));
      return;
    }
    if (req.url === '/api/compact') {
      compactCalls += 1;
      if (disableStatusbarAfterCompact) {
        statusbarRunning = false;
        disableStatusbarAfterCompact = false;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ compacted: true }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const lsSrv = await startHttpServer(async (req, res) => {
    if (req.headers['x-codeium-csrf-token'] !== REAL_CSRF) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'forbidden' }));
      return;
    }
    const body = await readJsonBody(req);
    if (failNextLs) {
      failNextLs = false;
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'temporary gateway error' }));
      return;
    }
    if (req.url.endsWith('/GetAllPlugins')) {
      seenStateRequests.push({
        workspaceUris: body.workspaceUris || [],
        contentType: req.headers['content-type'] || '',
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        plugins: [
          { name: 'antigravity-statusbar', path: '/plugins/antigravity-statusbar', disabled: false, isGlobal: true },
          { name: 'antigravity-mcp-manager', path: '/plugins/antigravity-mcp-manager', disabled: false, isGlobal: true },
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

  const preloadShim = `
    (function() {
      const token = new URLSearchParams(window.location.search).get('token');
      window.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'theme-change') {
          for (const [k, v] of Object.entries(event.data.payload.cssVariables || {})) {
            document.documentElement.style.setProperty(k, v);
          }
        }
      });
      window.sidecar = {
        async getWorkspaceUris() {
          return ['file:///initial-e2e-workspace'];
        },
        fetch(url, options = {}) {
          const headers = new Headers(options.headers || {});
          if (token) headers.set('X-Sidecar-Token', token);
          window.__lastFetchContentType = headers.get('Content-Type') || '';
          return fetch(url, { ...options, headers });
        },
        onWorkspaceChange() { return () => {}; }
      };
    })();
  `;

  const sidecarServer = await createSidecarServer({
    SidecarAppClass: createE2ESidecarAppClass({ token: UI_TOKEN, preloadJs: preloadShim }),
    ResponseClass: E2EResponse,
    env: {
      ANTIGRAVITY_LS_ADDRESS: `127.0.0.1:${lsSrv.port}`,
      ANTIGRAVITY_CSRF_TOKEN: REAL_CSRF,
    },
  });
  await sidecarServer.start();

  const browser = await launchChromium();
  try {
    const profiles = [
      { name: 'desktop', viewport: { width: 1280, height: 800 }, isMobile: false, hasTouch: false },
      { name: 'mobile', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true },
    ];

    for (const profile of profiles) {
      statusbarRunning = true;
      disableStatusbarAfterCompact = false;
      failNextLs = false;
      seenStateRequests.length = 0;

      const context = await browser.newContext({
        viewport: profile.viewport,
        isMobile: profile.isMobile,
        hasTouch: profile.hasTouch,
      });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (err) => errors.push(`pageerror: ${err.message}`));
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(`console.error: ${msg.text()}`);
        }
      });

      await page.goto(`http://127.0.0.1:${sidecarServer.app.port}/?token=${UI_TOKEN}`, { waitUntil: 'networkidle' });
      await page.waitForFunction(
        () => document.getElementById('connection-badge')?.dataset?.state === 'ok',
      );

      // F2: Verify initial getWorkspaceUris() was sent on first load and Content-Type header was set.
      assert.deepEqual(seenStateRequests[0]?.workspaceUris, ['file:///initial-e2e-workspace']);
      const lastCt = await page.evaluate(() => window.__lastFetchContentType);
      assert.equal(lastCt, 'application/json');

      // NB3: Check horizontal overflow across ALL 3 tabs + >= 44px touch targets.
      const checkOverflow = () =>
        page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

      assert.ok((await checkOverflow()) <= 0, `${profile.name}: overflow on statusbar tab`);
      const minBtnHeight = await page.evaluate(() => {
        const heights = ['#refresh-btn', '#compact-btn', '#tab-statusbar', '#tab-plugins', '#tab-diagnostics']
          .map((sel) => document.querySelector(sel).getBoundingClientRect().height);
        return Math.min(...heights);
      });
      assert.ok(minBtnHeight >= 44, `${profile.name}: touch target height < 44px (${minBtnHeight}px)`);

      const summaryText = await page.textContent('#telemetry-summary');
      assert.ok(summaryText.includes('60,000') && summaryText.includes('30%'));

      // Verify theme-change CSS variable sync via preload.js.
      await page.evaluate(() => {
        window.postMessage({ type: 'theme-change', payload: { cssVariables: { '--background': 'rgb(18, 22, 28)' } } }, '*');
      });
      const appliedBg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--background').trim());
      assert.equal(appliedBg, 'rgb(18, 22, 28)');

      // NB3: Keyboard ArrowRight tab navigation across Plugins & Diagnostics + overflow checks.
      await page.focus('#tab-statusbar');
      await page.keyboard.press('ArrowRight');
      assert.equal(await page.getAttribute('#tab-plugins', 'aria-selected'), 'true');
      assert.ok((await checkOverflow()) <= 0, `${profile.name}: overflow on plugins tab`);
      assert.ok((await page.textContent('#plugins-list')).includes('antigravity-statusbar'));

      await page.keyboard.press('ArrowRight');
      assert.equal(await page.getAttribute('#tab-diagnostics', 'aria-selected'), 'true');
      assert.ok((await checkOverflow()) <= 0, `${profile.name}: overflow on diagnostics tab`);
      assert.ok((await page.textContent('#diagnostics-list')).includes('explicit-confirmation-required'));

      await page.keyboard.press('ArrowRight');
      assert.equal(await page.getAttribute('#tab-statusbar', 'aria-selected'), 'true');

      // F2: Verify compact action keeps #compact-btn disabled when statusbar becomes inactive during post-compact refresh.
      const beforeCompact = compactCalls;
      disableStatusbarAfterCompact = true;
      await page.click('#compact-btn');
      await page.waitForFunction(
        () => document.getElementById('telemetry-summary')?.textContent?.includes('비활성'),
      );
      assert.equal(compactCalls, beforeCompact + 1);
      assert.equal(await page.isDisabled('#compact-btn'), true, `${profile.name}: compact-btn must stay disabled when statusbar becomes inactive`);

      assert.deepEqual(errors, [], `${profile.name}: unexpected browser/CSP errors`);

      // Verify error banner, #retry-btn >= 44px height, and retry recovery.
      statusbarRunning = true;
      failNextLs = true;
      await page.click('#refresh-btn');
      await page.waitForFunction(() => !document.getElementById('error-banner').hidden);
      const retryHeight = await page.evaluate(() => document.getElementById('retry-btn').getBoundingClientRect().height);
      assert.ok(retryHeight >= 44, `${profile.name}: retry-btn height < 44px (${retryHeight}px)`);
      await page.click('#retry-btn');
      await page.waitForFunction(() => document.getElementById('error-banner').hidden && document.getElementById('connection-badge')?.dataset?.state === 'ok');

      const unexpectedAfterRetry = errors.filter((msg) => !msg.includes('status of 502'));
      assert.deepEqual(unexpectedAfterRetry, [], `${profile.name}: unexpected errors during retry`);
      await context.close();
    }
  } finally {
    await browser.close();
    await sidecarServer.close();
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => statusbarSrv.server.close(r));
  }
});
