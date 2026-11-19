import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

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

test('ARP-TC-023: Playwright Chromium E2E verifies default window.fetch orchestrator.start/relayApi/DomOverlay, TrustedTypes CSP, Worker Blob, iframe load postMessage, and cross-origin DOMException', async () => {
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
    if (req.url === '/worker.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end("self.onmessage = (e) => self.postMessage('worker-pong:' + e.data);");
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
            allowedOrigins: [hostOrigin],
            policyName: 'arp-e2e-tt-policy',
          });
          const adapterB = createAntigravityFrameAdapter({
            allowedOrigins: [hostOrigin],
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

          runtime.orchestrator.dispose();
          crossIframe.remove();
          return results;
        };
      `);
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "require-trusted-types-for 'script'; trusted-types arp-e2e-tt-policy antigravity-remote-bridge-v1",
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
    assert.equal(e2eResult.isTrustedScriptURL, true);
    assert.equal(e2eResult.workerReply, 'worker-pong:ping');
    assert.deepEqual(e2eResult.mountedBridgeIds, [
      'ko-translator-overlay',
      'mcp-manager-slot',
      'statusbar-sidecar',
    ]);
    assert.equal(e2eResult.koOverlayStarted, true);
    assert.equal(e2eResult.koOverlayFallbackProvider, 'google-translate');
    assert.equal(e2eResult.koOverlayStrippedApiKey, true);
    assert.equal(e2eResult.telemetryUsedTokens, 54321);
    assert.equal(e2eResult.telemetryMaxLimit, 384000);
    assert.equal(e2eResult.inboundCount, 1);
    assert.equal(e2eResult.inboundType, 'toggle-aux-pane');
    assert.equal(e2eResult.inboundReceivedCount, 2);
    assert.equal(e2eResult.crossOriginErrorCode, 'CROSS_ORIGIN_IFRAME_DENIED');

    await context.close();
  } finally {
    await browser.close();
    await new Promise((r) => hostSrv.server.close(r));
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => sidecarSrv.server.close(r));
  }
});

test('ARP-TC-026: Playwright Desktop & Mobile (390x844 touch) E2E verifies strict CSP, zero horizontal overflow, 44px touch targets, preload token/theme sync, compact flow, and error retry', async () => {
  const uiDir = join(ROOT, 'sidecars/remote-panel/ui');
  const indexHtml = readFileSync(join(uiDir, 'index.html'), 'utf8');
  const stylesCss = readFileSync(join(uiDir, 'styles.css'), 'utf8');
  const appJs = readFileSync(join(uiDir, 'app.js'), 'utf8');

  const UI_TOKEN = 'pw-mobile-sidecar-token-7777';
  const STRICT_CSP =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'";

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
        fetch(url, options = {}) {
          const headers = new Headers(options.headers || {});
          headers.set('Content-Type', 'application/json');
          if (token) headers.set('X-Sidecar-Token', token);
          return fetch(url, { ...options, headers });
        },
        onWorkspaceChange() { return () => {}; }
      };
    })();
  `;

  let failNextState = false;
  let compactCalls = 0;

  const panelSrv = await startHttpServer((req, res) => {
    const parsed = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && parsed.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': STRICT_CSP });
      res.end(indexHtml);
      return;
    }
    if (req.method === 'GET' && parsed.pathname === '/styles.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8', 'Content-Security-Policy': STRICT_CSP });
      res.end(stylesCss);
      return;
    }
    if (req.method === 'GET' && parsed.pathname === '/app.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Content-Security-Policy': STRICT_CSP });
      res.end(appJs);
      return;
    }
    if (req.method === 'GET' && parsed.pathname === '/preload.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end(preloadShim);
      return;
    }
    if (req.method === 'GET' && parsed.pathname === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.headers['x-sidecar-token'] !== UI_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }

    if (parsed.pathname === '/api/state') {
      if (failNextState) {
        failNextState = false;
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'temporary gateway error' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        version: '1.1.0',
        mountedBridgeIds: ['statusbar-sidecar', 'mcp-manager-slot'],
        statusbarAvailable: true,
        plugins: [{ name: 'antigravity-statusbar', dir: 'antigravity-statusbar', enabled: true, isGlobal: true }],
        sidecars: [{ sidecarId: 'antigravity-statusbar/statusbar', pluginName: 'antigravity-statusbar', running: true }],
      }));
      return;
    }
    if (parsed.pathname === '/api/mcp/summary') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        slotMounted: true,
        mcpPluginActive: true,
        remoteStdioPolicy: 'explicit-confirmation-required',
        protectedConfigGuard: 'enabled',
        secretsRedacted: true,
      }));
      return;
    }
    if (parsed.pathname === '/api/statusbar/telemetry') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, data: { usedTokens: 60000, maxTokenLimit: 200000 } }));
      return;
    }
    if (parsed.pathname === '/api/statusbar/compact') {
      compactCalls += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, data: { compacted: true } }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const browser = await launchChromium();
  try {
    const profiles = [
      { name: 'desktop', viewport: { width: 1280, height: 800 }, isMobile: false, hasTouch: false },
      { name: 'mobile', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true },
    ];

    for (const profile of profiles) {
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

      await page.goto(`http://127.0.0.1:${panelSrv.port}/?token=${UI_TOKEN}`, { waitUntil: 'networkidle' });
      await page.waitForFunction(
        () => document.getElementById('connection-badge')?.dataset?.state === 'ok',
      );

      // Verify zero horizontal overflow and >= 44px touch targets on primary controls.
      const layout = await page.evaluate(() => {
        const overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
        const heights = ['#refresh-btn', '#compact-btn', '#tab-statusbar', '#tab-plugins', '#tab-diagnostics']
          .map((sel) => document.querySelector(sel).getBoundingClientRect().height);
        return { overflow, minButtonHeight: Math.min(...heights) };
      });
      assert.ok(layout.overflow <= 0, `${profile.name}: unexpected horizontal overflow (${layout.overflow}px)`);
      assert.ok(layout.minButtonHeight >= 44, `${profile.name}: touch target height < 44px (${layout.minButtonHeight}px)`);

      // Verify telemetry summary rendered.
      const summaryText = await page.textContent('#telemetry-summary');
      assert.ok(summaryText.includes('60,000') && summaryText.includes('30%'), `${profile.name}: telemetry summary mismatch (${summaryText})`);

      // Verify theme-change CSS variable sync via preload.js.
      await page.evaluate(() => {
        window.postMessage({ type: 'theme-change', payload: { cssVariables: { '--background': 'rgb(18, 22, 28)' } } }, '*');
      });
      const appliedBg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--background').trim());
      assert.equal(appliedBg, 'rgb(18, 22, 28)');

      // Verify compact action button works.
      const beforeCompact = compactCalls;
      await page.click('#compact-btn');
      await page.waitForFunction(
        () => document.getElementById('action-feedback')?.textContent?.includes('완료'),
      );
      assert.equal(compactCalls, beforeCompact + 1);

      // Verify tab navigation renders Plugins and Diagnostics panels.
      await page.click('#tab-plugins');
      const pluginText = await page.textContent('#plugins-list');
      assert.ok(pluginText.includes('antigravity-statusbar'));

      await page.click('#tab-diagnostics');
      const diagText = await page.textContent('#diagnostics-list');
      assert.ok(diagText.includes('explicit-confirmation-required'));

      // Assert 0 browser/CSP/console errors before triggering intentional 500 retry check.
      assert.deepEqual(errors, [], `${profile.name}: unexpected browser/CSP errors`);

      // Verify error banner & retry recovery flow.
      failNextState = true;
      await page.click('#refresh-btn');
      await page.waitForFunction(() => !document.getElementById('error-banner').hidden);
      await page.click('#retry-btn');
      await page.waitForFunction(() => document.getElementById('error-banner').hidden && document.getElementById('connection-badge')?.dataset?.state === 'ok');

      const unexpectedAfterRetry = errors.filter((msg) => !msg.includes('status of 500'));
      assert.deepEqual(unexpectedAfterRetry, [], `${profile.name}: unexpected errors during retry`);
      await context.close();
    }
  } finally {
    await browser.close();
    await new Promise((r) => panelSrv.server.close(r));
  }
});
