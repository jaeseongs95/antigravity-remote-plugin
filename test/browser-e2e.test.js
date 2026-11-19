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

          const spoofRes = runtime.bridges.statusbar.handleInboundMessage({
            origin: 'http://127.0.0.1:' + sidecarPort,
            source: window,
            data: { type: 'toggle-aux-pane', payload: { spoofed: true } },
          });
          results.spoofBlockedReason = spoofRes.reason;

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
    hostSrv.server.closeAllConnections?.();
    lsSrv.server.closeAllConnections?.();
    sidecarSrv.server.closeAllConnections?.();
    await new Promise((r) => hostSrv.server.close(r));
    await new Promise((r) => lsSrv.server.close(r));
    await new Promise((r) => sidecarSrv.server.close(r));
  }
});

test('ARP-TC-026: Playwright Desktop & Mobile (390x844 touch) E2E injects real dist/antigravity-remote.user.js and dist/bookmarklet.txt to verify live DOM translation, code preservation, companion sidecar triggers, 44px touch targets, and 0 overflow', async () => {
  const userscriptSource = readFileSync(join(ROOT, 'dist/antigravity-remote.user.js'), 'utf8');
  const bookmarkletSource = readFileSync(join(ROOT, 'dist/bookmarklet.txt'), 'utf8').trim();
  assert.ok(bookmarkletSource.startsWith('javascript:'));
  const bookmarkletCode = bookmarkletSource.slice('javascript:'.length);

  const translateSrv = await startHttpServer((req, res) => {
    const parsed = new URL(req.url, 'http://127.0.0.1');
    const q = parsed.searchParams.get('q') || '';
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
    });
    res.end(JSON.stringify([[[`[번역] ${q}`, q, null, null, 10]]]));
  });

  const remoteWebSrv = await startHttpServer((req, res) => {
    if (req.url === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Antigravity Remote Mock</title>
      </head>
      <body style="margin:0;padding:16px;font-family:sans-serif;">
        <main>
          <p id="thought-1">Thinking about cross-device remote plugin architecture.</p>
          <pre id="code-pre">npm run verify</pre>
          <code id="code-inline">const untouched = 123;</code>
          <textarea id="chat-input">User draft prompt</textarea>
        </main>
        <script>
          window.__auxEvents = [];
          window.addEventListener('message', (e) => {
            if (e.data && e.data.type === 'toggle-aux-pane') {
              window.__auxEvents.push(e.data.payload);
            }
          });
        </script>
      </body>
      </html>`);
  });

  const browser = await launchChromium();
  try {
    const scenarios = [
      { mode: 'userscript', viewport: { width: 1280, height: 800 }, isMobile: false, hasTouch: false },
      { mode: 'bookmarklet', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true },
    ];

    for (const sc of scenarios) {
      const context = await browser.newContext({
        viewport: sc.viewport,
        isMobile: sc.isMobile,
        hasTouch: sc.hasTouch,
      });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (err) => errors.push(`pageerror: ${err.message}`));
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(`console.error: ${msg.text()}`);
        }
      });

      const remoteOrigin = `http://127.0.0.1:${remoteWebSrv.port}`;
      await page.goto(`${remoteOrigin}/`, { waitUntil: 'networkidle' });

      // Configure test origin allowlist & loopback mock translate endpoint.
      await page.evaluate(
        ({ origin, translatePort, withGm }) => {
          window.__ARP_ALLOWED_ORIGINS__ = [origin];
          window.__ARP_TRANSLATE_ENDPOINT__ = `http://127.0.0.1:${translatePort}/translate_a/single`;
          if (withGm) {
            window.GM_xmlhttpRequest = ({ url, onload, onerror }) => {
              fetch(url)
                .then(async (r) => onload({ status: r.status, responseText: await r.text() }))
                .catch((err) => onerror(err));
            };
          }
        },
        { origin: remoteOrigin, translatePort: translateSrv.port, withGm: sc.mode === 'userscript' },
      );

      // Inject REAL built artifact (userscript or bookmarklet).
      await page.addScriptTag({
        content: sc.mode === 'userscript' ? userscriptSource : bookmarkletCode,
      });

      // Wait for real DOM translation to finish.
      await page.waitForFunction(
        () => document.getElementById('thought-1')?.textContent?.startsWith('[번역]'),
      );

      // Verify code blocks and inputs were NEVER mutated.
      assert.equal(await page.textContent('#code-pre'), 'npm run verify');
      assert.equal(await page.textContent('#code-inline'), 'const untouched = 123;');
      assert.equal(await page.inputValue('#chat-input'), 'User draft prompt');

      // Open dock popover & verify 44px touch targets + 0 horizontal overflow.
      await page.click('#arp-dock-pill');
      const metrics = await page.evaluate(() => {
        const overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
        const heights = ['#arp-dock-pill', '#arp-toggle-translate', '#arp-open-statusbar', '#arp-open-mcp']
          .map((sel) => document.querySelector(sel).getBoundingClientRect().height);
        return { overflow, minHeight: Math.min(...heights) };
      });
      assert.ok(metrics.overflow <= 0, `${sc.mode}: horizontal overflow (${metrics.overflow}px)`);
      assert.ok(metrics.minHeight >= 44, `${sc.mode}: button height < 44px (${metrics.minHeight}px)`);

      // Toggle translation OFF -> original English prose restored immediately.
      await page.click('#arp-toggle-translate');
      assert.equal(
        await page.textContent('#thought-1'),
        'Thinking about cross-device remote plugin architecture.',
      );

      // Trigger Statusbar & MCP Manager companion sidecars.
      await page.click('#arp-open-statusbar');
      await page.click('#arp-open-mcp');
      await page.waitForFunction(() => window.__auxEvents.length === 2);
      const auxEvents = await page.evaluate(() => window.__auxEvents);
      assert.equal(auxEvents[0].sidecarId, 'antigravity-statusbar/statusbar');
      assert.equal(auxEvents[1].sidecarId, 'antigravity-mcp-manager/mcp_manager');

      // Escape closes popover and returns focus to pill button.
      await page.keyboard.press('Escape');
      assert.equal(await page.getAttribute('#arp-dock-pill', 'aria-expanded'), 'false');

      // Repeated bookmarklet execution toggles popover idempotently (no duplicate root).
      if (sc.mode === 'bookmarklet') {
        await page.addScriptTag({ content: bookmarkletCode });
        const rootCount = await page.evaluate(() => document.querySelectorAll('#arp-remote-dock-root-v2').length);
        assert.equal(rootCount, 1);
        assert.equal(await page.getAttribute('#arp-dock-pill', 'aria-expanded'), 'true');
      }

      assert.deepEqual(errors, [], `${sc.mode}: unexpected browser errors`);
      await context.close();
    }
  } finally {
    await browser.close();
    remoteWebSrv.server.closeAllConnections?.();
    translateSrv.server.closeAllConnections?.();
    await new Promise((r) => remoteWebSrv.server.close(r));
    await new Promise((r) => translateSrv.server.close(r));
  }
});
