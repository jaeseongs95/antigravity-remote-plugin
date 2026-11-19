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

// --- Chromium CDP helpers to inspect & interact with real Closed Shadow DOM (zero prod backdoors) ---

function getAttr(node, name) {
  const attrs = node?.attributes || [];
  for (let i = 0; i < attrs.length; i += 2) {
    if (attrs[i] === name) return attrs[i + 1];
  }
  return null;
}

function hasAttr(node, name) {
  const attrs = node?.attributes || [];
  for (let i = 0; i < attrs.length; i += 2) {
    if (attrs[i] === name) return true;
  }
  return false;
}

function walkCdpTree(node, visitor) {
  if (!node) return;
  visitor(node);
  for (const sr of node.shadowRoots || []) {
    walkCdpTree(sr, visitor);
  }
  for (const child of node.children || []) {
    walkCdpTree(child, visitor);
  }
}

function cdpNodeText(node) {
  if (!node) return '';
  if (node.nodeType === 3) return node.nodeValue || '';
  let out = '';
  for (const sr of node.shadowRoots || []) out += cdpNodeText(sr);
  for (const child of node.children || []) out += cdpNodeText(child);
  return out;
}

async function getPiercedRoot(cdp) {
  const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
  return root;
}

function findCdpNode(root, predicate) {
  let found = null;
  walkCdpTree(root, (n) => {
    if (!found && predicate(n)) found = n;
  });
  return found;
}

async function getCdpBox(cdp, node) {
  const { model } = await cdp.send('DOM.getBoxModel', { backendNodeId: node.backendNodeId });
  const q = model.border;
  const xs = [q[0], q[2], q[4], q[6]];
  const ys = [q[1], q[3], q[5], q[7]];
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  return {
    x: minX,
    y: minY,
    width: maxX - minX,
    height: maxY - minY,
    cx: (minX + maxX) / 2,
    cy: (minY + maxY) / 2,
  };
}

async function clickCdpNode(page, cdp, predicate) {
  const root = await getPiercedRoot(cdp);
  const node = findCdpNode(root, predicate);
  assert.ok(node, 'Expected node inside Closed Shadow DOM to exist');
  const box = await getCdpBox(cdp, node);
  await page.mouse.click(box.cx, box.cy);
  return { node, box };
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

test('ARP-TC-028: Playwright Desktop & Mobile (390x844 touch) E2E verifies untrusted origin spoofing fail-closed (Userscript + Bookmarklet), locked-down window.antigravityRemoteHost, and impenetrable Closed Shadow DOM via CDP (zero getSlotRoot backdoor)', async () => {
  const userscriptSource = readFileSync(join(ROOT, 'dist/antigravity-remote.user.js'), 'utf8');
  const bookmarkletHref = readFileSync(join(ROOT, 'dist/bookmarklet.txt'), 'utf8').trim();
  assert.ok(bookmarkletHref.startsWith('javascript:'));

  const browser = await launchChromium();
  try {
    // 1) F2 & NB4: Untrusted origin fail-closed for BOTH Userscript AND Bookmarklet, even with spoofed window.antigravityRemoteHost!
    for (const evilMode of ['userscript', 'bookmarklet']) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.route('https://evil.example/**', (route) =>
        route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: '<!doctype html><html><body><h1>Untrusted</h1></body></html>',
        }),
      );
      await page.goto('https://evil.example/remote', { waitUntil: 'domcontentloaded' });
      await page.evaluate(() => {
        window.__spoofCalled = false;
        window.antigravityRemoteHost = {
          toggleDock() {
            window.__spoofCalled = true;
          },
        };
      });
      if (evilMode === 'userscript') {
        await page.addScriptTag({ content: userscriptSource });
      } else {
        await page.evaluate((bmHref) => {
          const a = document.createElement('a');
          a.id = 'evil-bm';
          a.href = bmHref;
          document.body.appendChild(a);
          a.click();
        }, bookmarkletHref);
        await new Promise((r) => setTimeout(r, 80));
      }
      const evilState = await page.evaluate(() => ({
        spoofCalled: window.__spoofCalled,
        surfaceCount: document.querySelectorAll('[data-remote-host-surface="closed-shadow"]').length,
      }));
      assert.equal(evilState.spoofCalled, false, `${evilMode}: isOriginAllowed must execute BEFORE touching window.antigravityRemoteHost`);
      assert.equal(evilState.surfaceCount, 0, `${evilMode}: must refuse to mount on untrusted origin`);
      await context.close();
    }

    // 2) Trusted real origin https://antigravity.google.com/remote (Desktop Userscript + Mobile 390x844 Bookmarklet)
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
      const cdp = await context.newCDPSession(page);
      const errors = [];
      page.on('pageerror', (err) => errors.push(`pageerror: ${err.message}`));
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          errors.push(`console.error: ${msg.text()}`);
        }
      });

      await page.route('https://antigravity.google.com/**', (route) =>
        route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          headers: {
            'Content-Security-Policy':
              "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'self'",
          },
          body: `<!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Antigravity Remote Web</title>
            </head>
            <body style="margin:0;padding:16px;font-family:sans-serif;">
              <main><p id="host-content">Remote Session Active</p></main>
            </body>
            </html>`,
        }),
      );

      await page.goto('https://antigravity.google.com/remote', { waitUntil: 'domcontentloaded' });

      if (sc.mode === 'userscript') {
        await page.addScriptTag({ content: userscriptSource });
      } else {
        await page.evaluate((bmHref) => {
          const a = document.createElement('a');
          a.id = 'run-bookmarklet';
          a.href = bmHref;
          a.textContent = 'Run Bookmarklet';
          document.body.appendChild(a);
          a.click();
        }, bookmarkletHref);
      }

      await page.waitForFunction(() => Boolean(window.antigravityRemoteHost));

      // F2: Verify locked-down global surface — zero renderer/getSlotRoot/registry/diagnostics/unregister/issueHandshakeNonce/dispose
      const surfaceAudit = await page.evaluate(() => {
        const hostEl = document.querySelector('[data-remote-host-surface="closed-shadow"]');
        const api = window.antigravityRemoteHost;
        return {
          exists: Boolean(hostEl),
          shadowRootIsNull: hostEl ? hostEl.shadowRoot === null : false,
          noTranslate: hostEl ? hostEl.getAttribute('translate') : null,
          keys: Object.keys(api).sort(),
          frozen: Object.isFrozen(api),
          hasRenderer: 'renderer' in api,
          hasRegistry: 'registry' in api,
          hasDiagnostics: 'diagnostics' in api,
          hasUnregister: 'unregister' in api,
          hasIssueNonce: 'issueHandshakeNonce' in api,
          hasDispose: 'dispose' in api,
        };
      });
      assert.equal(surfaceAudit.exists, true);
      assert.equal(surfaceAudit.shadowRootIsNull, true);
      assert.equal(surfaceAudit.noTranslate, 'no');
      assert.equal(surfaceAudit.frozen, true);
      assert.deepEqual(surfaceAudit.keys, [
        'contractVersion',
        'getLocale',
        'listSlots',
        'register',
        'setLocale',
        'toggleDock',
        'version',
      ]);
      assert.equal(surfaceAudit.hasRenderer, false);
      assert.equal(surfaceAudit.hasRegistry, false);
      assert.equal(surfaceAudit.hasDiagnostics, false);
      assert.equal(surfaceAudit.hasUnregister, false);
      assert.equal(surfaceAudit.hasIssueNonce, false);
      assert.equal(surfaceAudit.hasDispose, false);

      // Register status-bar + settings-pane plugins through the public register() API
      await page.evaluate(() => {
        window.__confirmedRuns = 0;
        window.__unregStatus = window.antigravityRemoteHost.register({
          contractVersion: 'remote-plugin.v1',
          id: 'demo-statusbar',
          version: '1.0.0',
          displayName: { ko: '상태바', en: 'Statusbar' },
          uiSlot: { slot: 'status-bar', slotId: 'demo-statusbar.root', exclusive: true },
          capabilities: ['badge', 'panel'],
          loadOrder: 10,
          getSnapshot() {
            return {
              revision: 'sb-1',
              badge: { text: { ko: '연결됨', en: 'Live' }, tone: 'ok' },
              sections: [
                {
                  kind: 'metrics',
                  items: [{ label: { ko: '컨텍스트', en: 'Context' }, value: '42%', tone: 'ok' }],
                },
              ],
            };
          },
        });
        window.__unregSettings = window.antigravityRemoteHost.register({
          contractVersion: 'remote-plugin.v1',
          id: 'demo-settings-tool',
          version: '1.0.0',
          displayName: { ko: '도구 설정', en: 'Tool Settings' },
          uiSlot: { slot: 'settings-pane', slotId: 'demo-settings-tool.pane', exclusive: false },
          capabilities: ['panel', 'actions'],
          loadOrder: 20,
          getSnapshot() {
            return {
              revision: 'cfg-1',
              sections: [
                {
                  kind: 'actions',
                  items: [{ id: 'apply-stdio', label: { ko: 'Stdio 적용', en: 'Apply Stdio' }, style: 'danger' }],
                },
              ],
            };
          },
          invoke(actionId, invocation) {
            if (actionId === 'apply-stdio' && invocation.challengeResponse?.confirmed !== true) {
              return {
                status: 'confirmation_required',
                challengeId: 'stdio-chg-1',
                message: { ko: 'Stdio 명령을 승인하시겠습니까?', en: 'Approve stdio command?' },
                confirmLabel: { ko: '승인', en: 'Approve' },
              };
            }
            window.__confirmedRuns += 1;
            return { status: 'ok', message: { ko: '적용됨', en: 'Applied' } };
          },
        });
      });

      // Wait briefly for async declarative render, then inspect & click Closed Shadow DOM via CDP!
      await new Promise((r) => setTimeout(r, 60));
      let root = await getPiercedRoot(cdp);
      const statusBar = findCdpNode(root, (n) => getAttr(n, 'data-remote-slot') === 'status-bar');
      assert.ok(statusBar && !hasAttr(statusBar, 'hidden'), `${sc.mode}: status-bar must be visible`);
      assert.ok(cdpNodeText(statusBar).includes('42%'), `${sc.mode}: status-bar must show metric 42%`);

      // Click dock pill via real mouse coordinates from CDP box model
      const { box: pillBox } = await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-rph-control') === 'dock-pill');
      await new Promise((r) => setTimeout(r, 40));

      root = await getPiercedRoot(cdp);
      const settingsGroup = findCdpNode(root, (n) => getAttr(n, 'data-remote-slot-group') === 'settings-pane');
      assert.ok(settingsGroup, `${sc.mode}: settings-pane plugin must render in settings-pane group`);

      const langNode = findCdpNode(root, (n) => getAttr(n, 'data-rph-control') === 'lang-toggle');
      const closeNode = findCdpNode(root, (n) => getAttr(n, 'data-rph-control') === 'close');
      const actionNode = findCdpNode(root, (n) => getAttr(n, 'data-action-id') === 'apply-stdio');
      const heights = await Promise.all([langNode, closeNode, actionNode].map((n) => getCdpBox(cdp, n).then((b) => b.height)));
      heights.push(pillBox.height);
      assert.ok(Math.min(...heights) >= 44, `${sc.mode}: touch target < 44px (${Math.min(...heights)}px)`);

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      assert.ok(overflow <= 0, `${sc.mode}: horizontal overflow (${overflow}px)`);

      // Click risky action -> 2-step confirmation MUST appear, never auto-confirmed!
      await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-action-id') === 'apply-stdio');
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(await page.evaluate(() => window.__confirmedRuns), 0, `${sc.mode}: must NEVER auto-confirm`);
      root = await getPiercedRoot(cdp);
      const confirmBox = findCdpNode(root, (n) => getAttr(n, 'data-rph-control') === 'confirm-box');
      assert.ok(confirmBox && !hasAttr(confirmBox, 'hidden'), `${sc.mode}: 2-step confirmation box must be visible`);

      // Click Confirm -> runs once and shows KO feedback ("적용됨")
      await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-rph-control') === 'confirm-accept');
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(await page.evaluate(() => window.__confirmedRuns), 1);

      // Click KO -> EN toggle -> both title AND existing action feedback ("Applied") translate live!
      await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-rph-control') === 'lang-toggle');
      await new Promise((r) => setTimeout(r, 50));
      root = await getPiercedRoot(cdp);
      const titleNode = findCdpNode(root, (n) => getAttr(n, 'class') === 'rph-title');
      assert.equal(cdpNodeText(titleNode), 'Remote Plugin Host');
      const drawerBody = findCdpNode(root, (n) => getAttr(n, 'data-rph-control') === 'drawer-body');
      assert.ok(cdpNodeText(drawerBody).includes('Applied'), `${sc.mode}: action feedback must translate dynamically to EN`);

      // Escape closes drawer
      await page.keyboard.press('Escape');
      await new Promise((r) => setTimeout(r, 40));
      root = await getPiercedRoot(cdp);
      const drawerAfterEsc = findCdpNode(root, (n) => getAttr(n, 'class') === 'rph-drawer');
      assert.equal(hasAttr(drawerAfterEsc, 'hidden'), true, `${sc.mode}: Escape must close drawer`);

      // Idempotent second bookmarklet tap toggles drawer open without duplicating host surface
      if (sc.mode === 'bookmarklet') {
        await page.click('#run-bookmarklet');
        const deadline = Date.now() + 5000;
        let reopened = false;
        while (Date.now() < deadline) {
          root = await getPiercedRoot(cdp);
          const d = findCdpNode(root, (n) => getAttr(n, 'class') === 'rph-drawer');
          if (d && !hasAttr(d, 'hidden')) {
            reopened = true;
            break;
          }
          await new Promise((r) => setTimeout(r, 25));
        }
        assert.equal(reopened, true, 'Second bookmarklet tap must reopen drawer');
        const hostCount = await page.evaluate(
          () => document.querySelectorAll('[data-remote-host-surface="closed-shadow"]').length,
        );
        assert.equal(hostCount, 1);
      }

      assert.deepEqual(errors, [], `${sc.mode}: unexpected browser errors`);
      await context.close();
    }
  } finally {
    await browser.close();
  }
});

test('ARP-TC-029: Playwright Chromium E2E runs built dist/addon-renderer.js inside strict assertNotDisposed() AddonManifest.v1 sandbox and verifies real host-initiated dispose() throws 0 errors', async () => {
  const addonRendererSource = readFileSync(join(ROOT, 'dist/addon-renderer.js'), 'utf8');
  const srv = await startHttpServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><html><head><meta charset="utf-8"></head><body><main id="desktop-settings"></main></body></html>');
  });

  const browser = await launchChromium();
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.goto(`http://127.0.0.1:${srv.port}/`, { waitUntil: 'domcontentloaded' });
    const result = await page.evaluate((rendererCode) => {
      const slots = new Map();
      const styles = new Map();
      const disposers = [];
      const disposerErrors = [];
      let disposed = false;

      function assertNotDisposed() {
        if (disposed) throw new Error('ERR_HANDLE_DISPOSED:antigravity-remote-plugin');
      }

      const addonHost = Object.freeze({
        pluginId: 'antigravity-remote-plugin',
        hostVersion: '1.0.1',
        hostProfileId: 'antigravity-desktop',
        storageNamespace: 'antigravity-remote-plugin',
        ipcChannelPrefix: null,
        getNoTranslateSelector() {
          return '[data-addon-host-owner], [translate="no"], [data-agy-no-translate="true"]';
        },
        mountSlot(slotId) {
          assertNotDisposed();
          if (slotId !== 'antigravity-remote-plugin.settings') {
            throw new Error(`ERR_UNDECLARED_SLOT:${slotId}`);
          }
          if (!slots.has(slotId)) {
            const el = document.createElement('div');
            el.setAttribute('translate', 'no');
            el.setAttribute('data-addon-host-owner', 'antigravity-remote-plugin');
            el.setAttribute('data-addon-host-slot', slotId);
            document.getElementById('desktop-settings').appendChild(el);
            slots.set(slotId, el);
          }
          return slots.get(slotId);
        },
        unmountSlot(slotId) {
          assertNotDisposed();
          const el = slots.get(slotId);
          if (!el) return false;
          el.remove();
          slots.delete(slotId);
          return true;
        },
        injectStyle(styleId, cssText) {
          assertNotDisposed();
          let st = styles.get(styleId);
          if (!st) {
            st = document.createElement('style');
            st.setAttribute('data-addon-host-owner', 'antigravity-remote-plugin');
            st.setAttribute('data-addon-host-style', `antigravity-remote-plugin:${styleId}`);
            document.head.appendChild(st);
            styles.set(styleId, st);
          }
          st.textContent = cssText;
          return st;
        },
        removeStyle(styleId) {
          assertNotDisposed();
          const st = styles.get(styleId);
          if (!st) return false;
          st.remove();
          styles.delete(styleId);
          return true;
        },
        listOwnedSlots() {
          return [...slots.keys()];
        },
        onDispose(fn) {
          assertNotDisposed();
          disposers.push(fn);
        },
        dispose() {
          if (disposed) return;
          disposed = true;
          for (const fn of disposers.splice(0, disposers.length)) {
            try {
              fn();
            } catch (err) {
              disposerErrors.push(err.message);
            }
          }
          for (const el of slots.values()) el.remove();
          slots.clear();
          for (const st of styles.values()) st.remove();
          styles.clear();
        },
      });

      const run = new Function('addonHost', rendererCode);
      run(addonHost);

      const slotEl = document.querySelector('[data-addon-host-slot="antigravity-remote-plugin.settings"]');
      const styleEl = document.querySelector('style[data-addon-host-owner="antigravity-remote-plugin"]');
      const koTitle = slotEl?.querySelector('.drc-title')?.textContent || '';
      slotEl?.querySelector('[data-drc-action="toggle-locale"]')?.click();
      const enTitle = slotEl?.querySelector('.drc-title')?.textContent || '';

      addonHost.dispose();
      const remainingSlots = document.querySelectorAll('[data-addon-host-owner="antigravity-remote-plugin"]').length;
      return {
        mounted: Boolean(slotEl),
        owner: slotEl?.getAttribute('data-addon-host-owner'),
        noTranslate: slotEl?.getAttribute('translate'),
        scopedStyle: Boolean(styleEl),
        koTitle,
        enTitle,
        remainingSlots,
        disposerErrors,
      };
    }, addonRendererSource);

    assert.deepEqual(errors, []);
    assert.deepEqual(result.disposerErrors, [], 'Real addonHost.dispose() must not trigger ERR_HANDLE_DISPOSED');
    assert.equal(result.mounted, true);
    assert.equal(result.owner, 'antigravity-remote-plugin');
    assert.equal(result.noTranslate, 'no');
    assert.equal(result.scopedStyle, true);
    assert.equal(result.koTitle, '원격 플러그인 컴패니언');
    assert.equal(result.enTitle, 'Remote Plugin Companion');
    assert.equal(result.remainingSlots, 0);

    await context.close();
  } finally {
    await browser.close();
    srv.server.closeAllConnections?.();
    await new Promise((r) => srv.server.close(r));
  }
});

test('ARP-TC-030: Playwright Chromium E2E verifies real cross-context iframe MessageChannel handshake, MessagePort register/snapshot/2-step invoke RPC, and clean disconnect teardown', async () => {
  const userscriptSource = readFileSync(join(ROOT, 'dist/antigravity-remote.user.js'), 'utf8');
  const bundleSource = readFileSync(join(ROOT, 'dist/remote_bridge.js'), 'utf8');

  const browser = await launchChromium();
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    const errors = [];
    page.on('pageerror', (err) => errors.push(`pageerror: ${err.message}`));
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
    });

    await page.route('https://antigravity.google.com/**', (route) => {
      const url = route.request().url();
      if (url.endsWith('/remote_bridge.js')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/javascript; charset=utf-8',
          body: bundleSource,
        });
      }
      if (url.endsWith('/plugin-frame')) {
        return route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: `<!doctype html><html><body><script type="module">
            import { connectPluginHandshake, serveRemotePluginOverPort } from '/remote_bridge.js';

            window.__rpcRuns = 0;
            const port = await connectPluginHandshake({
              selfWindow: window,
              targetWindow: window.parent,
              targetOrigin: 'https://antigravity.google.com',
              allowedOrigins: ['https://antigravity.google.com'],
              pluginId: 'iframe-aux-plugin',
            });
            const server = serveRemotePluginOverPort({
              port,
              plugin: {
                contractVersion: 'remote-plugin.v1',
                id: 'iframe-aux-plugin',
                version: '1.0.0',
                displayName: { ko: '아이프레임 보조', en: 'Iframe Aux' },
                uiSlot: { slot: 'aux-pane', slotId: 'iframe-aux-plugin.pane', exclusive: false },
                capabilities: ['panel', 'actions', 'subscribe'],
                loadOrder: 30,
                getSnapshot() {
                  return {
                    revision: 'if-1',
                    sections: [
                      {
                        kind: 'actions',
                        items: [{ id: 'rpc-run', label: { ko: 'RPC 실행', en: 'Run RPC' }, style: 'primary' }],
                      },
                    ],
                  };
                },
                invoke(actionId, invocation) {
                  if (actionId === 'rpc-run' && invocation.challengeResponse?.confirmed !== true) {
                    return {
                      status: 'confirmation_required',
                      challengeId: 'if-chg-1',
                      message: { ko: 'RPC 실행 확인', en: 'Confirm RPC run' },
                    };
                  }
                  window.__rpcRuns += 1;
                  return { status: 'ok', message: { ko: 'RPC 성공', en: 'RPC OK' } };
                },
                subscribe() { return () => {}; },
              },
            });
            await server.ready;
            window.__iframeServer = server;
            window.__iframeReady = true;
          </script></body></html>`,
        });
      }
      return route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: '<!doctype html><html><body><main>Remote Host</main></body></html>',
      });
    });

    await page.goto('https://antigravity.google.com/remote', { waitUntil: 'domcontentloaded' });
    await page.addScriptTag({ content: userscriptSource });
    await page.waitForFunction(() => Boolean(window.antigravityRemoteHost));

    // Mount real same-origin iframe that connects over MessageChannel challenge-response
    await page.evaluate(() => {
      const iframe = document.createElement('iframe');
      iframe.id = 'plugin-iframe';
      iframe.src = 'https://antigravity.google.com/plugin-frame';
      document.body.appendChild(iframe);
    });

    const frame = page.frame({ url: 'https://antigravity.google.com/plugin-frame' }) || page.frames()[1];
    await frame.waitForFunction(() => window.__iframeReady === true, null, { timeout: 5000 });

    // Open dock pill via CDP and verify aux-pane plugin rendered inside Closed Shadow DOM
    await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-rph-control') === 'dock-pill');
    await new Promise((r) => setTimeout(r, 60));
    let root = await getPiercedRoot(cdp);
    const auxGroup = findCdpNode(root, (n) => getAttr(n, 'data-remote-slot-group') === 'aux-pane');
    assert.ok(auxGroup && cdpNodeText(auxGroup).includes('아이프레임 보조'));

    // Click RPC action -> 2-step confirmation -> click Confirm -> RPC executes in iframe!
    await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-action-id') === 'rpc-run');
    await new Promise((r) => setTimeout(r, 60));
    assert.equal(await frame.evaluate(() => window.__rpcRuns), 0);

    await clickCdpNode(page, cdp, (n) => getAttr(n, 'data-rph-control') === 'confirm-accept');
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(await frame.evaluate(() => window.__rpcRuns), 1);

    root = await getPiercedRoot(cdp);
    const bodyAfterRpc = findCdpNode(root, (n) => getAttr(n, 'data-rph-control') === 'drawer-body');
    assert.ok(cdpNodeText(bodyAfterRpc).includes('RPC 성공'));

    // Iframe disconnects -> plugin unregisters and aux-pane disappears cleanly
    await frame.evaluate(() => window.__iframeServer.disconnect());
    await new Promise((r) => setTimeout(r, 80));
    root = await getPiercedRoot(cdp);
    const auxAfterDisconnect = findCdpNode(root, (n) => getAttr(n, 'data-remote-slot-group') === 'aux-pane');
    assert.equal(auxAfterDisconnect, null, 'Disconnecting MessagePort must remove plugin slot');

    assert.deepEqual(errors, []);
    await context.close();
  } finally {
    await browser.close();
  }
});
