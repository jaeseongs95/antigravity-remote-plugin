import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Response, SidecarApp } from 'sidecar_sdk';
import { createRemotePanelHandlers } from '../../src/adapters/antigravity/sidecar-host.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_DIR = join(__dirname, 'ui');
const PKG = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'));

const STRICT_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
].join('; ');

const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': STRICT_CSP,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
});

const INDEX_HTML = readFileSync(join(UI_DIR, 'index.html'), 'utf8');
const STYLES_CSS = readFileSync(join(UI_DIR, 'styles.css'), 'utf8');
const APP_JS = readFileSync(join(UI_DIR, 'app.js'), 'utf8');

function extractWorkspaceUris(data) {
  if (!data || typeof data !== 'object') {
    return [];
  }
  if (Array.isArray(data.workspaceUris)) {
    return data.workspaceUris.filter((uri) => typeof uri === 'string' && uri.trim().length > 0);
  }
  return [];
}

function toJsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    contentType: 'application/json; charset=utf-8',
    headers: { 'Cache-Control': 'no-store' },
  });
}

async function main() {
  const app = new SidecarApp();
  const handlers = createRemotePanelHandlers({
    lsAddress: process.env.ANTIGRAVITY_LS_ADDRESS,
    csrfToken: process.env.ANTIGRAVITY_CSRF_TOKEN,
    version: PKG.version,
  });

  app.page('/', () => new Response(INDEX_HTML, {
    contentType: 'text/html; charset=utf-8',
    headers: SECURITY_HEADERS,
  }));
  app.page('/styles.css', () => new Response(STYLES_CSS, {
    contentType: 'text/css; charset=utf-8',
    headers: SECURITY_HEADERS,
  }));
  app.page('/app.js', () => new Response(APP_JS, {
    contentType: 'application/javascript; charset=utf-8',
    headers: SECURITY_HEADERS,
  }));
  app.page('/favicon.ico', () => new Response('', {
    status: 204,
    contentType: 'image/x-icon',
  }));

  app.api('/api/health', async () => toJsonResponse(handlers.getHealth()), 'GET');

  app.api('/api/state', async (data) => {
    const state = await handlers.getState({ workspaceUris: extractWorkspaceUris(data) });
    return toJsonResponse(state);
  }, 'POST');

  app.api('/api/statusbar/telemetry', async (data) => {
    try {
      const result = await handlers.relayStatusbar('/api/telemetry', data || {}, {
        workspaceUris: extractWorkspaceUris(data),
      });
      return toJsonResponse(result);
    } catch (err) {
      return toJsonResponse(
        { ok: false, code: err.code || 'RELAY_FAILED', error: err.message },
        err.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/statusbar/context-limit', async (data) => {
    try {
      const result = await handlers.relayStatusbar('/api/context-limit', data || {}, {
        workspaceUris: extractWorkspaceUris(data),
      });
      return toJsonResponse(result);
    } catch (err) {
      return toJsonResponse(
        { ok: false, code: err.code || 'RELAY_FAILED', error: err.message },
        err.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/statusbar/compact', async (data) => {
    try {
      const result = await handlers.relayStatusbar('/api/compact', data || {}, {
        workspaceUris: extractWorkspaceUris(data),
      });
      return toJsonResponse(result);
    } catch (err) {
      return toJsonResponse(
        { ok: false, code: err.code || 'RELAY_FAILED', error: err.message },
        err.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/mcp/summary', async (data) => {
    const summary = await handlers.getMcpSummary({ workspaceUris: extractWorkspaceUris(data) });
    return toJsonResponse(summary);
  }, 'POST');

  const shutdown = async () => {
    handlers.dispose();
    await app.close();
  };
  process.on('SIGTERM', () => {
    void shutdown();
  });
  process.on('SIGINT', () => {
    void shutdown();
  });

  await app.run();
}

await main();
