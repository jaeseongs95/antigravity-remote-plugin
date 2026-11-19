import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRemotePanelHandlers } from '../../src/adapters/antigravity/sidecar-host.js';
import { redactSecrets, redactUrl } from '../../src/security/redactor.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_DIR = join(__dirname, 'ui');
const PKG = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'));

export const STRICT_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
].join('; ');

export const SECURITY_HEADERS = Object.freeze({
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

function sanitizeErrorPayload(err, fallbackCode = 'INTERNAL_ERROR') {
  const safeMessage = redactUrl(String(err?.message || 'Unexpected sidecar error.'));
  return redactSecrets({
    ok: false,
    code: typeof err?.code === 'string' && err.code ? err.code : fallbackCode,
    error: safeMessage,
  });
}

async function loadSidecarSdk(env) {
  try {
    return await import('sidecar_sdk');
  } catch (primaryErr) {
    const candidates = [
      env.ANTIGRAVITY_SIDECAR_SDK_PATH,
      env.NODE_PATH ? join(env.NODE_PATH, 'sidecar_sdk', 'index.mjs') : '',
      join(homedir(), '.gemini', 'antigravity', 'lib', 'node_modules', 'sidecar_sdk', 'index.mjs'),
    ].filter(Boolean);
    for (const candidate of candidates) {
      if (existsSync(candidate)) {
        return import(pathToFileURL(candidate).href);
      }
    }
    throw primaryErr;
  }
}

export async function createSidecarServer({
  SidecarAppClass = null,
  ResponseClass = null,
  env = process.env,
  fetchImpl = undefined,
} = {}) {
  let AppCtor = SidecarAppClass;
  let RespCtor = ResponseClass;
  if (!AppCtor || !RespCtor) {
    const sdk = await loadSidecarSdk(env);
    AppCtor = AppCtor || sdk.SidecarApp;
    RespCtor = RespCtor || sdk.Response;
  }

  function toJsonResponse(payload, status = 200) {
    return new RespCtor(JSON.stringify(redactSecrets(payload)), {
      status,
      contentType: 'application/json; charset=utf-8',
      headers: { 'Cache-Control': 'no-store' },
    });
  }

  let handlers = null;
  let initError = null;
  function getHandlersOrThrow() {
    if (handlers) {
      return handlers;
    }
    const lsAddress = env.ANTIGRAVITY_LS_ADDRESS;
    const csrfToken = env.ANTIGRAVITY_CSRF_TOKEN;
    if (!lsAddress || !csrfToken) {
      const err = new Error('Host LanguageServer credentials are not configured.');
      err.statusCode = 503;
      err.code = 'HOST_NOT_CONFIGURED';
      throw err;
    }
    try {
      handlers = createRemotePanelHandlers({
        lsAddress,
        csrfToken,
        fetchImpl,
        version: PKG.version,
      });
      initError = null;
      return handlers;
    } catch (err) {
      initError = err;
      const wrapped = new Error(redactUrl(String(err?.message || 'Sidecar initialization failed.')));
      wrapped.statusCode = 503;
      wrapped.code = err?.code || 'HOST_INIT_FAILED';
      throw wrapped;
    }
  }

  const app = new AppCtor();

  app.page('/', () => new RespCtor(INDEX_HTML, {
    contentType: 'text/html; charset=utf-8',
    headers: SECURITY_HEADERS,
  }));
  app.page('/styles.css', () => new RespCtor(STYLES_CSS, {
    contentType: 'text/css; charset=utf-8',
    headers: SECURITY_HEADERS,
  }));
  app.page('/app.js', () => new RespCtor(APP_JS, {
    contentType: 'application/javascript; charset=utf-8',
    headers: SECURITY_HEADERS,
  }));
  app.page('/favicon.ico', () => new RespCtor('', {
    status: 204,
    contentType: 'image/x-icon',
  }));

  app.api('/api/health', async () => {
    const configured = Boolean(env.ANTIGRAVITY_LS_ADDRESS && env.ANTIGRAVITY_CSRF_TOKEN);
    return toJsonResponse({
      ok: true,
      name: PKG.name,
      version: PKG.version,
      configured,
      degraded: !configured || Boolean(initError),
      capabilities: ['plugin-discovery', 'statusbar-relay', 'mcp-readonly-diagnostics'],
    });
  }, 'GET');

  app.api('/api/state', async (data) => {
    try {
      const h = getHandlersOrThrow();
      const state = await h.getState({ workspaceUris: extractWorkspaceUris(data) });
      return toJsonResponse(state);
    } catch (err) {
      return toJsonResponse(
        sanitizeErrorPayload(err, 'STATE_FETCH_FAILED'),
        err?.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/statusbar/telemetry', async (data) => {
    try {
      const h = getHandlersOrThrow();
      const result = await h.relayStatusbar('/api/telemetry', data || {}, {
        workspaceUris: extractWorkspaceUris(data),
      });
      return toJsonResponse(result);
    } catch (err) {
      return toJsonResponse(
        sanitizeErrorPayload(err, 'RELAY_FAILED'),
        err?.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/statusbar/context-limit', async (data) => {
    try {
      const h = getHandlersOrThrow();
      const result = await h.relayStatusbar('/api/context-limit', data || {}, {
        workspaceUris: extractWorkspaceUris(data),
      });
      return toJsonResponse(result);
    } catch (err) {
      return toJsonResponse(
        sanitizeErrorPayload(err, 'RELAY_FAILED'),
        err?.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/statusbar/compact', async (data) => {
    try {
      const h = getHandlersOrThrow();
      const result = await h.relayStatusbar('/api/compact', data || {}, {
        workspaceUris: extractWorkspaceUris(data),
      });
      return toJsonResponse(result);
    } catch (err) {
      return toJsonResponse(
        sanitizeErrorPayload(err, 'RELAY_FAILED'),
        err?.statusCode || 502,
      );
    }
  }, 'POST');

  app.api('/api/mcp/summary', async (data) => {
    try {
      const h = getHandlersOrThrow();
      const summary = await h.getMcpSummary({ workspaceUris: extractWorkspaceUris(data) });
      return toJsonResponse(summary);
    } catch (err) {
      return toJsonResponse(
        sanitizeErrorPayload(err, 'MCP_SUMMARY_FAILED'),
        err?.statusCode || 502,
      );
    }
  }, 'POST');

  return {
    app,
    async start() {
      return app.run();
    },
    async close() {
      if (handlers) {
        handlers.dispose();
        handlers = null;
      }
      await app.close();
    },
  };
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isDirectEntry) {
  const srv = await createSidecarServer();
  const shutdown = async () => {
    await srv.close();
  };
  process.on('SIGTERM', () => {
    void shutdown();
  });
  process.on('SIGINT', () => {
    void shutdown();
  });
  await srv.start();
}
