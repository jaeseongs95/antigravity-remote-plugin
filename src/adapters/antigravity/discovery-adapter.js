import {
  formatHostForUrl,
  isLoopbackHostname,
  SecurityPolicyError,
} from '../../security/origin-policy.js';

const RPC_BASE_PATH = '/exa.language_server_pb.LanguageServerService';

function validateLoopbackAddress(lsAddress) {
  if (typeof lsAddress !== 'string' || !lsAddress.trim()) {
    throw new SecurityPolicyError('INVALID_LS_ADDRESS', 'Language server address is required.');
  }
  const raw = lsAddress.trim();
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
  const normalized = hasScheme ? raw : `http://${raw}`;

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_err) {
    throw new SecurityPolicyError('INVALID_LS_ADDRESS', 'Language server address is not a valid URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SecurityPolicyError(
      'INVALID_LS_PROTOCOL',
      `Language server RPC adapter only permits http/https protocols, got "${parsed.protocol}".`,
    );
  }
  if (!isLoopbackHostname(parsed.hostname)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_LS_ADDRESS',
      'Language server RPC adapter only permits loopback addresses.',
    );
  }
  const host = formatHostForUrl(parsed.hostname);
  const portSuffix = parsed.port ? `:${parsed.port}` : '';
  return `${parsed.protocol}//${host}${portSuffix}`;
}

function validateCsrfToken(csrfToken) {
  if (typeof csrfToken !== 'string' || csrfToken.trim().length < 8) {
    throw new SecurityPolicyError(
      'MISSING_CSRF_TOKEN',
      'A real host-issued CSRF token is required; synthetic tokens are forbidden.',
    );
  }
  const lowered = csrfToken.trim().toLowerCase();
  if (lowered === 'csrf_token' || lowered === 'placeholder' || lowered === 'dummy') {
    throw new SecurityPolicyError(
      'SYNTHETIC_CSRF_TOKEN',
      'Synthetic placeholder CSRF tokens are forbidden.',
    );
  }
  return csrfToken.trim();
}

function extractInstallDir(rawPath, fallbackName) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    return fallbackName;
  }
  const stripped = rawPath.trim().replace(/\\/g, '/').replace(/\/+$/, '');
  const segment = stripped.split('/').pop();
  return segment || fallbackName;
}

export function createAntigravityDiscoveryAdapter({
  lsAddress,
  csrfToken,
  fetchImpl = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined,
}) {
  const origin = validateLoopbackAddress(lsAddress);
  const validToken = validateCsrfToken(csrfToken);
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('AntigravityDiscoveryAdapter requires a fetch implementation.');
  }

  async function callRpc(methodName, payload = {}) {
    const response = await fetchImpl(`${origin}${RPC_BASE_PATH}/${methodName}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-codeium-csrf-token': validToken,
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`LanguageServerService/${methodName} failed with HTTP ${response.status}`);
    }
    return response.json();
  }

  return {
    async listPlugins({ workspaceUris = [] } = {}) {
      const body = Array.isArray(workspaceUris) && workspaceUris.length > 0
        ? { workspaceUris }
        : {};
      const data = await callRpc('GetAllPlugins', body);
      if (!data || !Array.isArray(data.plugins)) {
        throw new Error('LanguageServerService/GetAllPlugins returned invalid payload: missing "plugins" array.');
      }
      return data.plugins.map((plugin) => ({
        name: plugin.name,
        path: plugin.path || '',
        dir: extractInstallDir(plugin.path, plugin.name),
        disabled: Boolean(plugin.disabled),
        enabled: !plugin.disabled,
        isGlobal: Boolean(plugin.isGlobal),
      }));
    },

    async listSidecars({ workspaceUris = [] } = {}) {
      const body = Array.isArray(workspaceUris) && workspaceUris.length > 0
        ? { workspaceUris }
        : {};
      const data = await callRpc('GetSidecars', body);
      if (!data || !Array.isArray(data.sidecars)) {
        throw new Error('LanguageServerService/GetSidecars returned invalid payload: missing "sidecars" array.');
      }
      return data.sidecars.map((sc) => ({
        sidecarId: sc.sidecarId || sc.id || '',
        pluginName: sc.pluginName || '',
        port: Number(sc.port || sc.webPort || 0),
        host: sc.host || '127.0.0.1',
        token: sc.token || sc.uiToken || '',
        running: sc.running !== false && sc.status !== 'stopped',
        disabled: Boolean(sc.disabled),
      }));
    },
  };
}
