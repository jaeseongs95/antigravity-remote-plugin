import { isLoopbackHostname, SecurityPolicyError } from '../../security/origin-policy.js';

const RPC_BASE_PATH = '/exa.language_server_pb.LanguageServerService';

function validateLoopbackAddress(lsAddress) {
  if (typeof lsAddress !== 'string' || !lsAddress.trim()) {
    throw new SecurityPolicyError('INVALID_LS_ADDRESS', 'Language server address is required.');
  }
  const normalized = lsAddress.includes('://') ? lsAddress.trim() : `http://${lsAddress.trim()}`;
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_err) {
    throw new SecurityPolicyError('INVALID_LS_ADDRESS', 'Language server address is not a valid URL.');
  }
  if (!isLoopbackHostname(parsed.hostname)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_LS_ADDRESS',
      'Language server RPC adapter only permits loopback addresses.',
    );
  }
  return parsed.origin;
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

export function createAntigravityDiscoveryAdapter({
  lsAddress,
  csrfToken,
  fetchImpl = globalThis.fetch,
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
      const plugins = Array.isArray(data?.plugins) ? data.plugins : [];
      return plugins.map((plugin) => ({
        name: plugin.name,
        path: plugin.path || '',
        dir: typeof plugin.path === 'string' && plugin.path.length > 0
          ? plugin.path.replace(/\\/g, '/').split('/').pop()
          : plugin.name,
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
      const sidecars = Array.isArray(data?.sidecars) ? data.sidecars : [];
      return sidecars.map((sc) => ({
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
