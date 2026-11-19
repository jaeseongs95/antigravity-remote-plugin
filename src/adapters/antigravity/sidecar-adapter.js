import { isLoopbackHostname, SecurityPolicyError } from '../../security/origin-policy.js';

function assertLoopbackSidecar(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') {
    throw new SecurityPolicyError('INVALID_SIDECAR', 'Sidecar descriptor is required.');
  }
  const host = sidecar.host || '127.0.0.1';
  if (!isLoopbackHostname(host)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_SIDECAR',
      'Sidecar relay only permits loopback (127.0.0.1 / localhost) sidecar servers.',
    );
  }
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError('INVALID_SIDECAR_PORT', 'Sidecar port must be a valid TCP port.');
  }
  return { host, port };
}

export function createAntigravitySidecarAdapter({ fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('AntigravitySidecarAdapter requires a fetch implementation.');
  }

  return {
    buildUiUrl({ sidecar, conversationId = '' }) {
      const { host, port } = assertLoopbackSidecar(sidecar);
      const url = new URL(`http://${host}:${port}/`);
      if (conversationId) {
        url.searchParams.set('conversationId', String(conversationId));
      }
      if (sidecar.token) {
        url.searchParams.set('token', String(sidecar.token));
      }
      return url.toString();
    },

    async requestJson({ sidecar, path, method = 'POST', body = {} }) {
      const { host, port } = assertLoopbackSidecar(sidecar);
      if (typeof path !== 'string' || !path.startsWith('/')) {
        throw new SecurityPolicyError('INVALID_API_PATH', 'Sidecar API path must start with "/".');
      }

      const headers = { 'Content-Type': 'application/json' };
      if (sidecar.token) {
        headers['X-Sidecar-Token'] = String(sidecar.token);
      }

      const response = await fetchImpl(`http://${host}:${port}${path}`, {
        method: method.toUpperCase(),
        headers,
        body: method.toUpperCase() === 'GET' ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        throw new Error(`Sidecar API ${path} failed with HTTP ${response.status}`);
      }
      return response.json();
    },
  };
}
