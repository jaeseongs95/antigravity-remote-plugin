import { bootstrapAntigravityRemoteBridge } from '../../runtime/bootstrap.js';
import { redactSecrets } from '../../security/redactor.js';

const ALLOWED_STATUSBAR_ENDPOINTS = new Set([
  '/api/telemetry',
  '/api/context-limit',
  '/api/compact',
]);

const NUMERIC_TELEMETRY_KEYS = [
  'usedTokens',
  'maxTokenLimit',
  'contextLimit',
  'inputTokens',
  'outputTokens',
  'cachedTokens',
  'totalTokens',
];

function sanitizeTelemetryPayload(raw) {
  const redacted = redactSecrets(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !redacted || typeof redacted !== 'object') {
    return redacted;
  }
  for (const key of NUMERIC_TELEMETRY_KEYS) {
    if (typeof raw[key] === 'number' && Number.isFinite(raw[key])) {
      redacted[key] = raw[key];
    }
  }
  return redacted;
}

export function createRemotePanelHandlers({
  lsAddress,
  csrfToken,
  fetchImpl = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined,
  readSettingsFile = async () => ({}),
  version = '1.1.0',
}) {
  const runtime = bootstrapAntigravityRemoteBridge({
    lsAddress,
    csrfToken,
    fetchImpl,
    readSettingsFile,
  });

  async function ensureReconciled(workspaceUris = []) {
    const context = Array.isArray(workspaceUris) && workspaceUris.length > 0
      ? { workspaceUris }
      : {};
    await runtime.orchestrator.start(context);
    return context;
  }

  return {
    getHealth() {
      return {
        ok: true,
        name: 'antigravity-remote-plugin',
        version,
        capabilities: [
          'plugin-discovery',
          'statusbar-relay',
          'mcp-readonly-diagnostics',
        ],
      };
    },

    async getState({ workspaceUris = [] } = {}) {
      const context = await ensureReconciled(workspaceUris);
      const { activePlugins, activeSidecars } =
        await runtime.orchestrator.discoverAuthoritativeState(context);

      const seenPluginNames = new Set();
      const plugins = [];
      for (const plugin of activePlugins.values()) {
        if (!plugin || typeof plugin.name !== 'string' || seenPluginNames.has(plugin.name)) {
          continue;
        }
        seenPluginNames.add(plugin.name);
        plugins.push({
          name: plugin.name,
          dir: plugin.dir || plugin.name,
          enabled: plugin.enabled !== false && plugin.disabled !== true,
          isGlobal: Boolean(plugin.isGlobal),
        });
      }

      const sidecars = [];
      for (const sidecar of activeSidecars.values()) {
        sidecars.push({
          sidecarId: sidecar.sidecarId,
          pluginName: sidecar.pluginName || '',
          running: sidecar.running !== false,
          disabled: Boolean(sidecar.disabled),
        });
      }

      const mountedBridgeIds = runtime.orchestrator.getMountedBridgeIds();
      return redactSecrets({
        ok: true,
        version,
        mountedBridgeIds,
        statusbarAvailable: mountedBridgeIds.includes('statusbar-sidecar'),
        plugins,
        sidecars,
      });
    },

    async relayStatusbar(path, payload = {}, { workspaceUris = [] } = {}) {
      if (!ALLOWED_STATUSBAR_ENDPOINTS.has(path)) {
        const err = new Error(`Unsupported statusbar endpoint: ${path}`);
        err.statusCode = 403;
        throw err;
      }
      await ensureReconciled(workspaceUris);
      const mountedBridgeIds = runtime.orchestrator.getMountedBridgeIds();
      if (!mountedBridgeIds.includes('statusbar-sidecar')) {
        const err = new Error('antigravity-statusbar sidecar is not active.');
        err.statusCode = 503;
        err.code = 'STATUSBAR_UNAVAILABLE';
        throw err;
      }
      const result = await runtime.bridges.statusbar.relayApi(path, payload, 'POST');
      return {
        ok: true,
        endpoint: path,
        data: sanitizeTelemetryPayload(result),
      };
    },

    async getMcpSummary({ workspaceUris = [] } = {}) {
      const context = await ensureReconciled(workspaceUris);
      const { activePlugins } = await runtime.orchestrator.discoverAuthoritativeState(context);
      const mountedBridgeIds = runtime.orchestrator.getMountedBridgeIds();
      const mcpPlugin = activePlugins.get('antigravity-mcp-manager') || null;
      return redactSecrets({
        ok: true,
        slotMounted: mountedBridgeIds.includes('mcp-manager-slot'),
        mcpPluginActive: Boolean(mcpPlugin),
        remoteStdioPolicy: 'explicit-confirmation-required',
        protectedConfigGuard: 'enabled',
        secretsRedacted: true,
      });
    },

    dispose() {
      runtime.orchestrator.dispose();
    },
  };
}
