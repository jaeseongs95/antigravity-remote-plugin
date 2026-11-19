import { AsyncMutex } from '../../core/lifecycle.js';
import { bootstrapAntigravityRemoteBridge } from '../../runtime/bootstrap.js';
import { redactSecrets } from '../../security/redactor.js';

const ALLOWED_STATUSBAR_ENDPOINTS = new Set([
  '/api/telemetry',
  '/api/context-limit',
  '/api/compact',
]);

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
  const opMutex = new AsyncMutex();

  async function reconcileLocked(workspaceUris = []) {
    const context = Array.isArray(workspaceUris) && workspaceUris.length > 0
      ? { workspaceUris }
      : {};
    const result = await runtime.orchestrator.start(context);
    return {
      mountedBridgeIds: runtime.orchestrator.getMountedBridgeIds(),
      activePlugins: result.activePlugins ?? new Map(),
      activeSidecars: result.activeSidecars ?? new Map(),
    };
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
      return opMutex.runExclusive(async () => {
        const { mountedBridgeIds, activePlugins, activeSidecars } =
          await reconcileLocked(workspaceUris);

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

        return redactSecrets({
          ok: true,
          version,
          mountedBridgeIds,
          statusbarAvailable: mountedBridgeIds.includes('statusbar-sidecar'),
          plugins,
          sidecars,
        });
      });
    },

    async relayStatusbar(path, payload = {}, { workspaceUris = [] } = {}) {
      if (!ALLOWED_STATUSBAR_ENDPOINTS.has(path)) {
        const err = new Error(`Unsupported statusbar endpoint: ${path}`);
        err.statusCode = 403;
        err.code = 'API_PATH_NOT_ALLOWED';
        throw err;
      }
      return opMutex.runExclusive(async () => {
        const { mountedBridgeIds } = await reconcileLocked(workspaceUris);
        if (!mountedBridgeIds.includes('statusbar-sidecar')) {
          const err = new Error('antigravity-statusbar sidecar is not active.');
          err.statusCode = 503;
          err.code = 'STATUSBAR_UNAVAILABLE';
          throw err;
        }
        try {
          const result = await runtime.bridges.statusbar.relayApi(path, payload, 'POST');
          return redactSecrets({
            ok: true,
            endpoint: path,
            data: result,
          });
        } catch (relayErr) {
          if (relayErr?.code === 'BRIDGE_NOT_MOUNTED' || relayErr?.code === 'SIDECAR_NOT_ACTIVE') {
            const unavailable = new Error('antigravity-statusbar sidecar is not active.');
            unavailable.statusCode = 503;
            unavailable.code = 'STATUSBAR_UNAVAILABLE';
            throw unavailable;
          }
          throw relayErr;
        }
      });
    },

    async getMcpSummary({ workspaceUris = [] } = {}) {
      return opMutex.runExclusive(async () => {
        const { mountedBridgeIds, activePlugins } = await reconcileLocked(workspaceUris);
        const mcpPlugin = activePlugins.get('antigravity-mcp-manager') || null;
        return redactSecrets({
          ok: true,
          slotMounted: mountedBridgeIds.includes('mcp-manager-slot'),
          mcpPluginActive: Boolean(mcpPlugin),
          remoteStdioPolicy: 'explicit-confirmation-required',
          protectedConfigGuard: 'enabled',
          secretsRedacted: true,
        });
      });
    },

    dispose() {
      runtime.orchestrator.dispose();
    },
  };
}
