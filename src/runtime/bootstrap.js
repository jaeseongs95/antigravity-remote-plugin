import { DiagnosticsBus } from '../core/diagnostics.js';
import { RemoteOrchestrator } from '../core/orchestrator.js';
import { createDomOverlayBridge } from '../bridges/dom-overlay-bridge.js';
import { createMcpExtensionSlot } from '../bridges/mcp-extension-slot.js';
import { createSidecarUiBridge } from '../bridges/sidecar-ui-bridge.js';
import { createAntigravityDiscoveryAdapter } from '../adapters/antigravity/discovery-adapter.js';
import {
  createAntigravityFrameAdapter,
  DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
} from '../adapters/antigravity/frame-adapter.js';
import {
  createAntigravitySettingsAdapter,
  DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
  sanitizeTranslatorSettings,
} from '../adapters/antigravity/settings-adapter.js';
import { createAntigravitySidecarAdapter } from '../adapters/antigravity/sidecar-adapter.js';
import { createAntigravityThemeWorkspaceAdapter } from '../adapters/antigravity/theme-workspace-adapter.js';

const ANTIGRAVITY_PROTECTED_MCP_PATHS = Object.freeze([
  /(?:^|\/)\.gemini\/config\/config\.json$/i,
  /(?:^|\/)\.gemini\/antigravity\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/config\/plugins\/[^/]+\/mcp_config\.json$/i,
]);

export function bootstrapAntigravityRemoteBridge({
  lsAddress,
  csrfToken,
  fetchImpl = globalThis.fetch,
  trustedTypesApi = null,
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  readSettingsFile = async () => ({}),
  createKoTranslator = null,
  mcpDelegate = null,
  initialFrame = null,
  initialThemeVariables = {},
  initialWorkspaceUris = [],
  hostLoadGuard = null,
  onSidecarEvent = null,
}) {
  const diagnostics = new DiagnosticsBus();

  const discoveryPort = createAntigravityDiscoveryAdapter({
    lsAddress,
    csrfToken,
    fetchImpl,
  });

  const framePort = createAntigravityFrameAdapter({
    allowedOrigins,
    trustedTypesApi,
    hostLoadGuard,
    diagnostics,
    initialFrame,
  });

  const sidecarRelayPort = createAntigravitySidecarAdapter({ fetchImpl });
  const settingsPort = createAntigravitySettingsAdapter({
    readSettingsFile,
    remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
  });
  const themeWorkspacePort = createAntigravityThemeWorkspaceAdapter({
    initialThemeVariables,
    initialWorkspaceUris,
  });

  const orchestrator = new RemoteOrchestrator({
    discoveryPort,
    framePort,
    diagnostics,
  });

  const bridges = {};

  if (typeof createKoTranslator === 'function') {
    const koBridge = createDomOverlayBridge({
      id: 'ko-translator-overlay',
      pluginName: 'antigravity-ko-translator',
      pluginAliases: ['ko-thought-translator'],
      createOverlay: createKoTranslator,
      settingsPort,
      sanitizeSettings: (raw) =>
        sanitizeTranslatorSettings(raw, {
          remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
        }),
    });
    orchestrator.registerBridge(koBridge);
    bridges.koTranslator = koBridge;
  }

  // Exact sidecar origin is derived dynamically from activeSidecar.host/port on mount;
  // never grant wildcard localhost:* / 127.0.0.1:* origins.
  const statusbarBridge = createSidecarUiBridge({
    id: 'statusbar-sidecar',
    pluginName: 'antigravity-statusbar',
    sidecarId: 'antigravity-statusbar/statusbar',
    relayPort: sidecarRelayPort,
    themeWorkspacePort,
    allowedOrigins: [],
    onInboundEvent: onSidecarEvent,
  });
  orchestrator.registerBridge(statusbarBridge);
  bridges.statusbar = statusbarBridge;

  const mcpSlot = createMcpExtensionSlot({
    id: 'mcp-manager-slot',
    pluginName: 'antigravity-mcp-manager',
    protectedConfigPatterns: ANTIGRAVITY_PROTECTED_MCP_PATHS,
    delegate: mcpDelegate,
  });
  orchestrator.registerBridge(mcpSlot);
  bridges.mcpManager = mcpSlot;

  return {
    orchestrator,
    diagnostics,
    framePort,
    themeWorkspacePort,
    bridges,
  };
}
