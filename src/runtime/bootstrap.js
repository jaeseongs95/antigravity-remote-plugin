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
} from '../adapters/antigravity/settings-adapter.js';
import { createAntigravitySidecarAdapter } from '../adapters/antigravity/sidecar-adapter.js';

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

  const orchestrator = new RemoteOrchestrator({
    discoveryPort,
    framePort,
    diagnostics,
  });

  const bridges = {};

  if (typeof createKoTranslator === 'function') {
    const koBridge = createDomOverlayBridge({
      id: 'ko-translator-overlay',
      pluginName: 'ko-thought-translator',
      createOverlay: createKoTranslator,
      settingsPort,
      remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
    });
    orchestrator.registerBridge(koBridge);
    bridges.koTranslator = koBridge;
  }

  const statusbarBridge = createSidecarUiBridge({
    id: 'statusbar-sidecar',
    pluginName: 'antigravity-statusbar',
    sidecarId: 'antigravity-statusbar/statusbar',
    relayPort: sidecarRelayPort,
    allowedOrigins: [...allowedOrigins, 'http://127.0.0.1:*', 'http://localhost:*'],
    onInboundEvent: onSidecarEvent,
  });
  orchestrator.registerBridge(statusbarBridge);
  bridges.statusbar = statusbarBridge;

  const mcpSlot = createMcpExtensionSlot({
    id: 'mcp-manager-slot',
    pluginName: 'antigravity-mcp-manager',
    delegate: mcpDelegate,
  });
  orchestrator.registerBridge(mcpSlot);
  bridges.mcpManager = mcpSlot;

  return {
    orchestrator,
    diagnostics,
    framePort,
    bridges,
  };
}
