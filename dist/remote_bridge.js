// antigravity-remote-plugin v0.1.0 — deterministic entry bundle
// Built from 17 source modules.
export { bootstrapAntigravityRemoteBridge } from '../src/runtime/bootstrap.js';
export { RemoteOrchestrator } from '../src/core/orchestrator.js';
export { DiagnosticsBus } from '../src/core/diagnostics.js';
export { DisposableStore, EventChain, SingleFlight } from '../src/core/lifecycle.js';
export { createDomOverlayBridge, sanitizeRemoteOverlaySettings } from '../src/bridges/dom-overlay-bridge.js';
export { createSidecarUiBridge } from '../src/bridges/sidecar-ui-bridge.js';
export { createMcpExtensionSlot } from '../src/bridges/mcp-extension-slot.js';
export const BUILD_VERSION = "0.1.0";
