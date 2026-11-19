export function assertPort(port, portName, requiredMethods) {
  if (!port || typeof port !== 'object') {
    throw new TypeError(`Missing required port "${portName}".`);
  }
  for (const method of requiredMethods) {
    if (typeof port[method] !== 'function') {
      throw new TypeError(`Port "${portName}" must implement method "${method}()".`);
    }
  }
  return port;
}

export const PORT_CONTRACTS = Object.freeze({
  HostDiscoveryPort: Object.freeze(['listPlugins', 'listSidecars']),
  FramePromotionPort: Object.freeze(['acquireActiveFrame', 'onFrameChange']),
  SidecarRelayPort: Object.freeze(['requestJson', 'buildUiUrl']),
  SettingsReadPort: Object.freeze(['readPluginSettings']),
  ThemeWorkspaceSyncPort: Object.freeze(['getThemeVariables', 'getWorkspaceUris', 'subscribe']),
  ExtensionBridgePort: Object.freeze(['id', 'pluginName', 'mount', 'dispose']),
});

export function validateDiscoveryPort(port) {
  return assertPort(port, 'HostDiscoveryPort', PORT_CONTRACTS.HostDiscoveryPort);
}

export function validateFramePromotionPort(port) {
  return assertPort(port, 'FramePromotionPort', PORT_CONTRACTS.FramePromotionPort);
}

export function validateSidecarRelayPort(port) {
  return assertPort(port, 'SidecarRelayPort', PORT_CONTRACTS.SidecarRelayPort);
}

export function validateSettingsReadPort(port) {
  return assertPort(port, 'SettingsReadPort', PORT_CONTRACTS.SettingsReadPort);
}

export function validateThemeWorkspaceSyncPort(port) {
  return assertPort(port, 'ThemeWorkspaceSyncPort', PORT_CONTRACTS.ThemeWorkspaceSyncPort);
}

export function validateBridgeDescriptor(bridge) {
  if (!bridge || typeof bridge !== 'object') {
    throw new TypeError('Bridge descriptor must be an object.');
  }
  if (typeof bridge.id !== 'string' || !bridge.id.trim()) {
    throw new TypeError('Bridge descriptor must have a non-empty string id.');
  }
  if (typeof bridge.pluginName !== 'string' || !bridge.pluginName.trim()) {
    throw new TypeError(`Bridge "${bridge.id}" must declare a non-empty pluginName.`);
  }
  if (typeof bridge.mount !== 'function' || typeof bridge.dispose !== 'function') {
    throw new TypeError(`Bridge "${bridge.id}" must implement mount() and dispose().`);
  }
  return bridge;
}
