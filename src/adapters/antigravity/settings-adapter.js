import { sanitizeRemoteOverlaySettings } from '../../bridges/dom-overlay-bridge.js';

export const DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER = 'google-translate';

export function createAntigravitySettingsAdapter({
  readSettingsFile,
  remoteFallbackProvider = DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
} = {}) {
  if (typeof readSettingsFile !== 'function') {
    throw new TypeError('AntigravitySettingsAdapter requires a readSettingsFile callback.');
  }

  return {
    async readPluginSettings(pluginName) {
      const raw = await readSettingsFile(pluginName);
      return sanitizeRemoteOverlaySettings(raw, {
        remoteFallbackProvider,
        localOnlyProviders: ['local-llm'],
      });
    },
  };
}
