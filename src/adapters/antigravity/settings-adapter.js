import { stripSensitiveDeep } from '../../security/redactor.js';

export const DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER = 'google-translate';

const TRANSLATOR_PLUGIN_NAMES = new Set([
  'antigravity-ko-translator',
  'ko-thought-translator',
]);

const ALLOWED_TRANSLATOR_SETTING_KEYS = Object.freeze([
  'enabled',
  'translateThinking',
  'translateStaticUi',
  'provider',
  'customEndpoint',
]);

export function sanitizeTranslatorSettings(
  rawSettings,
  { remoteFallbackProvider = DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER } = {},
) {
  const input = rawSettings && typeof rawSettings === 'object' ? rawSettings : {};
  const sanitized = {
    enabled: input.enabled !== false,
    translateThinking: input.translateThinking !== false,
    translateStaticUi: input.translateStaticUi !== false,
    provider:
      typeof input.provider === 'string' && input.provider.trim()
        ? input.provider.trim()
        : remoteFallbackProvider,
    customEndpoint: null,
  };

  if (typeof input.customEndpoint === 'string' && input.customEndpoint.trim()) {
    try {
      const parsed = new URL(input.customEndpoint.trim());
      if (parsed.protocol === 'https:' && !parsed.username && !parsed.password) {
        sanitized.customEndpoint = parsed.toString();
      }
    } catch (_err) {
      sanitized.customEndpoint = null;
    }
  }

  const lowerProvider = sanitized.provider.toLowerCase();
  if (lowerProvider === 'local-llm' || (lowerProvider === 'custom-https' && !sanitized.customEndpoint)) {
    sanitized.provider = sanitized.customEndpoint ? 'custom-https' : remoteFallbackProvider;
  }

  const locked = {};
  for (const key of ALLOWED_TRANSLATOR_SETTING_KEYS) {
    locked[key] = sanitized[key];
  }
  return Object.freeze(locked);
}

function sanitizeGenericSettings(rawSettings) {
  if (!rawSettings || typeof rawSettings !== 'object' || Array.isArray(rawSettings)) {
    return Object.freeze({});
  }
  return stripSensitiveDeep(rawSettings) || Object.freeze({});
}

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
      if (TRANSLATOR_PLUGIN_NAMES.has(String(pluginName || '').trim())) {
        return sanitizeTranslatorSettings(raw, { remoteFallbackProvider });
      }
      return sanitizeGenericSettings(raw);
    },
  };
}
