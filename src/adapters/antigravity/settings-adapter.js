import { isSensitiveKey } from '../../security/redactor.js';

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

  if (sanitized.provider.toLowerCase() === 'local-llm') {
    sanitized.provider = sanitized.customEndpoint ? 'custom-https' : remoteFallbackProvider;
  }

  const locked = {};
  for (const key of ALLOWED_TRANSLATOR_SETTING_KEYS) {
    locked[key] = sanitized[key];
  }
  return Object.freeze(locked);
}

function sanitizeGenericSettings(rawSettings, depth = 0, seen = new WeakSet()) {
  if (depth > 8 || rawSettings === null || rawSettings === undefined) {
    return Object.freeze({});
  }
  const input = typeof rawSettings === 'object' ? rawSettings : {};
  if (seen.has(input)) {
    return Object.freeze({});
  }
  seen.add(input);
  const clean = {};
  for (const [key, value] of Object.entries(input)) {
    if (isSensitiveKey(key) || typeof value === 'function') {
      continue;
    }
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      clean[key] = sanitizeGenericSettings(value, depth + 1, seen);
    } else if (Array.isArray(value)) {
      clean[key] = Object.freeze(
        value.map((item) =>
          item && typeof item === 'object' && !Array.isArray(item)
            ? sanitizeGenericSettings(item, depth + 1, seen)
            : item,
        ),
      );
    } else {
      clean[key] = value;
    }
  }
  return Object.freeze(clean);
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
