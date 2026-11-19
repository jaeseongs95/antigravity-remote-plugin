import { DisposableStore } from '../core/lifecycle.js';
import { SecurityPolicyError } from '../security/origin-policy.js';

const ALLOWED_OVERLAY_SETTING_KEYS = Object.freeze([
  'enabled',
  'translateThinking',
  'translateStaticUi',
  'provider',
  'customEndpoint',
]);

export function sanitizeRemoteOverlaySettings(
  rawSettings,
  { remoteFallbackProvider = 'remote-default', localOnlyProviders = ['local-llm'] } = {},
) {
  const input = rawSettings && typeof rawSettings === 'object' ? rawSettings : {};
  const sanitized = {
    enabled: input.enabled !== false,
    translateThinking: input.translateThinking !== false,
    translateStaticUi: input.translateStaticUi !== false,
    provider: typeof input.provider === 'string' && input.provider.trim()
      ? input.provider.trim()
      : remoteFallbackProvider,
    customEndpoint: null,
  };

  if (typeof input.customEndpoint === 'string' && input.customEndpoint.trim()) {
    try {
      const parsed = new URL(input.customEndpoint.trim());
      if (parsed.protocol === 'https:') {
        sanitized.customEndpoint = parsed.toString();
      }
    } catch (_err) {
      sanitized.customEndpoint = null;
    }
  }

  if (localOnlyProviders.includes(sanitized.provider.toLowerCase())) {
    sanitized.provider = sanitized.customEndpoint ? 'custom-https' : remoteFallbackProvider;
  }

  const locked = {};
  for (const key of ALLOWED_OVERLAY_SETTING_KEYS) {
    locked[key] = sanitized[key];
  }
  return Object.freeze(locked);
}

/**
 * Vendor-independent pure DOM overlay bridge.
 * Enforces least privilege: passes ONLY `{ win, doc, settings, onStatus }` to
 * the overlay factory and guarantees deterministic `dispose()` on teardown.
 */
export function createDomOverlayBridge({
  id,
  pluginName,
  createOverlay,
  settingsPort = null,
  remoteFallbackProvider = 'remote-default',
  onStatus = null,
}) {
  if (typeof createOverlay !== 'function') {
    throw new TypeError('DomOverlayBridge requires a createOverlay factory function.');
  }

  let activeInstance = null;
  let store = null;

  return {
    id,
    pluginName,
    requireSidecar: false,

    async mount({ frame, diagnostics }) {
      if (!frame || !frame.win || !frame.doc) {
        throw new SecurityPolicyError(
          'MISSING_PROMOTED_FRAME',
          `Bridge "${id}" requires a promoted frame with win and doc.`,
        );
      }

      if (activeInstance) {
        this.dispose();
      }

      store = new DisposableStore({ diagnostics });
      const rawSettings = settingsPort
        ? await settingsPort.readPluginSettings(pluginName)
        : {};
      const safeSettings = sanitizeRemoteOverlaySettings(rawSettings, {
        remoteFallbackProvider,
      });

      const statusCallback = (statusPayload) => {
        if (typeof onStatus === 'function') {
          onStatus(statusPayload);
        }
        if (diagnostics) {
          diagnostics.emit({
            level: 'info',
            code: 'OVERLAY_STATUS',
            source: `bridge.${id}`,
            message: 'Overlay status updated',
            detail: statusPayload,
          });
        }
      };

      // Least-privilege invocation: zero RPC clients, zero CSRF/sidecar tokens.
      const instance = createOverlay({
        win: frame.win,
        doc: frame.doc,
        settings: safeSettings,
        onStatus: statusCallback,
      });

      if (
        !instance ||
        typeof instance.start !== 'function' ||
        typeof instance.dispose !== 'function'
      ) {
        throw new TypeError(
          `Overlay factory for "${id}" must return { start(), dispose() }.`,
        );
      }

      activeInstance = instance;
      store.add(() => {
        if (activeInstance) {
          const target = activeInstance;
          activeInstance = null;
          target.dispose();
        }
      });

      await instance.start();
      return { settings: safeSettings };
    },

    updateSettings(nextRawSettings) {
      const safeNext = sanitizeRemoteOverlaySettings(nextRawSettings, {
        remoteFallbackProvider,
      });
      if (activeInstance && typeof activeInstance.updateSettings === 'function') {
        activeInstance.updateSettings(safeNext);
      }
      return safeNext;
    },

    dispose() {
      if (store) {
        const currentStore = store;
        store = null;
        currentStore.dispose();
      } else if (activeInstance) {
        const target = activeInstance;
        activeInstance = null;
        target.dispose();
      }
    },
  };
}
