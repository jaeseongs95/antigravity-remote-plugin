import { AsyncMutex, DisposableStore } from '../core/lifecycle.js';
import { SecurityPolicyError } from '../security/origin-policy.js';
import { isSensitiveKey } from '../security/redactor.js';

export function stripSensitiveSettings(rawSettings) {
  const input = rawSettings && typeof rawSettings === 'object' ? rawSettings : {};
  const clean = {};
  for (const [key, value] of Object.entries(input)) {
    if (isSensitiveKey(key) || typeof value === 'function') {
      continue;
    }
    clean[key] = value;
  }
  return Object.freeze(clean);
}

/**
 * Vendor- and domain-independent pure DOM overlay bridge.
 * Enforces least privilege: passes ONLY `{ win, doc, settings, onStatus }` to
 * the overlay factory, serializes mount/dispose against races, and rolls back
 * cleanly if `start()` fails.
 */
export function createDomOverlayBridge({
  id,
  pluginName,
  pluginAliases = [],
  createOverlay,
  settingsPort = null,
  sanitizeSettings = stripSensitiveSettings,
  onStatus = null,
}) {
  if (typeof createOverlay !== 'function') {
    throw new TypeError('DomOverlayBridge requires a createOverlay factory function.');
  }
  if (typeof sanitizeSettings !== 'function') {
    throw new TypeError('DomOverlayBridge sanitizeSettings must be a function.');
  }

  const mutex = new AsyncMutex();
  let mountEpoch = 0;
  let activeInstance = null;
  let store = null;

  function teardownCurrent() {
    if (store) {
      const currentStore = store;
      store = null;
      currentStore.dispose();
    } else if (activeInstance) {
      const target = activeInstance;
      activeInstance = null;
      target.dispose();
    }
  }

  return {
    id,
    pluginName,
    pluginAliases: [...pluginAliases],
    requireSidecar: false,

    async mount({ frame, diagnostics }) {
      if (!frame || !frame.win || !frame.doc) {
        throw new SecurityPolicyError(
          'MISSING_PROMOTED_FRAME',
          `Bridge "${id}" requires a promoted frame with win and doc.`,
        );
      }

      const myEpoch = ++mountEpoch;

      return mutex.runExclusive(async () => {
        if (myEpoch !== mountEpoch) {
          return { skipped: true };
        }

        teardownCurrent();

        const rawSettings = settingsPort
          ? await settingsPort.readPluginSettings(pluginName)
          : {};

        if (myEpoch !== mountEpoch) {
          return { skipped: true };
        }

        const safeSettings = Object.freeze({ ...sanitizeSettings(rawSettings) });

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

        const nextStore = new DisposableStore({ diagnostics });
        activeInstance = instance;
        store = nextStore;
        nextStore.add(() => {
          if (activeInstance === instance) {
            activeInstance = null;
          }
          instance.dispose();
        });

        try {
          await instance.start();
        } catch (startErr) {
          teardownCurrent();
          throw startErr;
        }

        if (myEpoch !== mountEpoch) {
          teardownCurrent();
          return { skipped: true };
        }

        return { settings: safeSettings };
      });
    },

    updateSettings(nextRawSettings) {
      const safeNext = Object.freeze({ ...sanitizeSettings(nextRawSettings) });
      if (activeInstance && typeof activeInstance.updateSettings === 'function') {
        activeInstance.updateSettings(safeNext);
      }
      return safeNext;
    },

    dispose() {
      mountEpoch += 1;
      teardownCurrent();
    },
  };
}
