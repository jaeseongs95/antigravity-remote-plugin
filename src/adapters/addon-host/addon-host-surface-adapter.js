import { assertPort } from '../../core/ports.js';
import { SecurityPolicyError } from '../../security/origin-policy.js';

const REQUIRED_ADDON_HOST_METHODS = Object.freeze([
  'mountSlot',
  'unmountSlot',
  'injectStyle',
  'removeStyle',
  'listOwnedSlots',
  'onDispose',
  'dispose',
]);

/**
 * Desktop AddonManifest.v1 adapter implementing HostSurfacePort strictly
 * through the scoped capability handle (`addonHost`) injected by the host loader.
 *
 * Pre-subscribes to `addonHost.onDispose(...)` before any consumer callback so
 * host-initiated `addonHost.dispose()` marks `disposed = true` first and allows
 * consumer teardown (`removeStyle`/`unmountSlot`) to return `false` safely without
 * throwing `ERR_HANDLE_DISPOSED`.
 */
export function createAddonHostSurfaceAdapter(addonHost, { diagnostics = null } = {}) {
  if (!addonHost || typeof addonHost !== 'object') {
    throw new SecurityPolicyError(
      'ERR_MISSING_ADDON_HOST',
      'AddonHostSurfaceAdapter requires a scoped addonHost capability handle.',
    );
  }
  assertPort(addonHost, 'addonHost', REQUIRED_ADDON_HOST_METHODS);

  let disposed = false;
  const ownedSlots = new Set();
  const ownedStyles = new Set();
  const localDisposers = [];

  function runLocalTeardown() {
    if (disposed) {
      return;
    }
    disposed = true;
    for (const fn of localDisposers.splice(0, localDisposers.length).reverse()) {
      try {
        fn();
      } catch (err) {
        if (diagnostics && typeof diagnostics.emit === 'function') {
          diagnostics.emit({
            level: 'error',
            code: 'SURFACE_DISPOSER_FAILED',
            source: 'adapter.addon-host-surface',
            message: 'Desktop surface disposer threw during teardown',
            detail: err,
          });
        }
      }
    }
    ownedSlots.clear();
    ownedStyles.clear();
  }

  // F4: Pre-subscribe to host disposal so `disposed = true` is set BEFORE consumer disposers run.
  addonHost.onDispose(runLocalTeardown);

  return Object.freeze({
    pluginId: typeof addonHost.pluginId === 'string' ? addonHost.pluginId : 'antigravity-remote-plugin',
    hostVersion: typeof addonHost.hostVersion === 'string' ? addonHost.hostVersion : '1.0.1',
    hostProfileId: typeof addonHost.hostProfileId === 'string' ? addonHost.hostProfileId : 'antigravity-desktop',
    storageNamespace:
      typeof addonHost.storageNamespace === 'string' ? addonHost.storageNamespace : 'antigravity-remote-plugin',

    mountSlot(slotId, parentEl) {
      if (disposed) {
        throw new SecurityPolicyError('ERR_SURFACE_DISPOSED', 'HostSurfacePort is already disposed.');
      }
      const el = addonHost.mountSlot(slotId, parentEl);
      ownedSlots.add(slotId);
      return el;
    },

    unmountSlot(slotId) {
      if (disposed) {
        return false;
      }
      ownedSlots.delete(slotId);
      return Boolean(addonHost.unmountSlot(slotId));
    },

    injectStyle(styleId, cssText) {
      if (disposed) {
        throw new SecurityPolicyError('ERR_SURFACE_DISPOSED', 'HostSurfacePort is already disposed.');
      }
      const el = addonHost.injectStyle(styleId, String(cssText || ''));
      ownedStyles.add(styleId);
      return el;
    },

    removeStyle(styleId) {
      if (disposed) {
        return false;
      }
      ownedStyles.delete(styleId);
      return Boolean(addonHost.removeStyle(styleId));
    },

    listOwnedSlots() {
      if (disposed) {
        return [];
      }
      return [...ownedSlots];
    },

    onDispose(fn) {
      if (disposed || typeof fn !== 'function') {
        return;
      }
      localDisposers.push(fn);
    },

    dispose() {
      if (disposed) {
        return;
      }
      runLocalTeardown();
      addonHost.dispose();
    },
  });
}
