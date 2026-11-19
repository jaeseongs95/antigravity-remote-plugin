import { assertPort } from '../../core/ports.js';
import { SecurityPolicyError } from '../../security/origin-policy.js';

const REQUIRED_ADDON_HOST_METHODS = Object.freeze([
  'mountSlot',
  'unmountSlot',
  'injectStyle',
  'removeStyle',
  'onDispose',
  'dispose',
]);

/**
 * Desktop AddonManifest.v1 adapter implementing HostSurfacePort strictly
 * through the scoped capability handle (`addonHost`) injected by the host loader.
 * Never touches document.head, host binary archives, or unowned DOM directly.
 */
export function createAddonHostSurfaceAdapter(addonHost) {
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
      return [...ownedSlots];
    },

    onDispose(fn) {
      if (disposed || typeof fn !== 'function') {
        return;
      }
      addonHost.onDispose(fn);
    },

    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      ownedSlots.clear();
      ownedStyles.clear();
      addonHost.dispose();
    },
  });
}
