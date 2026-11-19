import { createDeclarativeSlotRenderer } from '../core/declarative-slot-renderer.js';
import { mountDesktopCompanionView } from '../core/desktop-companion-view.js';
import { DiagnosticsBus } from '../core/diagnostics.js';
import { ALLOWED_UI_SLOTS, REMOTE_PLUGIN_CONTRACT_VERSION } from '../core/remote-plugin-contract.js';
import { RemotePluginRegistry } from '../core/remote-plugin-registry.js';
import { createAddonHostSurfaceAdapter } from '../adapters/addon-host/addon-host-surface-adapter.js';
import { DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS } from '../adapters/antigravity/frame-adapter.js';
import { createShadowSurfaceAdapter } from '../adapters/remote-web/shadow-surface-adapter.js';
import { isOriginAllowed } from '../security/origin-policy.js';
import { createPluginHandshakeHost } from '../security/plugin-handshake.js';

export const REMOTE_HOST_VERSION = '2.0.0';
export const DESKTOP_SETTINGS_SLOT_ID = 'antigravity-remote-plugin.settings';

/**
 * Pure, side-effect-free entry for mounting the RemotePlugin.v1 slot-based host
 * on allowed remote web origins. Contains zero production test hooks (`window.__ARP_*`).
 */
export function mountRemotePluginHost({
  win = globalThis.window,
  doc = globalThis.document,
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  initialLocale = 'ko',
  ownerId = 'antigravity-remote-plugin',
} = {}) {
  if (!win || !doc) {
    return null;
  }

  // Idempotent on repeated bookmarklet taps: toggle drawer without duplicating DOM.
  if (win.antigravityRemoteHost && typeof win.antigravityRemoteHost.toggleDock === 'function') {
    win.antigravityRemoteHost.toggleDock();
    return win.antigravityRemoteHost;
  }

  const currentOrigin = win.location?.origin || '';
  if (!isOriginAllowed(currentOrigin, allowedOrigins)) {
    return null;
  }

  const diagnostics = new DiagnosticsBus();
  const registry = new RemotePluginRegistry({ diagnostics });
  const surface = createShadowSurfaceAdapter({ doc, ownerId, diagnostics });
  const renderer = createDeclarativeSlotRenderer({
    win,
    doc,
    surface,
    registry,
    initialLocale,
  });

  const handshake = createPluginHandshakeHost({
    win,
    allowedOrigins,
    onPortConnected({ port, origin, pluginId }) {
      diagnostics.emit({
        level: 'info',
        code: 'REMOTE_PLUGIN_HANDSHAKE_CONNECTED',
        source: 'runtime.remote-host',
        message: 'Closed MessageChannel handshake established',
        detail: { origin, pluginId },
      });
      port.onmessage = (msgEvent) => {
        const msg = msgEvent?.data;
        if (!msg || typeof msg !== 'object') {
          return;
        }
        if (msg.type === 'remote-plugin-v1:list') {
          port.postMessage({
            type: 'remote-plugin-v1:list-result',
            plugins: registry.list().map((p) => ({
              id: p.id,
              version: p.version,
              uiSlot: p.uiSlot,
              capabilities: p.capabilities,
            })),
          });
        }
      };
    },
  });

  let disposed = false;
  const handle = Object.freeze({
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    version: REMOTE_HOST_VERSION,
    registry,
    renderer,
    diagnostics,
    register(plugin) {
      return registry.register(plugin, { locale: renderer.getLocale() });
    },
    unregister(pluginId) {
      return registry.unregister(pluginId);
    },
    listPlugins() {
      return registry.list();
    },
    listSlots() {
      return [...ALLOWED_UI_SLOTS];
    },
    toggleDock() {
      renderer.toggleOpen();
    },
    setOpen(open) {
      renderer.setOpen(open);
    },
    setLocale(locale) {
      return renderer.setLocale(locale);
    },
    getLocale() {
      return renderer.getLocale();
    },
    issueHandshakeNonce() {
      return handshake.issueNonce();
    },
    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      handshake.dispose();
      registry.dispose();
      surface.dispose();
      if (win.antigravityRemoteHost === handle) {
        delete win.antigravityRemoteHost;
      }
    },
  });

  win.antigravityRemoteHost = handle;
  return handle;
}

/**
 * Pure, side-effect-free entry for mounting the Desktop AddonManifest.v1 Option A
 * renderer strictly through the host-injected `addonHost` capability handle.
 */
export function mountDesktopAddon(
  addonHost,
  {
    doc = globalThis.document,
    clipboard = globalThis.navigator?.clipboard ?? null,
    remoteArtifacts = {
      bookmarklet: 'dist/bookmarklet.txt',
      userscriptPath: 'dist/antigravity-remote.user.js',
    },
    initialLocale = 'ko',
  } = {},
) {
  const surface = createAddonHostSurfaceAdapter(addonHost);
  const view = mountDesktopCompanionView({
    doc,
    surface,
    slotId: DESKTOP_SETTINGS_SLOT_ID,
    hostInfo: {
      hostProfileId: surface.hostProfileId,
      hostVersion: surface.hostVersion,
    },
    remoteArtifacts,
    clipboard,
    initialLocale,
  });

  return Object.freeze({
    pluginId: surface.pluginId,
    slotId: DESKTOP_SETTINGS_SLOT_ID,
    surface,
    view,
    dispose() {
      surface.dispose();
    },
  });
}
