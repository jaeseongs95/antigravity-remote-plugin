import { mountDesktopCompanionView } from '../core/desktop-companion-view.js';
import { createAddonHostSurfaceAdapter } from '../adapters/addon-host/addon-host-surface-adapter.js';

export const DESKTOP_SETTINGS_SLOT_ID = 'antigravity-remote-plugin.settings';

/**
 * Pure, side-effect-free Desktop AddonManifest.v1 composition root.
 * Delegates strictly to the host-injected `addonHost` capability handle.
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
    diagnostics = null,
  } = {},
) {
  const surface = createAddonHostSurfaceAdapter(addonHost, { diagnostics });
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
