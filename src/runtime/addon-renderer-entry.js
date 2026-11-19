import { mountDesktopAddon } from './desktop-addon-runtime.js';

/* global addonHost, __ARP_EMBEDDED_BOOKMARKLET__ */
const EMBEDDED_BOOKMARKLET =
  typeof __ARP_EMBEDDED_BOOKMARKLET__ === 'string' && __ARP_EMBEDDED_BOOKMARKLET__.length > 0
    ? __ARP_EMBEDDED_BOOKMARKLET__
    : 'dist/bookmarklet.txt';

if (typeof addonHost !== 'undefined' && typeof document !== 'undefined') {
  mountDesktopAddon(addonHost, {
    doc: document,
    clipboard: typeof navigator !== 'undefined' && navigator.clipboard ? navigator.clipboard : null,
    remoteArtifacts: {
      bookmarklet: EMBEDDED_BOOKMARKLET,
      userscriptPath: 'dist/antigravity-remote.user.js',
    },
  });
}
