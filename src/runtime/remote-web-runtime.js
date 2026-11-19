import { attachRemotePluginPortBridge } from '../bridges/remote-plugin-port-bridge.js';
import { createDeclarativeSlotRenderer } from '../core/declarative-slot-renderer.js';
import { DiagnosticsBus } from '../core/diagnostics.js';
import { ALLOWED_UI_SLOTS, REMOTE_PLUGIN_CONTRACT_VERSION } from '../core/remote-plugin-contract.js';
import { RemotePluginRegistry } from '../core/remote-plugin-registry.js';
import { DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS } from '../adapters/antigravity/frame-adapter.js';
import { createShadowSurfaceAdapter } from '../adapters/remote-web/shadow-surface-adapter.js';
import { isOriginAllowed } from '../security/origin-policy.js';
import { createPluginHandshakeHost } from '../security/plugin-handshake.js';

export const REMOTE_HOST_VERSION = '2.0.0';

// F2: Module-private WeakMap tracks verified host instances per window without trusting window globals.
const mountedHostsByWindow = new WeakMap();

/**
 * Pure, side-effect-free Remote Web composition root for the RemotePlugin.v1 slot host.
 *
 * Security invariants:
 * - Verifies `isOriginAllowed(win.location.origin, allowedOrigins)` FIRST before touching any window property.
 * - Uses module-private `WeakMap` for idempotent bookmarklet re-tap toggling (immune to window spoofing).
 * - Exposes ONLY a minimal, non-writable, frozen public registration surface on `window.antigravityRemoteHost`
 *   (no internal renderer/DOM handle, `registry`, `diagnostics`, cross-plugin `unregister`, `issueHandshakeNonce`, or `dispose`).
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

  // F2: Strictly validate origin BEFORE reading/calling anything on `win`.
  const currentOrigin = win.location?.origin || '';
  if (!isOriginAllowed(currentOrigin, allowedOrigins)) {
    return null;
  }

  // Idempotent on repeated bookmarklet taps: check module-private WeakMap first,
  // then a locked-down existing public facade installed by an earlier bookmarklet IIFE on this trusted origin.
  const existing = mountedHostsByWindow.get(win);
  if (existing) {
    existing.toggleDock();
    return existing.publicApi;
  }
  const existingDesc = Object.getOwnPropertyDescriptor(win, 'antigravityRemoteHost');
  if (
    existingDesc &&
    existingDesc.writable === false &&
    existingDesc.enumerable === false &&
    existingDesc.value &&
    existingDesc.value.contractVersion === REMOTE_PLUGIN_CONTRACT_VERSION &&
    typeof existingDesc.value.toggleDock === 'function'
  ) {
    existingDesc.value.toggleDock();
    return existingDesc.value;
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

  const activePortBridges = new Set();
  const handshake = createPluginHandshakeHost({
    win,
    allowedOrigins,
    onPortConnected({ port, origin, pluginId, close }) {
      diagnostics.emit({
        level: 'info',
        code: 'REMOTE_PLUGIN_HANDSHAKE_CONNECTED',
        source: 'runtime.remote-web',
        message: 'Closed MessageChannel handshake established',
        detail: { origin, pluginId },
      });
      const bridge = attachRemotePluginPortBridge({
        port,
        registry,
        diagnostics,
        onClose() {
          activePortBridges.delete(bridge);
          close();
        },
      });
      activePortBridges.add(bridge);
    },
  });

  let disposed = false;

  // Minimal locked-down public surface exposed on window.antigravityRemoteHost.
  const publicApi = Object.freeze({
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    version: REMOTE_HOST_VERSION,
    register(plugin) {
      if (disposed) {
        return () => {};
      }
      return registry.register(plugin, { locale: renderer.getLocale() });
    },
    listSlots() {
      return Object.freeze([...ALLOWED_UI_SLOTS]);
    },
    toggleDock() {
      if (!disposed) {
        renderer.toggleOpen();
      }
    },
    setLocale(locale) {
      if (disposed) {
        return Promise.resolve();
      }
      return renderer.setLocale(locale);
    },
    getLocale() {
      return renderer.getLocale();
    },
  });

  const dispose = () => {
    if (disposed) {
      return;
    }
    disposed = true;
    mountedHostsByWindow.delete(win);
    for (const bridge of [...activePortBridges]) {
      bridge.close();
    }
    activePortBridges.clear();
    handshake.dispose();
    registry.dispose();
    surface.dispose();
    if (win.antigravityRemoteHost === publicApi) {
      delete win.antigravityRemoteHost;
    }
  };

  const controller = Object.freeze({
    publicApi,
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    version: REMOTE_HOST_VERSION,
    register: publicApi.register,
    listSlots: publicApi.listSlots,
    listPlugins() {
      return registry.list();
    },
    toggleDock: publicApi.toggleDock,
    setOpen(open) {
      if (!disposed) {
        renderer.setOpen(open);
      }
    },
    isOpen() {
      return renderer.isOpen();
    },
    setLocale: publicApi.setLocale,
    getLocale: publicApi.getLocale,
    activePortCount() {
      return handshake.activePortCount();
    },
    dispose,
  });

  mountedHostsByWindow.set(win, controller);
  Object.defineProperty(win, 'antigravityRemoteHost', {
    value: publicApi,
    writable: false,
    enumerable: false,
    configurable: true,
  });

  return controller;
}
