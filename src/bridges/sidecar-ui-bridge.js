import { DisposableStore } from '../core/lifecycle.js';
import {
  validateSidecarRelayPort,
  validateThemeWorkspaceSyncPort,
} from '../core/ports.js';
import { createSafeElement } from '../security/dom-guard.js';
import {
  formatHostForUrl,
  isLoopbackHostname,
  isOriginAllowed,
  normalizeOrigin,
  SecurityPolicyError,
} from '../security/origin-policy.js';

export function deriveSidecarOrigin(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') {
    throw new SecurityPolicyError('INVALID_SIDECAR', 'Sidecar descriptor is required.');
  }
  const rawHost = sidecar.host || '127.0.0.1';
  if (!isLoopbackHostname(rawHost)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_SIDECAR',
      'Sidecar bridge only permits loopback sidecar origins.',
    );
  }
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError('INVALID_SIDECAR_PORT', 'Sidecar port must be a valid TCP port.');
  }
  const host = formatHostForUrl(rawHost);
  let parsed;
  try {
    parsed = new URL(`http://${host}:${port}/`);
  } catch (_err) {
    throw new SecurityPolicyError('INVALID_SIDECAR_ORIGIN', 'Sidecar origin is not a valid URL.');
  }
  // Normalizes default port 80 (http://127.0.0.1:80 -> http://127.0.0.1) to match browser event.origin.
  return parsed.origin.toLowerCase();
}

/**
 * Vendor- and domain-independent sidecar UI and JSON API relay bridge.
 * Defers initial theme/workspace postMessage until iframe `load` completes,
 * validates exact normalized loopback sidecar origin, and enforces fail-closed
 * `event.source` matching whenever an iframe is mounted.
 */
export function createSidecarUiBridge({
  id,
  pluginName,
  sidecarId,
  relayPort,
  themeWorkspacePort = null,
  allowedOrigins = [],
  allowedApiPaths = [],
  allowedInboundEvents = [],
  conversationIdProvider = null,
  onInboundEvent = null,
}) {
  validateSidecarRelayPort(relayPort);
  if (themeWorkspacePort !== null) {
    validateThemeWorkspaceSyncPort(themeWorkspacePort);
  }
  if (!Array.isArray(allowedApiPaths)) {
    throw new TypeError(`SidecarUiBridge "${id}" requires an allowedApiPaths array.`);
  }
  if (!Array.isArray(allowedInboundEvents)) {
    throw new TypeError(`SidecarUiBridge "${id}" requires an allowedInboundEvents array.`);
  }

  const permittedPaths = new Set(allowedApiPaths);
  const permittedEvents = new Set(allowedInboundEvents);
  let activeSidecar = null;
  let activeSidecarOrigin = null;
  let activeDiagnostics = null;
  let mountedIframe = null;
  let iframeLoaded = false;
  let store = null;

  function isOriginTrustedForActiveSidecar(candidateOrigin) {
    const normalized = normalizeOrigin(candidateOrigin);
    if (!normalized) {
      return false;
    }
    if (activeSidecarOrigin && normalized.origin === activeSidecarOrigin) {
      return true;
    }
    return Array.isArray(allowedOrigins) && allowedOrigins.length > 0
      ? isOriginAllowed(normalized.origin, allowedOrigins)
      : false;
  }

  function pushThemeAndWorkspace(targetWindow) {
    if (!targetWindow || typeof targetWindow.postMessage !== 'function' || !activeSidecarOrigin) {
      return;
    }
    if (!themeWorkspacePort) {
      return;
    }
    const vars = themeWorkspacePort.getThemeVariables();
    if (vars && typeof vars === 'object') {
      targetWindow.postMessage(
        { type: 'theme-change', payload: { cssVariables: { ...vars } } },
        activeSidecarOrigin,
      );
    }
    const uris = themeWorkspacePort.getWorkspaceUris();
    targetWindow.postMessage(
      { type: 'workspace-change', payload: { workspaceUris: Array.isArray(uris) ? [...uris] : [] } },
      activeSidecarOrigin,
    );
  }

  return {
    id,
    pluginName,
    sidecarId,
    requireSidecar: true,

    getActiveOrigin() {
      return activeSidecarOrigin;
    },

    getMountedIframe() {
      return mountedIframe;
    },

    async mount({ frame = null, sidecar, diagnostics }) {
      if (!sidecar) {
        throw new SecurityPolicyError(
          'SIDECAR_NOT_ACTIVE',
          `Cannot mount "${id}": sidecar "${sidecarId}" is not active.`,
        );
      }
      if (store) {
        this.dispose();
      }

      const sidecarOrigin = deriveSidecarOrigin(sidecar);
      activeSidecar = sidecar;
      activeSidecarOrigin = sidecarOrigin;
      activeDiagnostics = diagnostics || null;
      iframeLoaded = false;
      store = new DisposableStore({ diagnostics });

      try {
        // If a host frame with DOM is available, mount the sidecar iframe and wait for `load`.
        if (frame && frame.doc && typeof frame.doc.createElement === 'function') {
          const conversationId = typeof conversationIdProvider === 'function'
            ? conversationIdProvider()
            : (frame.conversationId || '');
          const uiUrl = relayPort.buildUiUrl({ sidecar, conversationId });
          const iframe = createSafeElement(frame.doc, 'iframe', {
            attrs: {
              src: uiUrl,
              'data-remote-sidecar-id': sidecarId,
              sandbox: 'allow-scripts allow-same-origin allow-forms',
            },
          });
          mountedIframe = iframe;

          const hasLoadEvents = typeof iframe.addEventListener === 'function';
          if (hasLoadEvents) {
            const onLoad = () => {
              iframeLoaded = true;
              if (mountedIframe === iframe && iframe.contentWindow) {
                pushThemeAndWorkspace(iframe.contentWindow);
              }
            };
            iframe.addEventListener('load', onLoad);
            store.add(() => {
              if (typeof iframe.removeEventListener === 'function') {
                iframe.removeEventListener('load', onLoad);
              }
            });
          }

          const mountContainer = frame.panelContainer || frame.doc.body || null;
          if (mountContainer && typeof mountContainer.appendChild === 'function') {
            mountContainer.appendChild(iframe);
            store.add(() => {
              if (typeof iframe.remove === 'function') {
                iframe.remove();
              } else if (mountContainer && typeof mountContainer.removeChild === 'function') {
                mountContainer.removeChild(iframe);
              }
            });
          }

          // Only push synchronously if the host element does not emit DOM load events.
          if (!hasLoadEvents && iframe.contentWindow) {
            iframeLoaded = true;
            pushThemeAndWorkspace(iframe.contentWindow);
          }
        }

        // Wire ThemeWorkspaceSyncPort live updates (delivered once iframe is loaded).
        if (themeWorkspacePort) {
          const unsubSync = themeWorkspacePort.subscribe((change) => {
            const targetWin = mountedIframe?.contentWindow || null;
            if (!targetWin || !activeSidecarOrigin || !iframeLoaded) {
              return;
            }
            if (change?.type === 'theme-change') {
              this.postThemeChange(targetWin, activeSidecarOrigin, change.cssVariables);
            } else if (change?.type === 'workspace-change') {
              this.postWorkspaceChange(targetWin, activeSidecarOrigin, change.workspaceUris);
            }
          });
          if (typeof unsubSync === 'function') {
            store.add(unsubSync);
          }
        }

        // Wire host window message listener for inbound sidecar preload events.
        if (frame && frame.win && typeof frame.win.addEventListener === 'function') {
          const onMessage = (event) => {
            this.handleInboundMessage(event);
          };
          frame.win.addEventListener('message', onMessage);
          store.add(() => {
            if (typeof frame.win.removeEventListener === 'function') {
              frame.win.removeEventListener('message', onMessage);
            }
          });
        }
      } catch (mountErr) {
        this.dispose();
        throw mountErr;
      }

      return { sidecarId: sidecar.sidecarId, origin: sidecarOrigin };
    },

    buildUiUrl({ conversationId = '' } = {}) {
      if (!activeSidecar) {
        throw new SecurityPolicyError('BRIDGE_NOT_MOUNTED', `Bridge "${id}" is not mounted.`);
      }
      return relayPort.buildUiUrl({
        sidecar: activeSidecar,
        conversationId,
      });
    },

    async relayApi(path, payload = {}, method = 'POST') {
      if (!activeSidecar) {
        throw new SecurityPolicyError('BRIDGE_NOT_MOUNTED', `Bridge "${id}" is not mounted.`);
      }
      if (!permittedPaths.has(path)) {
        throw new SecurityPolicyError(
          'API_PATH_NOT_ALLOWED',
          `Blocked sidecar API path "${path}" outside allowlist.`,
        );
      }
      return relayPort.requestJson({
        sidecar: activeSidecar,
        path,
        method,
        body: payload,
      });
    },

    postThemeChange(targetWindow, targetOrigin, cssVariables) {
      if (!isOriginTrustedForActiveSidecar(targetOrigin)) {
        throw new SecurityPolicyError(
          'ORIGIN_NOT_ALLOWED',
          'Refused to post theme-change to untrusted origin.',
        );
      }
      targetWindow.postMessage(
        {
          type: 'theme-change',
          payload: { cssVariables: { ...(cssVariables || {}) } },
        },
        targetOrigin,
      );
    },

    postWorkspaceChange(targetWindow, targetOrigin, workspaceUris) {
      if (!isOriginTrustedForActiveSidecar(targetOrigin)) {
        throw new SecurityPolicyError(
          'ORIGIN_NOT_ALLOWED',
          'Refused to post workspace-change to untrusted origin.',
        );
      }
      targetWindow.postMessage(
        {
          type: 'workspace-change',
          payload: { workspaceUris: Array.isArray(workspaceUris) ? [...workspaceUris] : [] },
        },
        targetOrigin,
      );
    },

    handleInboundMessage(event, expectedSource = null) {
      if (!event || typeof event !== 'object') {
        return { accepted: false, reason: 'INVALID_EVENT' };
      }
      if (!activeSidecarOrigin || !isOriginTrustedForActiveSidecar(event.origin)) {
        if (activeDiagnostics) {
          activeDiagnostics.emit({
            level: 'warn',
            code: 'UNTRUSTED_POSTMESSAGE_ORIGIN',
            source: `bridge.${id}`,
            message: 'Dropped inbound postMessage from untrusted origin',
            detail: { origin: event.origin },
          });
        }
        return { accepted: false, reason: 'UNTRUSTED_ORIGIN' };
      }

      // Fail-closed source check: require an explicit expectedSource or mounted iframe contentWindow.
      const requiredSource = expectedSource ?? mountedIframe?.contentWindow ?? null;
      if (!requiredSource) {
        return { accepted: false, reason: 'SOURCE_UNAVAILABLE' };
      }
      if (event.source !== requiredSource) {
        if (activeDiagnostics) {
          activeDiagnostics.emit({
            level: 'warn',
            code: 'POSTMESSAGE_SOURCE_MISMATCH',
            source: `bridge.${id}`,
            message: 'Dropped inbound postMessage from unexpected window source',
            detail: { origin: event.origin },
          });
        }
        return { accepted: false, reason: 'SOURCE_MISMATCH' };
      }

      const type = event.data?.type;
      if (typeof type !== 'string' || !permittedEvents.has(type)) {
        return { accepted: false, reason: 'UNSUPPORTED_EVENT_TYPE' };
      }
      if (typeof onInboundEvent === 'function') {
        onInboundEvent({ type, payload: event.data.payload ?? null });
      }
      return { accepted: true, type };
    },

    dispose() {
      if (store) {
        const currentStore = store;
        store = null;
        currentStore.dispose();
      }
      mountedIframe = null;
      iframeLoaded = false;
      activeSidecar = null;
      activeSidecarOrigin = null;
      activeDiagnostics = null;
    },
  };
}
