import { DisposableStore } from '../core/lifecycle.js';
import {
  validateSidecarRelayPort,
  validateThemeWorkspaceSyncPort,
} from '../core/ports.js';
import { createSafeElement } from '../security/dom-guard.js';
import {
  formatHostForUrl,
  isOriginAllowed,
  normalizeOrigin,
  SecurityPolicyError,
} from '../security/origin-policy.js';

export const ALLOWED_SIDECAR_INBOUND_EVENTS = Object.freeze([
  'sidecar-key-event',
  'toggle-aux-pane',
  'toggle-conversation',
  'add-artifact-comment',
  'request-credential-refresh',
]);

export const DEFAULT_ALLOWED_API_PATHS = Object.freeze([
  '/api/telemetry',
  '/api/context-limit',
  '/api/compact',
]);

function deriveSidecarOrigin(sidecar) {
  const host = formatHostForUrl(sidecar.host || '127.0.0.1');
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError('INVALID_SIDECAR_PORT', 'Sidecar port must be a valid TCP port.');
  }
  return `http://${host}:${port}`.toLowerCase();
}

/**
 * Vendor-independent sidecar UI and JSON API relay bridge.
 * Wires ThemeWorkspaceSyncPort + window message listener + exact activeSidecar
 * origin & source validation, with deterministic DisposableStore teardown.
 */
export function createSidecarUiBridge({
  id,
  pluginName,
  sidecarId,
  relayPort,
  themeWorkspacePort = null,
  allowedOrigins = [],
  allowedApiPaths = DEFAULT_ALLOWED_API_PATHS,
  conversationIdProvider = null,
  onInboundEvent = null,
}) {
  validateSidecarRelayPort(relayPort);
  if (themeWorkspacePort !== null) {
    validateThemeWorkspaceSyncPort(themeWorkspacePort);
  }

  const permittedPaths = new Set(allowedApiPaths);
  const permittedEvents = new Set(ALLOWED_SIDECAR_INBOUND_EVENTS);
  let activeSidecar = null;
  let activeSidecarOrigin = null;
  let activeDiagnostics = null;
  let mountedIframe = null;
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
      store = new DisposableStore({ diagnostics });

      // If a host frame with DOM is available, mount the sidecar iframe and wire listeners.
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
        mountedIframe = iframe;

        const targetWin = iframe.contentWindow || null;
        if (targetWin) {
          pushThemeAndWorkspace(targetWin);
        }
      }

      // Wire ThemeWorkspaceSyncPort live updates.
      if (themeWorkspacePort) {
        const unsubSync = themeWorkspacePort.subscribe((change) => {
          const targetWin = mountedIframe?.contentWindow || null;
          if (!targetWin || !activeSidecarOrigin) {
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
          const expectedSource = mountedIframe?.contentWindow || null;
          this.handleInboundMessage(event, expectedSource);
        };
        frame.win.addEventListener('message', onMessage);
        store.add(() => {
          if (typeof frame.win.removeEventListener === 'function') {
            frame.win.removeEventListener('message', onMessage);
          }
        });
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
      const requiredSource = expectedSource ?? mountedIframe?.contentWindow ?? null;
      if (requiredSource && event.source !== requiredSource) {
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
      activeSidecar = null;
      activeSidecarOrigin = null;
      activeDiagnostics = null;
    },
  };
}
