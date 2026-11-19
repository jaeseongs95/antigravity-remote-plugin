import { DisposableStore } from '../core/lifecycle.js';
import { validateSidecarRelayPort } from '../core/ports.js';
import { isOriginAllowed, SecurityPolicyError } from '../security/origin-policy.js';

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

/**
 * Vendor-independent sidecar UI and JSON API relay bridge.
 * Compatible with standard sidecar preload postMessage contracts (`theme-change`,
 * `workspace-change`) and strict origin/source validation.
 */
export function createSidecarUiBridge({
  id,
  pluginName,
  sidecarId,
  relayPort,
  allowedOrigins,
  allowedApiPaths = DEFAULT_ALLOWED_API_PATHS,
  onInboundEvent = null,
}) {
  validateSidecarRelayPort(relayPort);
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
    throw new SecurityPolicyError(
      'MISSING_ORIGIN_ALLOWLIST',
      `SidecarUiBridge "${id}" requires a non-empty allowedOrigins list.`,
    );
  }

  const permittedPaths = new Set(allowedApiPaths);
  const permittedEvents = new Set(ALLOWED_SIDECAR_INBOUND_EVENTS);
  let activeSidecar = null;
  let activeDiagnostics = null;
  let store = null;

  return {
    id,
    pluginName,
    sidecarId,
    requireSidecar: true,

    async mount({ sidecar, diagnostics }) {
      if (!sidecar) {
        throw new SecurityPolicyError(
          'SIDECAR_NOT_ACTIVE',
          `Cannot mount "${id}": sidecar "${sidecarId}" is not active.`,
        );
      }
      if (store) {
        this.dispose();
      }
      activeSidecar = sidecar;
      activeDiagnostics = diagnostics || null;
      store = new DisposableStore({ diagnostics });
      return { sidecarId: sidecar.sidecarId };
    },

    buildUiUrl({ conversationId }) {
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
      if (!isOriginAllowed(targetOrigin, allowedOrigins)) {
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
      if (!isOriginAllowed(targetOrigin, allowedOrigins)) {
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
      if (!isOriginAllowed(event.origin, allowedOrigins)) {
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
      if (expectedSource && event.source !== expectedSource) {
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
      activeSidecar = null;
      activeDiagnostics = null;
    },
  };
}
