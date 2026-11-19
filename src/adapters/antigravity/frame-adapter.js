import { EventChain } from '../../core/lifecycle.js';
import {
  assertOriginAllowed,
  normalizeOrigin,
  SecurityPolicyError,
} from '../../security/origin-policy.js';
import {
  createGuardedWorkerBlobUrl,
  isTrustedWorkerOrScriptUrl,
} from '../../security/script-guard.js';
import { createScopedTrustedTypesPolicy } from '../../security/trusted-types.js';

export const DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS = Object.freeze([
  'https://antigravity.google.com',
  'https://*.antigravity.google.com',
]);

function assertValidFrame(frame, allowedOrigins, label) {
  if (!frame || typeof frame !== 'object') {
    throw new SecurityPolicyError('INVALID_FRAME', `Invalid ${label}: expected frame object.`);
  }
  assertOriginAllowed(frame.origin, allowedOrigins, label);
  if (!frame.win || !frame.doc) {
    throw new SecurityPolicyError(
      'INCOMPLETE_FRAME',
      `Invalid ${label}: frame must expose both win and doc.`,
    );
  }
}

export function createAntigravityFrameAdapter({
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  trustedTypesApi = globalThis.trustedTypes ?? null,
  policyName = 'antigravity-remote-bridge-v1',
  hostLoadGuard = null,
  diagnostics = null,
  initialFrame = null,
} = {}) {
  const ttPolicy = createScopedTrustedTypesPolicy({
    trustedTypesApi,
    policyName,
    validateScriptUrl: (url) => isTrustedWorkerOrScriptUrl(url, allowedOrigins),
  });

  const guardFn = typeof hostLoadGuard === 'function' ? hostLoadGuard : null;
  const frameChain = new EventChain({
    hostGuard: null,
    diagnostics,
  });

  let currentFrame = null;
  if (initialFrame !== null) {
    assertValidFrame(initialFrame, allowedOrigins, 'initial remote frame');
    currentFrame = initialFrame;
  }

  function applyAndDispatchFrame(nextFrame) {
    if (guardFn && guardFn(nextFrame) === false) {
      return { allowed: false, invoked: 0 };
    }
    currentFrame = nextFrame;
    return frameChain.dispatch(nextFrame);
  }

  return {
    trustedTypesPolicy: ttPolicy,

    async acquireActiveFrame() {
      if (currentFrame !== null) {
        assertValidFrame(currentFrame, allowedOrigins, 'active remote frame');
      }
      return currentFrame;
    },

    onFrameChange(handler) {
      return frameChain.register(handler, { label: 'frame-change' });
    },

    notifyFramePromoted(nextFrame) {
      if (nextFrame !== null) {
        assertValidFrame(nextFrame, allowedOrigins, 'promoted frame');
      }
      return applyAndDispatchFrame(nextFrame);
    },

    /**
     * Promotes an accessible remote iframe element into a validated frame descriptor
     * (`{ win, doc, origin, iframeEl }`). Translates cross-origin DOMException into
     * `CROSS_ORIGIN_IFRAME_DENIED` and cross-checks `targetOrigin` against actual
     * `iframe.contentWindow.location.origin`.
     */
    promoteRemoteIframe(iframeEl, { targetOrigin = '', conversationId = '' } = {}) {
      if (!iframeEl || typeof iframeEl !== 'object') {
        throw new SecurityPolicyError('INVALID_IFRAME', 'An iframe element is required for promotion.');
      }

      let win;
      let doc;
      let actualOrigin;
      try {
        win = iframeEl.contentWindow;
        actualOrigin = win?.location?.origin || '';
        doc = iframeEl.contentDocument || win?.document;
      } catch (_err) {
        throw new SecurityPolicyError(
          'CROSS_ORIGIN_IFRAME_DENIED',
          'Cannot access cross-origin iframe document without host-sanctioned promotion.',
        );
      }

      if (!win || !doc) {
        throw new SecurityPolicyError(
          'UNAVAILABLE_IFRAME_DOCUMENT',
          'Remote iframe does not expose an accessible contentWindow/contentDocument.',
        );
      }

      if (!actualOrigin || actualOrigin === 'null') {
        throw new SecurityPolicyError(
          'UNAVAILABLE_IFRAME_ORIGIN',
          'Remote iframe does not expose a verifiable origin.',
        );
      }

      const resolvedOrigin = targetOrigin || actualOrigin;
      assertOriginAllowed(resolvedOrigin, allowedOrigins, 'remote iframe');

      if (targetOrigin) {
        const expectedNorm = normalizeOrigin(targetOrigin);
        const actualNorm = normalizeOrigin(actualOrigin);
        if (!expectedNorm || !actualNorm || expectedNorm.origin !== actualNorm.origin) {
          throw new SecurityPolicyError(
            'ORIGIN_MISMATCH',
            'Supplied targetOrigin does not match the actual accessible iframe origin.',
          );
        }
      }

      const promoted = {
        win,
        doc,
        origin: resolvedOrigin,
        iframeEl,
        conversationId,
      };
      const dispatchResult = applyAndDispatchFrame(promoted);
      return dispatchResult.allowed ? promoted : null;
    },

    createSafeWorkerBlobUrl({ scriptUrl, createBlobUrl }) {
      return createGuardedWorkerBlobUrl({
        scriptUrl,
        allowlist: allowedOrigins,
        createBlobUrl,
        trustedTypesPolicy: ttPolicy,
      });
    },
  };
}
