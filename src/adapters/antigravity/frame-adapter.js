import { EventChain } from '../../core/lifecycle.js';
import { assertOriginAllowed, SecurityPolicyError } from '../../security/origin-policy.js';
import { createGuardedWorkerBlobUrl, isTrustedScriptUrl } from '../../security/script-guard.js';
import { createScopedTrustedTypesPolicy } from '../../security/trusted-types.js';

export const DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS = Object.freeze([
  'https://antigravity.google.com',
  'https://*.antigravity.google.com',
]);

function assertValidFrame(frame, allowedOrigins, label) {
  if (!frame || typeof frame !== 'object') {
    throw new SecurityPolicyError('INVALID_FRAME', `Invalid ${label}: expected frame object.`);
  }
  // Fail-closed: origin is mandatory on every non-null frame.
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
  trustedTypesApi = null,
  policyName = 'antigravity-remote-bridge-v1',
  hostLoadGuard = null,
  diagnostics = null,
  initialFrame = null,
} = {}) {
  const ttPolicy = createScopedTrustedTypesPolicy({
    trustedTypesApi,
    policyName,
    validateScriptUrl: (url) => isTrustedScriptUrl(url, allowedOrigins),
  });

  const frameChain = new EventChain({
    hostGuard: hostLoadGuard,
    diagnostics,
  });

  let currentFrame = null;
  if (initialFrame !== null) {
    assertValidFrame(initialFrame, allowedOrigins, 'initial remote frame');
    currentFrame = initialFrame;
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
      currentFrame = nextFrame;
      return frameChain.dispatch(nextFrame);
    },

    /**
     * Promotes a same-origin / accessible remote iframe element into a validated
     * frame descriptor (`{ win, doc, origin, iframeEl }`) and notifies subscribers.
     * Never uses `document.write`, `<base>`, or cross-origin bypasses.
     */
    promoteRemoteIframe(iframeEl, { targetOrigin, conversationId = '' } = {}) {
      if (!iframeEl || typeof iframeEl !== 'object') {
        throw new SecurityPolicyError('INVALID_IFRAME', 'An iframe element is required for promotion.');
      }
      const resolvedOrigin = targetOrigin || iframeEl.contentWindow?.location?.origin || '';
      assertOriginAllowed(resolvedOrigin, allowedOrigins, 'remote iframe');

      let win;
      let doc;
      try {
        win = iframeEl.contentWindow;
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

      const promoted = {
        win,
        doc,
        origin: resolvedOrigin,
        iframeEl,
        conversationId,
      };
      currentFrame = promoted;
      frameChain.dispatch(promoted);
      return promoted;
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
