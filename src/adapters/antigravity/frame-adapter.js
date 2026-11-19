import { EventChain } from '../../core/lifecycle.js';
import { assertOriginAllowed } from '../../security/origin-policy.js';
import { createGuardedWorkerBlobUrl, isTrustedScriptUrl } from '../../security/script-guard.js';
import { createScopedTrustedTypesPolicy } from '../../security/trusted-types.js';

export const DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS = Object.freeze([
  'https://antigravity.google.com',
  'https://*.antigravity.google.com',
]);

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

  let currentFrame = initialFrame;

  return {
    trustedTypesPolicy: ttPolicy,

    async acquireActiveFrame() {
      if (currentFrame && currentFrame.origin) {
        assertOriginAllowed(currentFrame.origin, allowedOrigins, 'remote frame');
      }
      return currentFrame;
    },

    onFrameChange(handler) {
      return frameChain.register(handler, { label: 'frame-change' });
    },

    notifyFramePromoted(nextFrame) {
      if (nextFrame && nextFrame.origin) {
        assertOriginAllowed(nextFrame.origin, allowedOrigins, 'promoted frame');
      }
      currentFrame = nextFrame;
      return frameChain.dispatch(nextFrame);
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
