import { isOriginAllowed, SecurityPolicyError } from './origin-policy.js';

const FORBIDDEN_PROTOCOLS = new Set([
  'javascript:',
  'data:',
  'vbscript:',
  'file:',
  'blob:',
]);

export function isTrustedScriptUrl(rawUrl, allowlist) {
  if (typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_err) {
    return false;
  }
  const proto = parsed.protocol.toLowerCase();
  if (FORBIDDEN_PROTOCOLS.has(proto)) {
    return false;
  }
  if (proto !== 'https:' && proto !== 'http:') {
    return false;
  }
  return isOriginAllowed(parsed.origin, allowlist);
}

export function assertTrustedScriptUrl(rawUrl, allowlist) {
  if (!isTrustedScriptUrl(rawUrl, allowlist)) {
    throw new SecurityPolicyError(
      'UNTRUSTED_SCRIPT_URL',
      'Blocked script URL outside trusted origin allowlist.',
    );
  }
}

/**
 * Guards Worker / AudioWorklet bootstrap Blob URL creation by requiring
 * the underlying script URL to pass `isTrustedScriptUrl` first.
 */
export function createGuardedWorkerBlobUrl({
  scriptUrl,
  allowlist,
  createBlobUrl,
  trustedTypesPolicy = null,
}) {
  assertTrustedScriptUrl(scriptUrl, allowlist);
  if (typeof createBlobUrl !== 'function') {
    throw new SecurityPolicyError(
      'MISSING_BLOB_FACTORY',
      'A Blob URL factory function is required.',
    );
  }
  const validatedUrl = trustedTypesPolicy
    ? trustedTypesPolicy.createScriptURL(scriptUrl)
    : scriptUrl;
  return createBlobUrl(String(validatedUrl));
}
