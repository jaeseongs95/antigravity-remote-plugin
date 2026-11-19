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

/**
 * Validates a `blob:` URL whose embedded origin belongs to the trusted allowlist.
 * Used for Worker / AudioWorklet Blob URLs after their source script URL has
 * already passed `isTrustedScriptUrl`.
 */
export function isTrustedBlobUrl(rawUrl, allowlist) {
  if (typeof rawUrl !== 'string' || !rawUrl.startsWith('blob:')) {
    return false;
  }
  const inner = rawUrl.slice('blob:'.length);
  let parsed;
  try {
    parsed = new URL(inner);
  } catch (_err) {
    return false;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return false;
  }
  return isOriginAllowed(parsed.origin, allowlist);
}

export function isTrustedWorkerOrScriptUrl(rawUrl, allowlist) {
  return isTrustedScriptUrl(rawUrl, allowlist) || isTrustedBlobUrl(rawUrl, allowlist);
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
 * Guards Worker / AudioWorklet bootstrap Blob URL creation:
 * 1) Validates `scriptUrl` against `isTrustedScriptUrl` (fail-closed).
 * 2) Calls `createBlobUrl(scriptUrl)` to mint the `blob:` URL.
 * 3) If `trustedTypesPolicy` is provided, wraps the resulting `blob:` URL via
 *    `trustedTypesPolicy.createScriptURL(blobUrl)` and returns the native
 *    TrustedScriptURL object intact (never coerced with String()).
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
  const rawBlobUrl = createBlobUrl(scriptUrl);
  if (!isTrustedBlobUrl(rawBlobUrl, allowlist)) {
    throw new SecurityPolicyError(
      'UNTRUSTED_SCRIPT_URL',
      'Generated Worker Blob URL failed trusted origin allowlist validation.',
    );
  }
  if (trustedTypesPolicy) {
    return trustedTypesPolicy.createScriptURL(rawBlobUrl);
  }
  return rawBlobUrl;
}
