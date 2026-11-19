import { SecurityPolicyError } from './origin-policy.js';

export const RESERVED_TRUSTED_TYPES_POLICIES = Object.freeze([
  'default',
  'dompurify',
  'angular',
]);

export function assertAllowedPolicyName(policyName) {
  if (typeof policyName !== 'string' || policyName.trim().length === 0) {
    throw new SecurityPolicyError(
      'INVALID_TRUSTED_TYPES_POLICY',
      'TrustedTypes policy name must be a non-empty string.',
    );
  }
  const normalized = policyName.trim().toLowerCase();
  if (RESERVED_TRUSTED_TYPES_POLICIES.includes(normalized)) {
    throw new SecurityPolicyError(
      'RESERVED_TRUSTED_TYPES_POLICY',
      `Creating reserved TrustedTypes policy "${policyName}" is forbidden.`,
    );
  }
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(policyName.trim())) {
    throw new SecurityPolicyError(
      'INVALID_TRUSTED_TYPES_POLICY',
      `TrustedTypes policy name "${policyName}" contains invalid characters.`,
    );
  }
}

export function createScopedTrustedTypesPolicy({
  trustedTypesApi,
  policyName = 'remote-bridge-script-v1',
  validateScriptUrl,
}) {
  assertAllowedPolicyName(policyName);
  if (typeof validateScriptUrl !== 'function') {
    throw new SecurityPolicyError(
      'MISSING_SCRIPT_VALIDATOR',
      'A script URL validator function is required to create a TrustedTypes policy.',
    );
  }

  if (!trustedTypesApi || typeof trustedTypesApi.createPolicy !== 'function') {
    return {
      name: policyName,
      isNative: false,
      createScriptURL(url) {
        if (!validateScriptUrl(url)) {
          throw new SecurityPolicyError(
            'UNTRUSTED_SCRIPT_URL',
            'Script URL failed allowlist validation.',
          );
        }
        return url;
      },
    };
  }

  const nativePolicy = trustedTypesApi.createPolicy(policyName, {
    createScriptURL(url) {
      if (!validateScriptUrl(url)) {
        throw new SecurityPolicyError(
          'UNTRUSTED_SCRIPT_URL',
          'Script URL failed allowlist validation.',
        );
      }
      return url;
    },
  });

  return {
    name: policyName,
    isNative: true,
    createScriptURL(url) {
      return nativePolicy.createScriptURL(url);
    },
  };
}
