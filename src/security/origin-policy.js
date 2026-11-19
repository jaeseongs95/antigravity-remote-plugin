export class SecurityPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SecurityPolicyError';
    this.code = code;
  }
}

export function normalizeOrigin(rawOrigin) {
  if (typeof rawOrigin !== 'string' || rawOrigin.trim().length === 0) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(rawOrigin);
  } catch (_err) {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return null;
  }
  return {
    origin: parsed.origin.toLowerCase(),
    protocol: parsed.protocol.toLowerCase(),
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port || '',
  };
}

export function isLoopbackHostname(hostname) {
  if (typeof hostname !== 'string') {
    return false;
  }
  const lower = hostname.toLowerCase();
  return lower === '127.0.0.1' || lower === 'localhost' || lower === '[::1]' || lower === '::1';
}

export function matchesDomainBoundary(hostname, rule) {
  if (typeof hostname !== 'string' || typeof rule !== 'string') {
    return false;
  }
  const host = hostname.toLowerCase();
  const pattern = rule.trim().toLowerCase();
  if (!pattern) {
    return false;
  }
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    if (!suffix || suffix.includes('*')) {
      return false;
    }
    return host.length > suffix.length + 1 && host.endsWith(`.${suffix}`);
  }
  return host === pattern;
}

/**
 * Checks whether `candidateOrigin` satisfies an explicit allowlist.
 * Supports exact origins (e.g., "https://host.example"), wildcard subdomain
 * patterns with scheme ("https://*.example.com"), or loopback ("http://127.0.0.1:*").
 * Never performs substring matching.
 */
export function isOriginAllowed(candidateOrigin, allowlist) {
  const candidate = normalizeOrigin(candidateOrigin);
  if (!candidate || !Array.isArray(allowlist) || allowlist.length === 0) {
    return false;
  }

  for (const rawRule of allowlist) {
    if (typeof rawRule !== 'string') {
      continue;
    }
    const rule = rawRule.trim().toLowerCase();
    if (!rule) {
      continue;
    }

    if (rule.startsWith('https://*.')) {
      if (candidate.protocol !== 'https:') {
        continue;
      }
      const hostPattern = rule.slice('https://'.length);
      if (matchesDomainBoundary(candidate.hostname, hostPattern) && candidate.port === '') {
        return true;
      }
      continue;
    }

    if (rule === 'http://127.0.0.1:*' || rule === 'http://localhost:*') {
      if (candidate.protocol !== 'http:') {
        continue;
      }
      const expectedHost = rule.startsWith('http://127.0.0.1') ? '127.0.0.1' : 'localhost';
      if (candidate.hostname === expectedHost) {
        return true;
      }
      continue;
    }

    const normalizedRule = normalizeOrigin(rule);
    if (!normalizedRule) {
      continue;
    }
    if (candidate.origin === normalizedRule.origin) {
      return true;
    }
  }

  return false;
}

export function assertOriginAllowed(candidateOrigin, allowlist, context = 'origin') {
  if (!isOriginAllowed(candidateOrigin, allowlist)) {
    throw new SecurityPolicyError(
      'ORIGIN_NOT_ALLOWED',
      `Blocked untrusted ${context}: origin is not in the allowlist.`,
    );
  }
}
