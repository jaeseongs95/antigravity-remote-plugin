const SENSITIVE_KEY_PATTERN =
  /^(authorization|cookie|set-cookie|token|access_token|refresh_token|csrf|csrf_token|x-sidecar-token|x-csrf-token|x-api-key|api_key|apikey|secret|password|passwd|env|headers)$/i;

const SENSITIVE_SUBSTRING_PATTERN =
  /(token|secret|password|passwd|csrf|authorization|apikey|api_key)/i;

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'access_token',
  'refresh_token',
  'csrf',
  'csrf_token',
  'api_key',
  'apikey',
  'secret',
  'key',
  'password',
  'passwd',
  'x-sidecar-token',
]);

const INLINE_PARAM_PATTERN =
  /([?&#](?:token|access_token|refresh_token|csrf|csrf_token|api_key|apikey|secret|key|password|passwd|x-sidecar-token)=)([^&#]*)/gi;

const INLINE_USERINFO_PATTERN = /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:)([^/\s@]+)(@)/g;

export const REDACTED = '[REDACTED]';

function redactFragment(hash) {
  if (!hash || hash.length <= 1) {
    return hash;
  }
  return hash.replace(INLINE_PARAM_PATTERN, `$1${REDACTED}`);
}

export function redactUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return rawUrl;
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_err) {
    return rawUrl
      .replace(INLINE_USERINFO_PATTERN, `$1${REDACTED}$3`)
      .replace(INLINE_PARAM_PATTERN, `$1${REDACTED}`);
  }
  let mutated = false;
  for (const paramKey of [...parsed.searchParams.keys()]) {
    if (SENSITIVE_QUERY_PARAMS.has(paramKey.toLowerCase())) {
      parsed.searchParams.set(paramKey, REDACTED);
      mutated = true;
    }
  }
  if (parsed.password) {
    parsed.password = REDACTED;
    mutated = true;
  }
  if (parsed.hash) {
    const cleanHash = redactFragment(parsed.hash);
    if (cleanHash !== parsed.hash) {
      parsed.hash = cleanHash;
      mutated = true;
    }
  }
  return mutated ? parsed.toString() : rawUrl;
}

export function isSensitiveKey(key) {
  if (typeof key !== 'string') {
    return false;
  }
  const normalized = key.trim();
  return (
    SENSITIVE_KEY_PATTERN.test(normalized) ||
    SENSITIVE_SUBSTRING_PATTERN.test(normalized)
  );
}

export function redactSecrets(value, depth = 0, seen = new WeakSet()) {
  if (depth > 8) {
    return '[TRUNCATED]';
  }
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return redactUrl(value);
  }
  if (typeof value !== 'object') {
    return value;
  }
  if (seen.has(value)) {
    return '[CIRCULAR]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item, depth + 1, seen));
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactUrl(value.message || ''),
      code: value.code ?? undefined,
    };
  }

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (isSensitiveKey(k)) {
      out[k] = REDACTED;
    } else {
      out[k] = redactSecrets(v, depth + 1, seen);
    }
  }
  return out;
}

export function stripSensitiveDeep(value, depth = 0, seen = new WeakSet()) {
  if (depth > 8 || value === null || value === undefined || typeof value === 'function') {
    return undefined;
  }
  if (typeof value !== 'object') {
    return value;
  }
  if (seen.has(value)) {
    return undefined;
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const arr = [];
      for (const item of value) {
        if (typeof item === 'function') {
          continue;
        }
        const cleaned = stripSensitiveDeep(item, depth + 1, seen);
        if (cleaned !== undefined || item === null) {
          arr.push(cleaned === undefined ? null : cleaned);
        }
      }
      return Object.freeze(arr);
    }

    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (isSensitiveKey(k) || typeof v === 'function') {
        continue;
      }
      const cleaned = stripSensitiveDeep(v, depth + 1, seen);
      if (cleaned !== undefined || v === null) {
        out[k] = cleaned === undefined ? null : cleaned;
      }
    }
    return Object.freeze(out);
  } finally {
    seen.delete(value);
  }
}

export function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) {
    return value;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      deepFreeze(item, seen);
    }
  } else {
    for (const prop of Object.values(value)) {
      deepFreeze(prop, seen);
    }
  }
  return Object.freeze(value);
}
