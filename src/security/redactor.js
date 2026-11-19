const SENSITIVE_KEY_PATTERN =
  /^(authorization|cookie|set-cookie|token|access_token|refresh_token|csrf|csrf_token|x-sidecar-token|x-csrf-token|x-api-key|api_key|apikey|secret|password|passwd|env|headers)$/i;

const SENSITIVE_SUBSTRING_PATTERN =
  /(token|secret|password|csrf|authorization|apikey|api_key)/i;

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
]);

export const REDACTED = '[REDACTED]';

export function redactUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return rawUrl;
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    return rawUrl.replace(
      /([?&](?:token|access_token|csrf|csrf_token|api_key|apikey|secret|key)=)([^&#]*)/gi,
      `$1${REDACTED}`,
    );
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
