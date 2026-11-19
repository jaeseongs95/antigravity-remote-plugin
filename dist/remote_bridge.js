// antigravity-remote-plugin v1.0.0 — standalone self-contained ESM bundle
// Generated deterministically from 18 source modules.
export const BUILD_VERSION = "1.0.0";

// --- module: src/security/redactor.js ---
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

// --- module: src/security/origin-policy.js ---
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
  const lower = hostname.trim().toLowerCase();
  return lower === '127.0.0.1' || lower === 'localhost' || lower === '[::1]' || lower === '::1';
}

export function formatHostForUrl(hostname) {
  if (typeof hostname !== 'string' || !hostname.trim()) {
    throw new SecurityPolicyError('INVALID_HOST', 'Hostname must be a non-empty string.');
  }
  const trimmed = hostname.trim();
  if (trimmed.includes(':') && !trimmed.startsWith('[')) {
    return `[${trimmed}]`;
  }
  return trimmed;
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

    if (
      rule === 'http://127.0.0.1:*' ||
      rule === 'http://localhost:*' ||
      rule === 'http://[::1]:*'
    ) {
      if (candidate.protocol !== 'http:') {
        continue;
      }
      const expectedHost = rule.startsWith('http://127.0.0.1')
        ? '127.0.0.1'
        : rule.startsWith('http://[::1]')
          ? '[::1]'
          : 'localhost';
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

// --- module: src/security/trusted-types.js ---
export const RESERVED_TRUSTED_TYPES_POLICIES = Object.freeze([
  'default',
  'dompurify',
  'angular',
]);

const POLICY_CACHE = new WeakMap();

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
  trustedTypesApi = null,
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

  const trimmedName = policyName.trim();

  if (!trustedTypesApi || typeof trustedTypesApi.createPolicy !== 'function') {
    return {
      name: trimmedName,
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

  // Reuse an already-registered policy for this TrustedTypes API to avoid
  // duplicate-policy TypeError on re-initialization in real browsers.
  let apiCache = POLICY_CACHE.get(trustedTypesApi);
  if (!apiCache) {
    apiCache = new Map();
    POLICY_CACHE.set(trustedTypesApi, apiCache);
  }

  let entry = apiCache.get(trimmedName);
  if (!entry) {
    const holder = { validator: validateScriptUrl };
    const nativePolicy = trustedTypesApi.createPolicy(trimmedName, {
      createScriptURL(url) {
        if (!holder.validator(url)) {
          throw new SecurityPolicyError(
            'UNTRUSTED_SCRIPT_URL',
            'Script URL failed allowlist validation.',
          );
        }
        return url;
      },
    });
    entry = { holder, nativePolicy };
    apiCache.set(trimmedName, entry);
  } else {
    entry.holder.validator = validateScriptUrl;
  }

  return {
    name: trimmedName,
    isNative: true,
    createScriptURL(url) {
      if (!validateScriptUrl(url)) {
        throw new SecurityPolicyError(
          'UNTRUSTED_SCRIPT_URL',
          'Script URL failed allowlist validation.',
        );
      }
      entry.holder.validator = validateScriptUrl;
      return entry.nativePolicy.createScriptURL(url);
    },
  };
}

// --- module: src/security/script-guard.js ---
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

// --- module: src/security/dom-guard.js ---
const FORBIDDEN_TAGS = new Set(['base', 'script', 'object', 'embed']);

const FORBIDDEN_PROP_PREFIXES = Object.freeze(['on']);

const FORBIDDEN_HTML_PROPS = new Set([
  ['inner', 'HTML'].join(''),
  ['outer', 'HTML'].join(''),
  ['insertAdjacent', 'HTML'].join(''),
  'srcdoc',
]);

const FORBIDDEN_URI_SCHEME_PATTERN = /^(?:javascript|vbscript|data):/i;

function normalizeUriForSchemeCheck(rawValue) {
  // Strip ASCII control characters (including \t, \n, \r, \0) and spaces that browsers ignore in URL schemes.
  return String(rawValue).replace(/[\u0000-\u0020\u007f]+/g, '');
}

export function assertSafeTagName(tagName) {
  if (typeof tagName !== 'string' || tagName.trim().length === 0) {
    throw new SecurityPolicyError('INVALID_TAG_NAME', 'Tag name must be a non-empty string.');
  }
  const normalized = tagName.trim().toLowerCase();
  if (FORBIDDEN_TAGS.has(normalized)) {
    throw new SecurityPolicyError(
      'FORBIDDEN_ELEMENT_TAG',
      `Creating <${normalized}> elements is forbidden by security policy.`,
    );
  }
  return normalized;
}

export function assertSafeAttribute(attrName, attrValue) {
  if (typeof attrName !== 'string' || attrName.trim().length === 0) {
    throw new SecurityPolicyError('INVALID_ATTRIBUTE', 'Attribute name must be non-empty.');
  }
  const normalized = attrName.trim();
  const lower = normalized.toLowerCase();
  if (FORBIDDEN_HTML_PROPS.has(normalized) || FORBIDDEN_HTML_PROPS.has(lower)) {
    throw new SecurityPolicyError(
      'FORBIDDEN_HTML_SINK',
      `Setting unsafe HTML sink "${attrName}" is forbidden.`,
    );
  }
  for (const prefix of FORBIDDEN_PROP_PREFIXES) {
    if (lower.startsWith(prefix) && lower.length > prefix.length) {
      throw new SecurityPolicyError(
        'FORBIDDEN_EVENT_ATTRIBUTE',
        `Inline event handler attribute "${attrName}" is forbidden.`,
      );
    }
  }
  if (attrValue !== null && attrValue !== undefined) {
    // Coerce objects (e.g. { toString: () => 'javascript:...' }) before validation.
    const collapsed = normalizeUriForSchemeCheck(attrValue);
    if (FORBIDDEN_URI_SCHEME_PATTERN.test(collapsed)) {
      throw new SecurityPolicyError(
        'FORBIDDEN_URI_SCHEME',
        `Dangerous URI scheme in attribute "${attrName}" is forbidden.`,
      );
    }
  }
}

export function createSafeElement(doc, tagName, { attrs = {}, text = null } = {}) {
  const safeTag = assertSafeTagName(tagName);
  if (!doc || typeof doc.createElement !== 'function') {
    throw new SecurityPolicyError('INVALID_DOCUMENT', 'A document with createElement is required.');
  }
  const el = doc.createElement(safeTag);
  for (const [key, val] of Object.entries(attrs)) {
    const stringVal = val !== null && val !== undefined ? String(val) : val;
    assertSafeAttribute(key, stringVal);
    if (stringVal !== null && stringVal !== undefined) {
      el.setAttribute(key, stringVal);
    }
  }
  if (text !== null && text !== undefined) {
    el.textContent = String(text);
  }
  return el;
}

// --- module: src/core/diagnostics.js ---
const DEFAULT_MAX_EVENTS = 200;

export class DiagnosticsBus {
  #events = [];
  #listeners = new Set();
  #maxEvents;

  constructor({ maxEvents = DEFAULT_MAX_EVENTS } = {}) {
    this.#maxEvents = Math.max(1, Number(maxEvents) || DEFAULT_MAX_EVENTS);
  }

  emit({ level = 'info', code, source, message, detail = null }) {
    const entry = deepFreeze({
      timestamp: new Date().toISOString(),
      level,
      code: String(code || 'UNKNOWN'),
      source: String(source || 'core'),
      message: String(redactSecrets(message || '')),
      detail: detail === null || detail === undefined ? null : redactSecrets(detail),
    });

    this.#events.push(entry);
    if (this.#events.length > this.#maxEvents) {
      this.#events.splice(0, this.#events.length - this.#maxEvents);
    }

    for (const listener of [...this.#listeners]) {
      try {
        listener(entry);
      } catch (_listenerErr) {
        // Isolated listener failure: never break other observers or caller flow.
      }
    }
    return entry;
  }

  subscribe(listener) {
    if (typeof listener !== 'function') {
      throw new TypeError('Diagnostics listener must be a function.');
    }
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  snapshot() {
    return [...this.#events];
  }

  clear() {
    this.#events.length = 0;
  }
}

// --- module: src/core/lifecycle.js ---
export class DisposableStore {
  #disposers = [];
  #disposed = false;
  #diagnostics;

  constructor({ diagnostics = null } = {}) {
    this.#diagnostics = diagnostics;
  }

  get isDisposed() {
    return this.#disposed;
  }

  get size() {
    return this.#disposers.length;
  }

  add(disposable) {
    const fn =
      typeof disposable === 'function'
        ? disposable
        : disposable && typeof disposable.dispose === 'function'
          ? () => disposable.dispose()
          : null;

    if (!fn) {
      throw new TypeError('Disposable must be a function or an object with dispose().');
    }

    if (this.#disposed) {
      this.#invokeSafe(fn, 'late-add');
      return () => {};
    }

    let active = true;
    const entry = () => {
      if (!active) {
        return;
      }
      active = false;
      fn();
    };
    this.#disposers.push(entry);

    return () => {
      if (!active) {
        return;
      }
      active = false;
      const idx = this.#disposers.indexOf(entry);
      if (idx !== -1) {
        this.#disposers.splice(idx, 1);
      }
      this.#invokeSafe(fn, 'manual-remove');
    };
  }

  dispose() {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    const toRun = this.#disposers.splice(0, this.#disposers.length).reverse();
    for (const fn of toRun) {
      this.#invokeSafe(fn, 'store-dispose');
    }
  }

  #invokeSafe(fn, phase) {
    try {
      fn();
    } catch (err) {
      if (this.#diagnostics) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'DISPOSE_FAILED',
          source: 'core.lifecycle',
          message: `Disposer failed during ${phase}`,
          detail: err,
        });
      }
    }
  }
}

/**
 * Serializes async critical sections in FIFO order.
 */
export class AsyncMutex {
  #tail = Promise.resolve();

  async runExclusive(taskFn) {
    if (typeof taskFn !== 'function') {
      throw new TypeError('AsyncMutex taskFn must be a function.');
    }
    const prev = this.#tail;
    let release;
    this.#tail = new Promise((resolve) => {
      release = resolve;
    });
    await prev;
    try {
      return await taskFn();
    } finally {
      release();
    }
  }
}

/**
 * Composable, arbitrary-order safe hook chain that preserves host guard semantics.
 * Catches both synchronous throws and async promise rejections from handlers.
 */
export class EventChain {
  #handlers = new Map();
  #nextId = 1;
  #hostGuard;
  #diagnostics;

  constructor({ hostGuard = null, diagnostics = null } = {}) {
    this.#hostGuard = typeof hostGuard === 'function' ? hostGuard : null;
    this.#diagnostics = diagnostics;
  }

  get size() {
    return this.#handlers.size;
  }

  register(handler, { label = 'anonymous' } = {}) {
    if (typeof handler !== 'function') {
      throw new TypeError('EventChain handler must be a function.');
    }
    const id = this.#nextId++;
    this.#handlers.set(id, { handler, label });
    return () => {
      this.#handlers.delete(id);
    };
  }

  dispatch(...args) {
    let guardResult = true;
    if (this.#hostGuard) {
      guardResult = this.#hostGuard(...args);
      if (guardResult === false) {
        return { allowed: false, invoked: 0 };
      }
    }

    let invoked = 0;
    for (const { handler, label } of [...this.#handlers.values()]) {
      try {
        const result = handler(...args);
        invoked += 1;
        if (result && typeof result.then === 'function') {
          result.catch((err) => {
            if (this.#diagnostics) {
              this.#diagnostics.emit({
                level: 'error',
                code: 'EVENT_CHAIN_ASYNC_HANDLER_FAILED',
                source: 'core.lifecycle',
                message: `Async handler "${label}" rejected during dispatch`,
                detail: err,
              });
            }
          });
        }
      } catch (err) {
        if (this.#diagnostics) {
          this.#diagnostics.emit({
            level: 'error',
            code: 'EVENT_CHAIN_HANDLER_FAILED',
            source: 'core.lifecycle',
            message: `Handler "${label}" threw during dispatch`,
            detail: err,
          });
        }
      }
    }
    return { allowed: guardResult, invoked };
  }

  clear() {
    this.#handlers.clear();
  }
}

/**
 * Coalesces concurrent async operations by key to prevent duplicate discovery RPCs.
 */
export class SingleFlight {
  #inflight = new Map();

  async run(key, taskFn) {
    if (typeof taskFn !== 'function') {
      throw new TypeError('SingleFlight taskFn must be a function.');
    }
    const existing = this.#inflight.get(key);
    if (existing) {
      return existing;
    }
    const promise = Promise.resolve()
      .then(() => taskFn())
      .finally(() => {
        if (this.#inflight.get(key) === promise) {
          this.#inflight.delete(key);
        }
      });
    this.#inflight.set(key, promise);
    return promise;
  }

  get activeCount() {
    return this.#inflight.size;
  }
}

// --- module: src/core/ports.js ---
export function assertPort(port, portName, requiredMethods) {
  if (!port || typeof port !== 'object') {
    throw new TypeError(`Missing required port "${portName}".`);
  }
  for (const method of requiredMethods) {
    if (typeof port[method] !== 'function') {
      throw new TypeError(`Port "${portName}" must implement method "${method}()".`);
    }
  }
  return port;
}

export const PORT_CONTRACTS = Object.freeze({
  HostDiscoveryPort: Object.freeze(['listPlugins', 'listSidecars']),
  FramePromotionPort: Object.freeze(['acquireActiveFrame', 'onFrameChange']),
  SidecarRelayPort: Object.freeze(['requestJson', 'buildUiUrl']),
  SettingsReadPort: Object.freeze(['readPluginSettings']),
  ThemeWorkspaceSyncPort: Object.freeze(['getThemeVariables', 'getWorkspaceUris', 'subscribe']),
  ExtensionBridgePort: Object.freeze(['id', 'pluginName', 'mount', 'dispose']),
});

export function validateDiscoveryPort(port) {
  return assertPort(port, 'HostDiscoveryPort', PORT_CONTRACTS.HostDiscoveryPort);
}

export function validateFramePromotionPort(port) {
  return assertPort(port, 'FramePromotionPort', PORT_CONTRACTS.FramePromotionPort);
}

export function validateSidecarRelayPort(port) {
  return assertPort(port, 'SidecarRelayPort', PORT_CONTRACTS.SidecarRelayPort);
}

export function validateSettingsReadPort(port) {
  return assertPort(port, 'SettingsReadPort', PORT_CONTRACTS.SettingsReadPort);
}

export function validateThemeWorkspaceSyncPort(port) {
  return assertPort(port, 'ThemeWorkspaceSyncPort', PORT_CONTRACTS.ThemeWorkspaceSyncPort);
}

export function validateBridgeDescriptor(bridge) {
  if (!bridge || typeof bridge !== 'object') {
    throw new TypeError('Bridge descriptor must be an object.');
  }
  if (typeof bridge.id !== 'string' || !bridge.id.trim()) {
    throw new TypeError('Bridge descriptor must have a non-empty string id.');
  }
  if (typeof bridge.pluginName !== 'string' || !bridge.pluginName.trim()) {
    throw new TypeError(`Bridge "${bridge.id}" must declare a non-empty pluginName.`);
  }
  if (typeof bridge.mount !== 'function' || typeof bridge.dispose !== 'function') {
    throw new TypeError(`Bridge "${bridge.id}" must implement mount() and dispose().`);
  }
  return bridge;
}

// --- module: src/core/orchestrator.js ---
function computeSidecarFingerprint(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') {
    return null;
  }
  return `${sidecar.sidecarId || ''}|${sidecar.host || '127.0.0.1'}|${sidecar.port || ''}|${sidecar.token || ''}`;
}

export class RemoteOrchestrator {
  #discoveryPort;
  #framePort;
  #diagnostics;
  #bridges = new Map();
  #mounted = new Map();
  #mountedFingerprints = new Map();
  #singleFlight = new SingleFlight();
  #mutex = new AsyncMutex();
  #store;
  #started = false;
  #epoch = 0;
  #activeFrame = null;

  constructor({ discoveryPort, framePort, diagnostics = new DiagnosticsBus() }) {
    this.#discoveryPort = validateDiscoveryPort(discoveryPort);
    this.#framePort = validateFramePromotionPort(framePort);
    this.#diagnostics = diagnostics;
    this.#store = new DisposableStore({ diagnostics });
  }

  get diagnostics() {
    return this.#diagnostics;
  }

  registerBridge(bridge) {
    validateBridgeDescriptor(bridge);
    if (this.#bridges.has(bridge.id)) {
      throw new Error(`Bridge "${bridge.id}" is already registered.`);
    }
    this.#bridges.set(bridge.id, bridge);
    return () => {
      this.#unmountBridge(bridge.id);
      this.#bridges.delete(bridge.id);
    };
  }

  async discoverAuthoritativeState(context = {}) {
    return this.#singleFlight.run('discovery', async () => {
      const [plugins, sidecars] = await Promise.all([
        this.#discoveryPort.listPlugins(context),
        this.#discoveryPort.listSidecars(context),
      ]);
      if (!Array.isArray(plugins)) {
        throw new TypeError('HostDiscoveryPort.listPlugins() must return an array.');
      }
      if (!Array.isArray(sidecars)) {
        throw new TypeError('HostDiscoveryPort.listSidecars() must return an array.');
      }

      const activePlugins = new Map();
      for (const plugin of plugins) {
        if (!plugin || typeof plugin.name !== 'string') {
          continue;
        }
        const isEnabled = plugin.disabled !== true && plugin.enabled !== false;
        if (isEnabled) {
          activePlugins.set(plugin.name, plugin);
          if (typeof plugin.dir === 'string' && plugin.dir.trim()) {
            activePlugins.set(plugin.dir.trim(), plugin);
          }
        }
      }

      const activeSidecars = new Map();
      for (const sidecar of sidecars) {
        if (!sidecar || typeof sidecar.sidecarId !== 'string') {
          continue;
        }
        if (sidecar.running !== false && sidecar.disabled !== true) {
          activeSidecars.set(sidecar.sidecarId, sidecar);
        }
      }

      return { activePlugins, activeSidecars };
    });
  }

  async start(context = {}) {
    return this.#mutex.runExclusive(async () => {
      if (this.#started && !this.#store.isDisposed) {
        return this.#reconcileLocked(this.#epoch, context);
      }

      if (this.#store.isDisposed) {
        this.#store = new DisposableStore({ diagnostics: this.#diagnostics });
      }

      const startEpoch = this.#epoch;
      const frame = await this.#framePort.acquireActiveFrame();
      if (startEpoch !== this.#epoch || this.#store.isDisposed) {
        return { mountedIds: [], skippedIds: [], failedIds: [] };
      }

      this.#activeFrame = frame;
      this.#started = true;

      const unsubFrame = this.#framePort.onFrameChange((nextFrame) => {
        // Bump epoch immediately to invalidate any in-flight mount from the old frame.
        const changeEpoch = ++this.#epoch;
        return this.#mutex.runExclusive(async () => {
          if (changeEpoch !== this.#epoch || this.#store.isDisposed) {
            return;
          }
          this.#activeFrame = nextFrame;
          this.#unmountAll();
          if (nextFrame) {
            await this.#reconcileLocked(changeEpoch, context);
          }
        });
      });
      if (typeof unsubFrame === 'function') {
        this.#store.add(unsubFrame);
      }

      return this.#reconcileLocked(startEpoch, context);
    });
  }

  async reconcile(context = {}) {
    const runEpoch = this.#epoch;
    return this.#mutex.runExclusive(() => this.#reconcileLocked(runEpoch, context));
  }

  async #reconcileLocked(runEpoch, context) {
    if (runEpoch !== this.#epoch || this.#store.isDisposed) {
      return { mountedIds: [], skippedIds: [], failedIds: [] };
    }

    const { activePlugins, activeSidecars } = await this.discoverAuthoritativeState(context);
    if (runEpoch !== this.#epoch || this.#store.isDisposed) {
      return { mountedIds: [], skippedIds: [], failedIds: [] };
    }

    const mountedIds = [];
    const skippedIds = [];
    const failedIds = [];

    for (const [bridgeId, bridge] of [...this.#bridges.entries()]) {
      if (runEpoch !== this.#epoch || this.#store.isDisposed) {
        break;
      }

      const pluginRecord = this.#matchActivePlugin(bridge, activePlugins);
      const sidecarRecord = bridge.sidecarId
        ? activeSidecars.get(bridge.sidecarId) ?? null
        : null;

      const isEligible = Boolean(pluginRecord) && (!bridge.requireSidecar || Boolean(sidecarRecord));

      if (!isEligible) {
        if (this.#mounted.has(bridgeId)) {
          this.#unmountBridge(bridgeId);
        }
        skippedIds.push(bridgeId);
        this.#diagnostics.emit({
          level: 'info',
          code: 'BRIDGE_SKIPPED_INACTIVE',
          source: 'core.orchestrator',
          message: `Skipped bridge "${bridgeId}": authoritative plugin/sidecar not active`,
          detail: { bridgeId, pluginName: bridge.pluginName, sidecarId: bridge.sidecarId ?? null },
        });
        continue;
      }

      const nextFingerprint = computeSidecarFingerprint(sidecarRecord);
      if (this.#mounted.has(bridgeId)) {
        const prevFingerprint = this.#mountedFingerprints.get(bridgeId) ?? null;
        if (prevFingerprint === nextFingerprint) {
          mountedIds.push(bridgeId);
          continue;
        }
        // Sidecar host/port/token changed (e.g. sidecar restarted): unmount stale instance and remount.
        this.#unmountBridge(bridgeId);
      }

      try {
        await bridge.mount({
          frame: this.#activeFrame,
          plugin: pluginRecord,
          sidecar: sidecarRecord,
          diagnostics: this.#diagnostics,
        });
        if (runEpoch !== this.#epoch || this.#store.isDisposed || !this.#bridges.has(bridgeId)) {
          this.#safeDisposeBridge(bridgeId, bridge);
          continue;
        }
        this.#mounted.set(bridgeId, bridge);
        this.#mountedFingerprints.set(bridgeId, nextFingerprint);
        mountedIds.push(bridgeId);
      } catch (err) {
        this.#safeDisposeBridge(bridgeId, bridge);
        failedIds.push(bridgeId);
        this.#diagnostics.emit({
          level: 'error',
          code: 'BRIDGE_MOUNT_FAILED',
          source: 'core.orchestrator',
          message: `Failed to mount bridge "${bridgeId}"`,
          detail: err,
        });
      }
    }

    return { mountedIds, skippedIds, failedIds };
  }

  getMountedBridgeIds() {
    return [...this.#mounted.keys()];
  }

  #matchActivePlugin(bridge, activePlugins) {
    if (activePlugins.has(bridge.pluginName)) {
      return activePlugins.get(bridge.pluginName);
    }
    if (Array.isArray(bridge.pluginAliases)) {
      for (const alias of bridge.pluginAliases) {
        if (typeof alias === 'string' && activePlugins.has(alias)) {
          return activePlugins.get(alias);
        }
      }
    }
    return null;
  }

  #safeDisposeBridge(bridgeId, bridge) {
    try {
      bridge.dispose();
    } catch (err) {
      this.#diagnostics.emit({
        level: 'error',
        code: 'BRIDGE_DISPOSE_FAILED',
        source: 'core.orchestrator',
        message: `Failed to dispose bridge "${bridgeId}"`,
        detail: err,
      });
    }
  }

  #unmountBridge(bridgeId) {
    const bridge = this.#mounted.get(bridgeId);
    if (!bridge) {
      return;
    }
    this.#mounted.delete(bridgeId);
    this.#mountedFingerprints.delete(bridgeId);
    this.#safeDisposeBridge(bridgeId, bridge);
  }

  #unmountAll() {
    for (const bridgeId of [...this.#mounted.keys()].reverse()) {
      this.#unmountBridge(bridgeId);
    }
  }

  dispose() {
    this.#epoch += 1;
    this.#started = false;
    this.#unmountAll();
    this.#store.dispose();
    this.#activeFrame = null;
  }
}

// --- module: src/bridges/dom-overlay-bridge.js ---
export function stripSensitiveSettings(rawSettings) {
  if (!rawSettings || typeof rawSettings !== 'object' || Array.isArray(rawSettings)) {
    return Object.freeze({});
  }
  return stripSensitiveDeep(rawSettings) || Object.freeze({});
}

/**
 * Vendor- and domain-independent pure DOM overlay bridge.
 * Enforces least privilege: passes ONLY `{ win, doc, settings, onStatus }` to
 * the overlay factory, validates SettingsReadPort, serializes mount/dispose
 * against races, and rolls back cleanly if `start()` fails.
 */
export function createDomOverlayBridge({
  id,
  pluginName,
  pluginAliases = [],
  createOverlay,
  settingsPort = null,
  sanitizeSettings = stripSensitiveSettings,
  onStatus = null,
}) {
  if (typeof createOverlay !== 'function') {
    throw new TypeError('DomOverlayBridge requires a createOverlay factory function.');
  }
  if (typeof sanitizeSettings !== 'function') {
    throw new TypeError('DomOverlayBridge sanitizeSettings must be a function.');
  }
  if (settingsPort !== null) {
    validateSettingsReadPort(settingsPort);
  }

  const mutex = new AsyncMutex();
  let mountEpoch = 0;
  let activeInstance = null;
  let store = null;

  function teardownCurrent() {
    if (store) {
      const currentStore = store;
      store = null;
      currentStore.dispose();
    } else if (activeInstance) {
      const target = activeInstance;
      activeInstance = null;
      target.dispose();
    }
  }

  return {
    id,
    pluginName,
    pluginAliases: [...pluginAliases],
    requireSidecar: false,

    async mount({ frame, plugin = null, diagnostics }) {
      if (!frame || !frame.win || !frame.doc) {
        throw new SecurityPolicyError(
          'MISSING_PROMOTED_FRAME',
          `Bridge "${id}" requires a promoted frame with win and doc.`,
        );
      }

      const myEpoch = ++mountEpoch;

      return mutex.runExclusive(async () => {
        if (myEpoch !== mountEpoch) {
          return { skipped: true };
        }

        teardownCurrent();

        const resolvedPluginName = plugin?.name || pluginName;
        const rawSettings = settingsPort
          ? await settingsPort.readPluginSettings(resolvedPluginName)
          : {};

        if (myEpoch !== mountEpoch) {
          return { skipped: true };
        }

        const safeSettings = Object.freeze({ ...sanitizeSettings(rawSettings) });

        const statusCallback = (statusPayload) => {
          if (typeof onStatus === 'function') {
            onStatus(statusPayload);
          }
          if (diagnostics) {
            diagnostics.emit({
              level: 'info',
              code: 'OVERLAY_STATUS',
              source: `bridge.${id}`,
              message: 'Overlay status updated',
              detail: statusPayload,
            });
          }
        };

        // Least-privilege invocation: zero RPC clients, zero CSRF/sidecar tokens.
        const instance = createOverlay({
          win: frame.win,
          doc: frame.doc,
          settings: safeSettings,
          onStatus: statusCallback,
        });

        if (
          !instance ||
          typeof instance.start !== 'function' ||
          typeof instance.dispose !== 'function'
        ) {
          throw new TypeError(
            `Overlay factory for "${id}" must return { start(), dispose() }.`,
          );
        }

        const nextStore = new DisposableStore({ diagnostics });
        activeInstance = instance;
        store = nextStore;
        nextStore.add(() => {
          if (activeInstance === instance) {
            activeInstance = null;
          }
          instance.dispose();
        });

        try {
          await instance.start();
        } catch (startErr) {
          teardownCurrent();
          throw startErr;
        }

        if (myEpoch !== mountEpoch) {
          teardownCurrent();
          return { skipped: true };
        }

        return { settings: safeSettings };
      });
    },

    updateSettings(nextRawSettings) {
      const safeNext = Object.freeze({ ...sanitizeSettings(nextRawSettings) });
      if (activeInstance && typeof activeInstance.updateSettings === 'function') {
        activeInstance.updateSettings(safeNext);
      }
      return safeNext;
    },

    dispose() {
      mountEpoch += 1;
      teardownCurrent();
    },
  };
}

// --- module: src/bridges/sidecar-ui-bridge.js ---
export function deriveSidecarOrigin(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') {
    throw new SecurityPolicyError('INVALID_SIDECAR', 'Sidecar descriptor is required.');
  }
  const rawHost = sidecar.host || '127.0.0.1';
  if (!isLoopbackHostname(rawHost)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_SIDECAR',
      'Sidecar bridge only permits loopback sidecar origins.',
    );
  }
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError('INVALID_SIDECAR_PORT', 'Sidecar port must be a valid TCP port.');
  }
  const host = formatHostForUrl(rawHost);
  let parsed;
  try {
    parsed = new URL(`http://${host}:${port}/`);
  } catch (_err) {
    throw new SecurityPolicyError('INVALID_SIDECAR_ORIGIN', 'Sidecar origin is not a valid URL.');
  }
  // Normalizes default port 80 (http://127.0.0.1:80 -> http://127.0.0.1) to match browser event.origin.
  return parsed.origin.toLowerCase();
}

/**
 * Vendor- and domain-independent sidecar UI and JSON API relay bridge.
 * Defers initial theme/workspace postMessage until iframe `load` completes,
 * validates exact normalized loopback sidecar origin, and enforces fail-closed
 * `event.source` matching whenever an iframe is mounted.
 */
export function createSidecarUiBridge({
  id,
  pluginName,
  sidecarId,
  relayPort,
  themeWorkspacePort = null,
  allowedOrigins = [],
  allowedApiPaths = [],
  allowedInboundEvents = [],
  conversationIdProvider = null,
  onInboundEvent = null,
}) {
  validateSidecarRelayPort(relayPort);
  if (themeWorkspacePort !== null) {
    validateThemeWorkspaceSyncPort(themeWorkspacePort);
  }
  if (!Array.isArray(allowedApiPaths)) {
    throw new TypeError(`SidecarUiBridge "${id}" requires an allowedApiPaths array.`);
  }
  if (!Array.isArray(allowedInboundEvents)) {
    throw new TypeError(`SidecarUiBridge "${id}" requires an allowedInboundEvents array.`);
  }

  const permittedPaths = new Set(allowedApiPaths);
  const permittedEvents = new Set(allowedInboundEvents);
  let activeSidecar = null;
  let activeSidecarOrigin = null;
  let activeDiagnostics = null;
  let mountedIframe = null;
  let iframeLoaded = false;
  let store = null;

  function isOriginTrustedForActiveSidecar(candidateOrigin) {
    const normalized = normalizeOrigin(candidateOrigin);
    if (!normalized) {
      return false;
    }
    if (activeSidecarOrigin && normalized.origin === activeSidecarOrigin) {
      return true;
    }
    return Array.isArray(allowedOrigins) && allowedOrigins.length > 0
      ? isOriginAllowed(normalized.origin, allowedOrigins)
      : false;
  }

  function pushThemeAndWorkspace(targetWindow) {
    if (!targetWindow || typeof targetWindow.postMessage !== 'function' || !activeSidecarOrigin) {
      return;
    }
    if (!themeWorkspacePort) {
      return;
    }
    const vars = themeWorkspacePort.getThemeVariables();
    if (vars && typeof vars === 'object') {
      targetWindow.postMessage(
        { type: 'theme-change', payload: { cssVariables: { ...vars } } },
        activeSidecarOrigin,
      );
    }
    const uris = themeWorkspacePort.getWorkspaceUris();
    targetWindow.postMessage(
      { type: 'workspace-change', payload: { workspaceUris: Array.isArray(uris) ? [...uris] : [] } },
      activeSidecarOrigin,
    );
  }

  return {
    id,
    pluginName,
    sidecarId,
    requireSidecar: true,

    getActiveOrigin() {
      return activeSidecarOrigin;
    },

    getMountedIframe() {
      return mountedIframe;
    },

    async mount({ frame = null, sidecar, diagnostics }) {
      if (!sidecar) {
        throw new SecurityPolicyError(
          'SIDECAR_NOT_ACTIVE',
          `Cannot mount "${id}": sidecar "${sidecarId}" is not active.`,
        );
      }
      if (store) {
        this.dispose();
      }

      const sidecarOrigin = deriveSidecarOrigin(sidecar);
      activeSidecar = sidecar;
      activeSidecarOrigin = sidecarOrigin;
      activeDiagnostics = diagnostics || null;
      iframeLoaded = false;
      store = new DisposableStore({ diagnostics });

      try {
        // If a host frame with DOM is available, mount the sidecar iframe and wait for `load`.
        if (frame && frame.doc && typeof frame.doc.createElement === 'function') {
          const conversationId = typeof conversationIdProvider === 'function'
            ? conversationIdProvider()
            : (frame.conversationId || '');
          const uiUrl = relayPort.buildUiUrl({ sidecar, conversationId });
          const iframe = createSafeElement(frame.doc, 'iframe', {
            attrs: {
              src: uiUrl,
              'data-remote-sidecar-id': sidecarId,
              sandbox: 'allow-scripts allow-same-origin allow-forms',
            },
          });
          mountedIframe = iframe;

          const hasLoadEvents = typeof iframe.addEventListener === 'function';
          if (hasLoadEvents) {
            const onLoad = () => {
              iframeLoaded = true;
              if (mountedIframe === iframe && iframe.contentWindow) {
                pushThemeAndWorkspace(iframe.contentWindow);
              }
            };
            iframe.addEventListener('load', onLoad);
            store.add(() => {
              if (typeof iframe.removeEventListener === 'function') {
                iframe.removeEventListener('load', onLoad);
              }
            });
          }

          const mountContainer = frame.panelContainer || frame.doc.body || null;
          if (mountContainer && typeof mountContainer.appendChild === 'function') {
            mountContainer.appendChild(iframe);
            store.add(() => {
              if (typeof iframe.remove === 'function') {
                iframe.remove();
              } else if (mountContainer && typeof mountContainer.removeChild === 'function') {
                mountContainer.removeChild(iframe);
              }
            });
          }

          // Only push synchronously if the host element does not emit DOM load events.
          if (!hasLoadEvents && iframe.contentWindow) {
            iframeLoaded = true;
            pushThemeAndWorkspace(iframe.contentWindow);
          }
        }

        // Wire ThemeWorkspaceSyncPort live updates (delivered once iframe is loaded).
        if (themeWorkspacePort) {
          const unsubSync = themeWorkspacePort.subscribe((change) => {
            const targetWin = mountedIframe?.contentWindow || null;
            if (!targetWin || !activeSidecarOrigin || !iframeLoaded) {
              return;
            }
            if (change?.type === 'theme-change') {
              this.postThemeChange(targetWin, activeSidecarOrigin, change.cssVariables);
            } else if (change?.type === 'workspace-change') {
              this.postWorkspaceChange(targetWin, activeSidecarOrigin, change.workspaceUris);
            }
          });
          if (typeof unsubSync === 'function') {
            store.add(unsubSync);
          }
        }

        // Wire host window message listener for inbound sidecar preload events.
        if (frame && frame.win && typeof frame.win.addEventListener === 'function') {
          const onMessage = (event) => {
            this.handleInboundMessage(event);
          };
          frame.win.addEventListener('message', onMessage);
          store.add(() => {
            if (typeof frame.win.removeEventListener === 'function') {
              frame.win.removeEventListener('message', onMessage);
            }
          });
        }
      } catch (mountErr) {
        this.dispose();
        throw mountErr;
      }

      return { sidecarId: sidecar.sidecarId, origin: sidecarOrigin };
    },

    buildUiUrl({ conversationId = '' } = {}) {
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
      if (!isOriginTrustedForActiveSidecar(targetOrigin)) {
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
      if (!isOriginTrustedForActiveSidecar(targetOrigin)) {
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
      if (!activeSidecarOrigin || !isOriginTrustedForActiveSidecar(event.origin)) {
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

      // Fail-closed source check: require an explicit expectedSource or mounted iframe contentWindow.
      const requiredSource = expectedSource ?? mountedIframe?.contentWindow ?? null;
      if (!requiredSource) {
        return { accepted: false, reason: 'SOURCE_UNAVAILABLE' };
      }
      if (event.source !== requiredSource) {
        if (activeDiagnostics) {
          activeDiagnostics.emit({
            level: 'warn',
            code: 'POSTMESSAGE_SOURCE_MISMATCH',
            source: `bridge.${id}`,
            message: 'Dropped inbound postMessage from unexpected window source',
            detail: { origin: event.origin },
          });
        }
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
      mountedIframe = null;
      iframeLoaded = false;
      activeSidecar = null;
      activeSidecarOrigin = null;
      activeDiagnostics = null;
    },
  };
}

// --- module: src/bridges/mcp-extension-slot.js ---
const DEFAULT_PROTECTED_CONFIG_PATTERNS = Object.freeze([
  /(?:^|\/)config\/config\.json$/i,
  /(?:^|\/)plugins\/[^/]+\/mcp_config\.json$/i,
]);

const CONTROL_CHAR_PATTERN = /[\u0000-\u001f\u007f]/;

/**
 * Pure, cross-platform lexical path canonicalizer (resolves \, //, ., .., ~/).
 * Rejects NUL bytes and ASCII control characters to prevent regex anchor bypasses.
 */
export function canonicalizeConfigPath(rawPath) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    throw new SecurityPolicyError(
      'INVALID_CONFIG_PATH',
      'A non-empty targetConfigPath is required for MCP configuration mutations.',
    );
  }
  if (CONTROL_CHAR_PATTERN.test(rawPath)) {
    throw new SecurityPolicyError(
      'INVALID_CONFIG_PATH',
      'Configuration path contains forbidden NUL or ASCII control characters.',
    );
  }

  let normalized = rawPath.trim().replace(/\\/g, '/');
  if (/^[a-zA-Z]:[^/]/.test(normalized)) {
    throw new SecurityPolicyError(
      'INVALID_CONFIG_PATH',
      'Ambiguous drive-relative Windows configuration paths are forbidden.',
    );
  }
  if (normalized === '~' || normalized.startsWith('~/')) {
    normalized = `/__home__${normalized.slice(1)}`;
  }

  const driveMatch = normalized.match(/^([a-zA-Z]:)(\/.*)?$/);
  const prefix = driveMatch ? driveMatch[1].toLowerCase() : normalized.startsWith('/') ? '/' : '';
  const body = driveMatch ? (driveMatch[2] || '') : normalized;

  const segments = body.split('/');
  const resolved = [];
  for (const seg of segments) {
    if (!seg || seg === '.') {
      continue;
    }
    if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else if (!prefix) {
        resolved.push('..');
      }
      continue;
    }
    resolved.push(seg);
  }

  const joined = resolved.join('/');
  if (driveMatch) {
    return `${prefix}/${joined}`;
  }
  return prefix ? `/${joined}` : joined;
}

export function assertWritableConfigPath(targetPath, extraProtectedPatterns = []) {
  const canonical = canonicalizeConfigPath(targetPath);
  const allPatterns = [...DEFAULT_PROTECTED_CONFIG_PATTERNS, ...extraProtectedPatterns];
  for (const pattern of allPatterns) {
    if (pattern.test(canonical)) {
      throw new SecurityPolicyError(
        'PROTECTED_CONFIG_PATH',
        'Direct modification of protected host or plugin MCP configuration files is forbidden.',
      );
    }
  }
  return canonical;
}

function isStdioMutation({ transport, serverConfig }) {
  const normalizedTransport = typeof transport === 'string' ? transport.trim().toLowerCase() : '';
  if (normalizedTransport === 'stdio') {
    return true;
  }
  if (serverConfig && typeof serverConfig === 'object') {
    if (typeof serverConfig.command === 'string' && serverConfig.command.trim().length > 0) {
      return true;
    }
  }
  return false;
}

export function assertRemoteMcpMutationAllowed({ transport, serverConfig = null, userConfirmed }) {
  if (isStdioMutation({ transport, serverConfig }) && userConfirmed !== true) {
    throw new SecurityPolicyError(
      'UNCONFIRMED_REMOTE_STDIO',
      'Adding or executing a stdio MCP command over a remote channel requires explicit user confirmation.',
    );
  }
}

/**
 * Optional, decoupled extension slot for future remote MCP management.
 * Operates with zero dependency on legacy globals or merged inject files.
 */
export function createMcpExtensionSlot({
  id = 'mcp-extension-slot',
  pluginName,
  sidecarId = null,
  protectedConfigPatterns = [],
  delegate = null,
}) {
  let mounted = false;

  return {
    id,
    pluginName,
    sidecarId,
    requireSidecar: Boolean(sidecarId),

    async mount({ diagnostics }) {
      mounted = true;
      if (diagnostics) {
        diagnostics.emit({
          level: 'info',
          code: 'MCP_SLOT_MOUNTED',
          source: `bridge.${id}`,
          message: 'Optional MCP extension slot mounted in decoupled mode',
          detail: { hasDelegate: Boolean(delegate) },
        });
      }
      return { decoupled: !delegate };
    },

    async requestServerMutation({ targetConfigPath, transport, serverConfig, userConfirmed = false }) {
      if (!mounted) {
        throw new SecurityPolicyError('BRIDGE_NOT_MOUNTED', `Slot "${id}" is not mounted.`);
      }
      const canonicalPath = assertWritableConfigPath(targetConfigPath, protectedConfigPatterns);
      assertRemoteMcpMutationAllowed({ transport, serverConfig, userConfirmed });

      if (!delegate || typeof delegate.applyMutation !== 'function') {
        return {
          applied: false,
          reason: 'NO_DELEGATE_ATTACHED',
          targetConfigPath: canonicalPath,
          sanitizedPreview: redactSecrets(serverConfig),
        };
      }
      return delegate.applyMutation({
        targetConfigPath: canonicalPath,
        transport,
        serverConfig,
        userConfirmed,
      });
    },

    sanitizeServerView(serverConfig) {
      return redactSecrets(serverConfig);
    },

    dispose() {
      mounted = false;
    },
  };
}

// --- module: src/adapters/antigravity/discovery-adapter.js ---
const RPC_BASE_PATH = '/exa.language_server_pb.LanguageServerService';

function validateLoopbackAddress(lsAddress) {
  if (typeof lsAddress !== 'string' || !lsAddress.trim()) {
    throw new SecurityPolicyError('INVALID_LS_ADDRESS', 'Language server address is required.');
  }
  const raw = lsAddress.trim();
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
  const normalized = hasScheme ? raw : `http://${raw}`;

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_err) {
    throw new SecurityPolicyError('INVALID_LS_ADDRESS', 'Language server address is not a valid URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SecurityPolicyError(
      'INVALID_LS_PROTOCOL',
      `Language server RPC adapter only permits http/https protocols, got "${parsed.protocol}".`,
    );
  }
  if (!isLoopbackHostname(parsed.hostname)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_LS_ADDRESS',
      'Language server RPC adapter only permits loopback addresses.',
    );
  }
  const host = formatHostForUrl(parsed.hostname);
  const portSuffix = parsed.port ? `:${parsed.port}` : '';
  return `${parsed.protocol}//${host}${portSuffix}`;
}

function validateCsrfToken(csrfToken) {
  if (typeof csrfToken !== 'string' || csrfToken.trim().length < 8) {
    throw new SecurityPolicyError(
      'MISSING_CSRF_TOKEN',
      'A real host-issued CSRF token is required; synthetic tokens are forbidden.',
    );
  }
  const lowered = csrfToken.trim().toLowerCase();
  if (lowered === 'csrf_token' || lowered === 'placeholder' || lowered === 'dummy') {
    throw new SecurityPolicyError(
      'SYNTHETIC_CSRF_TOKEN',
      'Synthetic placeholder CSRF tokens are forbidden.',
    );
  }
  return csrfToken.trim();
}

function extractInstallDir(rawPath, fallbackName) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    return fallbackName;
  }
  const stripped = rawPath.trim().replace(/\\/g, '/').replace(/\/+$/, '');
  const segment = stripped.split('/').pop();
  return segment || fallbackName;
}

export function createAntigravityDiscoveryAdapter({
  lsAddress,
  csrfToken,
  fetchImpl = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined,
}) {
  const origin = validateLoopbackAddress(lsAddress);
  const validToken = validateCsrfToken(csrfToken);
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('AntigravityDiscoveryAdapter requires a fetch implementation.');
  }

  async function callRpc(methodName, payload = {}) {
    const response = await fetchImpl(`${origin}${RPC_BASE_PATH}/${methodName}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-codeium-csrf-token': validToken,
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`LanguageServerService/${methodName} failed with HTTP ${response.status}`);
    }
    return response.json();
  }

  return {
    async listPlugins({ workspaceUris = [] } = {}) {
      const body = Array.isArray(workspaceUris) && workspaceUris.length > 0
        ? { workspaceUris }
        : {};
      const data = await callRpc('GetAllPlugins', body);
      if (!data || !Array.isArray(data.plugins)) {
        throw new Error('LanguageServerService/GetAllPlugins returned invalid payload: missing "plugins" array.');
      }
      return data.plugins.map((plugin) => ({
        name: plugin.name,
        path: plugin.path || '',
        dir: extractInstallDir(plugin.path, plugin.name),
        disabled: Boolean(plugin.disabled),
        enabled: !plugin.disabled,
        isGlobal: Boolean(plugin.isGlobal),
      }));
    },

    async listSidecars({ workspaceUris = [] } = {}) {
      const body = Array.isArray(workspaceUris) && workspaceUris.length > 0
        ? { workspaceUris }
        : {};
      const data = await callRpc('GetSidecars', body);
      if (!data || !Array.isArray(data.sidecars)) {
        throw new Error('LanguageServerService/GetSidecars returned invalid payload: missing "sidecars" array.');
      }
      return data.sidecars.map((sc) => ({
        sidecarId: sc.sidecarId || sc.id || '',
        pluginName: sc.pluginName || '',
        port: Number(sc.port || sc.webPort || 0),
        host: sc.host || '127.0.0.1',
        token: sc.token || sc.uiToken || '',
        running: sc.running !== false && sc.status !== 'stopped',
        disabled: Boolean(sc.disabled),
      }));
    },
  };
}

// --- module: src/adapters/antigravity/frame-adapter.js ---
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

// --- module: src/adapters/antigravity/sidecar-adapter.js ---
function assertLoopbackSidecar(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') {
    throw new SecurityPolicyError('INVALID_SIDECAR', 'Sidecar descriptor is required.');
  }
  const rawHost = sidecar.host || '127.0.0.1';
  if (!isLoopbackHostname(rawHost)) {
    throw new SecurityPolicyError(
      'NON_LOOPBACK_SIDECAR',
      'Sidecar relay only permits loopback (127.0.0.1 / localhost / ::1) sidecar servers.',
    );
  }
  const host = formatHostForUrl(rawHost);
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError('INVALID_SIDECAR_PORT', 'Sidecar port must be a valid TCP port.');
  }
  return { host, port };
}

export function createAntigravitySidecarAdapter({
  fetchImpl = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined,
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('AntigravitySidecarAdapter requires a fetch implementation.');
  }

  return {
    /**
     * Builds the loopback sidecar UI URL without embedding secrets in query parameters.
     * Authentication tokens are sent strictly via the `X-Sidecar-Token` request header.
     */
    buildUiUrl({ sidecar, conversationId = '' }) {
      const { host, port } = assertLoopbackSidecar(sidecar);
      const url = new URL(`http://${host}:${port}/`);
      if (conversationId) {
        url.searchParams.set('conversationId', String(conversationId));
      }
      return url.toString();
    },

    async requestJson({ sidecar, path, method = 'POST', body = {} }) {
      const { host, port } = assertLoopbackSidecar(sidecar);
      if (typeof path !== 'string' || !path.startsWith('/')) {
        throw new SecurityPolicyError('INVALID_API_PATH', 'Sidecar API path must start with "/".');
      }

      const headers = { 'Content-Type': 'application/json' };
      if (sidecar.token) {
        headers['X-Sidecar-Token'] = String(sidecar.token);
      }

      const response = await fetchImpl(`http://${host}:${port}${path}`, {
        method: method.toUpperCase(),
        headers,
        body: method.toUpperCase() === 'GET' ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        throw new Error(`Sidecar API ${path} failed with HTTP ${response.status}`);
      }
      return response.json();
    },
  };
}

// --- module: src/adapters/antigravity/settings-adapter.js ---
export const DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER = 'google-translate';

const TRANSLATOR_PLUGIN_NAMES = new Set([
  'antigravity-ko-translator',
  'ko-thought-translator',
]);

const ALLOWED_TRANSLATOR_SETTING_KEYS = Object.freeze([
  'enabled',
  'translateThinking',
  'translateStaticUi',
  'provider',
  'customEndpoint',
]);

export function sanitizeTranslatorSettings(
  rawSettings,
  { remoteFallbackProvider = DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER } = {},
) {
  const input = rawSettings && typeof rawSettings === 'object' ? rawSettings : {};
  const sanitized = {
    enabled: input.enabled !== false,
    translateThinking: input.translateThinking !== false,
    translateStaticUi: input.translateStaticUi !== false,
    provider:
      typeof input.provider === 'string' && input.provider.trim()
        ? input.provider.trim()
        : remoteFallbackProvider,
    customEndpoint: null,
  };

  if (typeof input.customEndpoint === 'string' && input.customEndpoint.trim()) {
    try {
      const parsed = new URL(input.customEndpoint.trim());
      if (parsed.protocol === 'https:' && !parsed.username && !parsed.password) {
        sanitized.customEndpoint = parsed.toString();
      }
    } catch (_err) {
      sanitized.customEndpoint = null;
    }
  }

  const lowerProvider = sanitized.provider.toLowerCase();
  if (lowerProvider === 'local-llm' || (lowerProvider === 'custom-https' && !sanitized.customEndpoint)) {
    sanitized.provider = sanitized.customEndpoint ? 'custom-https' : remoteFallbackProvider;
  }

  const locked = {};
  for (const key of ALLOWED_TRANSLATOR_SETTING_KEYS) {
    locked[key] = sanitized[key];
  }
  return Object.freeze(locked);
}

function sanitizeGenericSettings(rawSettings) {
  if (!rawSettings || typeof rawSettings !== 'object' || Array.isArray(rawSettings)) {
    return Object.freeze({});
  }
  return stripSensitiveDeep(rawSettings) || Object.freeze({});
}

export function createAntigravitySettingsAdapter({
  readSettingsFile,
  remoteFallbackProvider = DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
} = {}) {
  if (typeof readSettingsFile !== 'function') {
    throw new TypeError('AntigravitySettingsAdapter requires a readSettingsFile callback.');
  }

  return {
    async readPluginSettings(pluginName) {
      const raw = await readSettingsFile(pluginName);
      if (TRANSLATOR_PLUGIN_NAMES.has(String(pluginName || '').trim())) {
        return sanitizeTranslatorSettings(raw, { remoteFallbackProvider });
      }
      return sanitizeGenericSettings(raw);
    },
  };
}

// --- module: src/adapters/antigravity/theme-workspace-adapter.js ---
/**
 * Antigravity implementation of ThemeWorkspaceSyncPort.
 * Tracks host CSS theme variables and active workspace URIs, notifying sidecar
 * bridges on changes so `theme-change` and `workspace-change` stay synchronized.
 */
export function createAntigravityThemeWorkspaceAdapter({
  initialThemeVariables = {},
  initialWorkspaceUris = [],
} = {}) {
  let themeVariables = { ...(initialThemeVariables || {}) };
  let workspaceUris = Array.isArray(initialWorkspaceUris) ? [...initialWorkspaceUris] : [];
  const listeners = new Set();

  function notify(payload) {
    for (const listener of [...listeners]) {
      listener(payload);
    }
  }

  return {
    getThemeVariables() {
      return { ...themeVariables };
    },

    getWorkspaceUris() {
      return [...workspaceUris];
    },

    subscribe(listener) {
      if (typeof listener !== 'function') {
        throw new TypeError('ThemeWorkspaceSyncPort listener must be a function.');
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },

    updateTheme(nextVariables) {
      themeVariables = { ...(nextVariables || {}) };
      notify({ type: 'theme-change', cssVariables: { ...themeVariables } });
    },

    updateWorkspaces(nextUris) {
      workspaceUris = Array.isArray(nextUris) ? [...nextUris] : [];
      notify({ type: 'workspace-change', workspaceUris: [...workspaceUris] });
    },
  };
}

// --- module: src/runtime/bootstrap.js ---
export const ANTIGRAVITY_STATUSBAR_API_PATHS = Object.freeze([
  '/api/telemetry',
  '/api/context-limit',
  '/api/compact',
]);

export const ANTIGRAVITY_SIDECAR_INBOUND_EVENTS = Object.freeze([
  'sidecar-key-event',
  'toggle-aux-pane',
  'toggle-conversation',
  'add-artifact-comment',
  'request-credential-refresh',
]);

export const ANTIGRAVITY_PROTECTED_MCP_PATHS = Object.freeze([
  /(?:^|\/)\.gemini\/config\/config\.json$/i,
  /(?:^|\/)\.gemini\/config\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/antigravity\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/config\/plugins\/[^/]+\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/config\/plugins\/[^/]+\/config\.json$/i,
]);

export function bootstrapAntigravityRemoteBridge({
  lsAddress,
  csrfToken,
  fetchImpl = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined,
  trustedTypesApi = globalThis.trustedTypes ?? null,
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  readSettingsFile = async () => ({}),
  createKoTranslator = null,
  mcpDelegate = null,
  initialFrame = null,
  initialThemeVariables = {},
  initialWorkspaceUris = [],
  hostLoadGuard = null,
  onSidecarEvent = null,
}) {
  const diagnostics = new DiagnosticsBus();

  const discoveryPort = createAntigravityDiscoveryAdapter({
    lsAddress,
    csrfToken,
    fetchImpl,
  });

  const framePort = createAntigravityFrameAdapter({
    allowedOrigins,
    trustedTypesApi,
    hostLoadGuard,
    diagnostics,
    initialFrame,
  });

  const sidecarRelayPort = createAntigravitySidecarAdapter({ fetchImpl });
  const settingsPort = createAntigravitySettingsAdapter({
    readSettingsFile,
    remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
  });
  const themeWorkspacePort = createAntigravityThemeWorkspaceAdapter({
    initialThemeVariables,
    initialWorkspaceUris,
  });

  const orchestrator = new RemoteOrchestrator({
    discoveryPort,
    framePort,
    diagnostics,
  });

  const bridges = {};

  if (typeof createKoTranslator === 'function') {
    const koBridge = createDomOverlayBridge({
      id: 'ko-translator-overlay',
      pluginName: 'antigravity-ko-translator',
      pluginAliases: ['ko-thought-translator'],
      createOverlay: createKoTranslator,
      settingsPort,
      sanitizeSettings: (raw) =>
        sanitizeTranslatorSettings(raw, {
          remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
        }),
    });
    orchestrator.registerBridge(koBridge);
    bridges.koTranslator = koBridge;
  }

  // Exact sidecar origin is derived dynamically from activeSidecar.host/port on mount;
  // never grant wildcard localhost:* / 127.0.0.1:* origins.
  const statusbarBridge = createSidecarUiBridge({
    id: 'statusbar-sidecar',
    pluginName: 'antigravity-statusbar',
    sidecarId: 'antigravity-statusbar/statusbar',
    relayPort: sidecarRelayPort,
    themeWorkspacePort,
    allowedOrigins: [],
    allowedApiPaths: ANTIGRAVITY_STATUSBAR_API_PATHS,
    allowedInboundEvents: ANTIGRAVITY_SIDECAR_INBOUND_EVENTS,
    onInboundEvent: onSidecarEvent,
  });
  orchestrator.registerBridge(statusbarBridge);
  bridges.statusbar = statusbarBridge;

  const mcpSlot = createMcpExtensionSlot({
    id: 'mcp-manager-slot',
    pluginName: 'antigravity-mcp-manager',
    protectedConfigPatterns: ANTIGRAVITY_PROTECTED_MCP_PATHS,
    delegate: mcpDelegate,
  });
  orchestrator.registerBridge(mcpSlot);
  bridges.mcpManager = mcpSlot;

  return {
    orchestrator,
    diagnostics,
    framePort,
    themeWorkspacePort,
    bridges,
  };
}
