// antigravity-remote-plugin v2.0.0 — standalone self-contained ESM bundle
// Built deterministically with esbuild from 28 library modules.

// src/security/redactor.js
var SENSITIVE_KEY_PATTERN = /^(authorization|cookie|set-cookie|token|access_token|refresh_token|csrf|csrf_token|x-sidecar-token|x-csrf-token|x-api-key|api_key|apikey|secret|password|passwd|env|headers)$/i;
var SENSITIVE_SUBSTRING_PATTERN = /(token|secret|password|passwd|csrf|authorization|apikey|api_key)/i;
var SENSITIVE_QUERY_PARAMS = /* @__PURE__ */ new Set([
  "token",
  "access_token",
  "refresh_token",
  "csrf",
  "csrf_token",
  "api_key",
  "apikey",
  "secret",
  "key",
  "password",
  "passwd",
  "x-sidecar-token"
]);
var INLINE_PARAM_PATTERN = /([?&#](?:token|access_token|refresh_token|csrf|csrf_token|api_key|apikey|secret|key|password|passwd|x-sidecar-token)=)([^&#]*)/gi;
var INLINE_USERINFO_PATTERN = /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:)([^/\s@]+)(@)/g;
var REDACTED = "[REDACTED]";
function redactFragment(hash) {
  if (!hash || hash.length <= 1) {
    return hash;
  }
  return hash.replace(INLINE_PARAM_PATTERN, `$1${REDACTED}`);
}
function redactUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) {
    return rawUrl;
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_err) {
    return rawUrl.replace(INLINE_USERINFO_PATTERN, `$1${REDACTED}$3`).replace(INLINE_PARAM_PATTERN, `$1${REDACTED}`);
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
var NUMERIC_TOKEN_METRIC_PATTERN = /^(?:used|max|total|input|output|cached|prompt|completion|context|remaining)[a-z0-9_]*token(?:s|limit|count)?$/i;
function isSensitiveKey(key, value = void 0) {
  if (typeof key !== "string") {
    return false;
  }
  const normalized = key.trim();
  if (typeof value === "number" && Number.isInteger(value) && Number.isFinite(value) && NUMERIC_TOKEN_METRIC_PATTERN.test(normalized)) {
    return false;
  }
  return SENSITIVE_KEY_PATTERN.test(normalized) || SENSITIVE_SUBSTRING_PATTERN.test(normalized);
}
function redactSecrets(value, depth = 0, seen = /* @__PURE__ */ new WeakSet()) {
  if (depth > 8) {
    return "[TRUNCATED]";
  }
  if (value === null || value === void 0) {
    return value;
  }
  if (typeof value === "string") {
    return redactUrl(value);
  }
  if (typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return "[CIRCULAR]";
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item, depth + 1, seen));
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactUrl(value.message || ""),
      code: value.code ?? void 0
    };
  }
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (isSensitiveKey(k, v)) {
      out[k] = REDACTED;
    } else {
      out[k] = redactSecrets(v, depth + 1, seen);
    }
  }
  return out;
}
function stripSensitiveDeep(value, depth = 0, seen = /* @__PURE__ */ new WeakSet()) {
  if (depth > 8 || value === null || value === void 0 || typeof value === "function") {
    return void 0;
  }
  if (typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return void 0;
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const arr = [];
      for (const item of value) {
        if (typeof item === "function") {
          continue;
        }
        const cleaned = stripSensitiveDeep(item, depth + 1, seen);
        if (cleaned !== void 0 || item === null) {
          arr.push(cleaned === void 0 ? null : cleaned);
        }
      }
      return Object.freeze(arr);
    }
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (isSensitiveKey(k) || typeof v === "function") {
        continue;
      }
      const cleaned = stripSensitiveDeep(v, depth + 1, seen);
      if (cleaned !== void 0 || v === null) {
        out[k] = cleaned === void 0 ? null : cleaned;
      }
    }
    return Object.freeze(out);
  } finally {
    seen.delete(value);
  }
}
function deepFreeze(value, seen = /* @__PURE__ */ new WeakSet()) {
  if (value === null || typeof value !== "object" || seen.has(value)) {
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

// src/security/origin-policy.js
var SecurityPolicyError = class extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SecurityPolicyError";
    this.code = code;
  }
};
function normalizeOrigin(rawOrigin) {
  if (typeof rawOrigin !== "string" || rawOrigin.trim().length === 0) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(rawOrigin);
  } catch (_err) {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return null;
  }
  return {
    origin: parsed.origin.toLowerCase(),
    protocol: parsed.protocol.toLowerCase(),
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port || ""
  };
}
function isLoopbackHostname(hostname) {
  if (typeof hostname !== "string") {
    return false;
  }
  const lower = hostname.trim().toLowerCase();
  return lower === "127.0.0.1" || lower === "localhost" || lower === "[::1]" || lower === "::1";
}
function formatHostForUrl(hostname) {
  if (typeof hostname !== "string" || !hostname.trim()) {
    throw new SecurityPolicyError("INVALID_HOST", "Hostname must be a non-empty string.");
  }
  const trimmed = hostname.trim();
  if (trimmed.includes(":") && !trimmed.startsWith("[")) {
    return `[${trimmed}]`;
  }
  return trimmed;
}
function matchesDomainBoundary(hostname, rule) {
  if (typeof hostname !== "string" || typeof rule !== "string") {
    return false;
  }
  const host = hostname.toLowerCase();
  const pattern = rule.trim().toLowerCase();
  if (!pattern) {
    return false;
  }
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    if (!suffix || suffix.includes("*")) {
      return false;
    }
    return host.length > suffix.length + 1 && host.endsWith(`.${suffix}`);
  }
  return host === pattern;
}
function isOriginAllowed(candidateOrigin, allowlist) {
  const candidate = normalizeOrigin(candidateOrigin);
  if (!candidate || !Array.isArray(allowlist) || allowlist.length === 0) {
    return false;
  }
  for (const rawRule of allowlist) {
    if (typeof rawRule !== "string") {
      continue;
    }
    const rule = rawRule.trim().toLowerCase();
    if (!rule) {
      continue;
    }
    if (rule.startsWith("https://*.")) {
      if (candidate.protocol !== "https:") {
        continue;
      }
      const hostPattern = rule.slice("https://".length);
      if (matchesDomainBoundary(candidate.hostname, hostPattern) && candidate.port === "") {
        return true;
      }
      continue;
    }
    if (rule === "http://127.0.0.1:*" || rule === "http://localhost:*" || rule === "http://[::1]:*") {
      if (candidate.protocol !== "http:") {
        continue;
      }
      const expectedHost = rule.startsWith("http://127.0.0.1") ? "127.0.0.1" : rule.startsWith("http://[::1]") ? "[::1]" : "localhost";
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
function assertOriginAllowed(candidateOrigin, allowlist, context = "origin") {
  if (!isOriginAllowed(candidateOrigin, allowlist)) {
    throw new SecurityPolicyError(
      "ORIGIN_NOT_ALLOWED",
      `Blocked untrusted ${context}: origin is not in the allowlist.`
    );
  }
}

// src/security/trusted-types.js
var RESERVED_TRUSTED_TYPES_POLICIES = Object.freeze([
  "default",
  "dompurify",
  "angular"
]);
var POLICY_CACHE = /* @__PURE__ */ new WeakMap();
function assertAllowedPolicyName(policyName) {
  if (typeof policyName !== "string" || policyName.trim().length === 0) {
    throw new SecurityPolicyError(
      "INVALID_TRUSTED_TYPES_POLICY",
      "TrustedTypes policy name must be a non-empty string."
    );
  }
  const normalized = policyName.trim().toLowerCase();
  if (RESERVED_TRUSTED_TYPES_POLICIES.includes(normalized)) {
    throw new SecurityPolicyError(
      "RESERVED_TRUSTED_TYPES_POLICY",
      `Creating reserved TrustedTypes policy "${policyName}" is forbidden.`
    );
  }
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(policyName.trim())) {
    throw new SecurityPolicyError(
      "INVALID_TRUSTED_TYPES_POLICY",
      `TrustedTypes policy name "${policyName}" contains invalid characters.`
    );
  }
}
function createScopedTrustedTypesPolicy({
  trustedTypesApi = null,
  policyName = "remote-bridge-script-v1",
  validateScriptUrl
}) {
  assertAllowedPolicyName(policyName);
  if (typeof validateScriptUrl !== "function") {
    throw new SecurityPolicyError(
      "MISSING_SCRIPT_VALIDATOR",
      "A script URL validator function is required to create a TrustedTypes policy."
    );
  }
  const trimmedName = policyName.trim();
  if (!trustedTypesApi || typeof trustedTypesApi.createPolicy !== "function") {
    return {
      name: trimmedName,
      isNative: false,
      createScriptURL(url) {
        if (!validateScriptUrl(url)) {
          throw new SecurityPolicyError(
            "UNTRUSTED_SCRIPT_URL",
            "Script URL failed allowlist validation."
          );
        }
        return url;
      }
    };
  }
  let apiCache = POLICY_CACHE.get(trustedTypesApi);
  if (!apiCache) {
    apiCache = /* @__PURE__ */ new Map();
    POLICY_CACHE.set(trustedTypesApi, apiCache);
  }
  let entry = apiCache.get(trimmedName);
  if (!entry) {
    const holder = { validator: validateScriptUrl };
    const nativePolicy = trustedTypesApi.createPolicy(trimmedName, {
      createScriptURL(url) {
        if (!holder.validator(url)) {
          throw new SecurityPolicyError(
            "UNTRUSTED_SCRIPT_URL",
            "Script URL failed allowlist validation."
          );
        }
        return url;
      }
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
          "UNTRUSTED_SCRIPT_URL",
          "Script URL failed allowlist validation."
        );
      }
      entry.holder.validator = validateScriptUrl;
      return entry.nativePolicy.createScriptURL(url);
    }
  };
}

// src/security/script-guard.js
var FORBIDDEN_PROTOCOLS = /* @__PURE__ */ new Set([
  "javascript:",
  "data:",
  "vbscript:",
  "file:",
  "blob:"
]);
function isTrustedScriptUrl(rawUrl, allowlist) {
  if (typeof rawUrl !== "string" || rawUrl.trim().length === 0) {
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
  if (proto !== "https:" && proto !== "http:") {
    return false;
  }
  return isOriginAllowed(parsed.origin, allowlist);
}
function isTrustedBlobUrl(rawUrl, allowlist) {
  if (typeof rawUrl !== "string" || !rawUrl.startsWith("blob:")) {
    return false;
  }
  const inner = rawUrl.slice("blob:".length);
  let parsed;
  try {
    parsed = new URL(inner);
  } catch (_err) {
    return false;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return false;
  }
  return isOriginAllowed(parsed.origin, allowlist);
}
function isTrustedWorkerOrScriptUrl(rawUrl, allowlist) {
  return isTrustedScriptUrl(rawUrl, allowlist) || isTrustedBlobUrl(rawUrl, allowlist);
}
function assertTrustedScriptUrl(rawUrl, allowlist) {
  if (!isTrustedScriptUrl(rawUrl, allowlist)) {
    throw new SecurityPolicyError(
      "UNTRUSTED_SCRIPT_URL",
      "Blocked script URL outside trusted origin allowlist."
    );
  }
}
function createGuardedWorkerBlobUrl({
  scriptUrl,
  allowlist,
  createBlobUrl,
  trustedTypesPolicy = null
}) {
  assertTrustedScriptUrl(scriptUrl, allowlist);
  if (typeof createBlobUrl !== "function") {
    throw new SecurityPolicyError(
      "MISSING_BLOB_FACTORY",
      "A Blob URL factory function is required."
    );
  }
  const rawBlobUrl = createBlobUrl(scriptUrl);
  if (!isTrustedBlobUrl(rawBlobUrl, allowlist)) {
    throw new SecurityPolicyError(
      "UNTRUSTED_SCRIPT_URL",
      "Generated Worker Blob URL failed trusted origin allowlist validation."
    );
  }
  if (trustedTypesPolicy) {
    return trustedTypesPolicy.createScriptURL(rawBlobUrl);
  }
  return rawBlobUrl;
}

// src/security/dom-guard.js
var FORBIDDEN_TAGS = /* @__PURE__ */ new Set(["base", "script", "object", "embed"]);
var FORBIDDEN_PROP_PREFIXES = Object.freeze(["on"]);
var FORBIDDEN_HTML_PROPS = /* @__PURE__ */ new Set([
  ["inner", "HTML"].join(""),
  ["outer", "HTML"].join(""),
  ["insertAdjacent", "HTML"].join(""),
  "srcdoc"
]);
var FORBIDDEN_URI_SCHEME_PATTERN = /^(?:javascript|vbscript|data):/i;
function normalizeUriForSchemeCheck(rawValue) {
  return String(rawValue).replace(/[\u0000-\u0020\u007f]+/g, "");
}
function assertSafeTagName(tagName) {
  if (typeof tagName !== "string" || tagName.trim().length === 0) {
    throw new SecurityPolicyError("INVALID_TAG_NAME", "Tag name must be a non-empty string.");
  }
  const normalized = tagName.trim().toLowerCase();
  if (FORBIDDEN_TAGS.has(normalized)) {
    throw new SecurityPolicyError(
      "FORBIDDEN_ELEMENT_TAG",
      `Creating <${normalized}> elements is forbidden by security policy.`
    );
  }
  return normalized;
}
function assertSafeAttribute(attrName, attrValue) {
  if (typeof attrName !== "string" || attrName.trim().length === 0) {
    throw new SecurityPolicyError("INVALID_ATTRIBUTE", "Attribute name must be non-empty.");
  }
  const normalized = attrName.trim();
  const lower = normalized.toLowerCase();
  if (FORBIDDEN_HTML_PROPS.has(normalized) || FORBIDDEN_HTML_PROPS.has(lower)) {
    throw new SecurityPolicyError(
      "FORBIDDEN_HTML_SINK",
      `Setting unsafe HTML sink "${attrName}" is forbidden.`
    );
  }
  for (const prefix of FORBIDDEN_PROP_PREFIXES) {
    if (lower.startsWith(prefix) && lower.length > prefix.length) {
      throw new SecurityPolicyError(
        "FORBIDDEN_EVENT_ATTRIBUTE",
        `Inline event handler attribute "${attrName}" is forbidden.`
      );
    }
  }
  if (attrValue !== null && attrValue !== void 0) {
    const collapsed = normalizeUriForSchemeCheck(attrValue);
    if (FORBIDDEN_URI_SCHEME_PATTERN.test(collapsed)) {
      throw new SecurityPolicyError(
        "FORBIDDEN_URI_SCHEME",
        `Dangerous URI scheme in attribute "${attrName}" is forbidden.`
      );
    }
  }
}
function createSafeElement(doc, tagName, { attrs = {}, text = null } = {}) {
  const safeTag = assertSafeTagName(tagName);
  if (!doc || typeof doc.createElement !== "function") {
    throw new SecurityPolicyError("INVALID_DOCUMENT", "A document with createElement is required.");
  }
  const el = doc.createElement(safeTag);
  for (const [key, val] of Object.entries(attrs)) {
    const stringVal = val !== null && val !== void 0 ? String(val) : val;
    assertSafeAttribute(key, stringVal);
    if (stringVal !== null && stringVal !== void 0) {
      el.setAttribute(key, stringVal);
    }
  }
  if (text !== null && text !== void 0) {
    el.textContent = String(text);
  }
  return el;
}

// src/security/plugin-handshake.js
var HANDSHAKE_REQUEST_TYPE = "remote-plugin-v1:handshake-request";
var HANDSHAKE_CHALLENGE_TYPE = "remote-plugin-v1:handshake-challenge";
var HANDSHAKE_PROTOCOL_TYPE = "remote-plugin-v1:handshake-init";
var HANDSHAKE_ACK_TYPE = "remote-plugin-v1:handshake-ack";
var DEFAULT_NONCE_TTL_MS = 3e4;
var MAX_PENDING_NONCES = 128;
function generateHandshakeNonce(byteLength = 24) {
  const bytes = new Uint8Array(byteLength);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new SecurityPolicyError(
      "ERR_CRYPTO_UNAVAILABLE",
      "Web Crypto API is required to generate cryptographic handshake nonces."
    );
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function createPluginHandshakeHost({
  win,
  allowedOrigins,
  onPortConnected,
  nonceTtlMs = DEFAULT_NONCE_TTL_MS,
  now = () => Date.now()
}) {
  if (!win || typeof win.addEventListener !== "function") {
    throw new SecurityPolicyError("ERR_INVALID_WINDOW", "A window with event listeners is required.");
  }
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
    throw new SecurityPolicyError("ERR_EMPTY_ALLOWLIST", "An explicit allowedOrigins array is required.");
  }
  if (typeof onPortConnected !== "function") {
    throw new TypeError("onPortConnected callback is required.");
  }
  const pendingNonces = /* @__PURE__ */ new Map();
  const activePorts = /* @__PURE__ */ new Set();
  let disposed = false;
  function pruneExpiredNonces() {
    const t = now();
    for (const [nonce, meta] of pendingNonces.entries()) {
      if (meta.expiresAt <= t) {
        pendingNonces.delete(nonce);
      }
    }
  }
  function issueNonceInternal({ boundOrigin = null, boundSource = null } = {}) {
    if (disposed) {
      throw new SecurityPolicyError("ERR_HANDSHAKE_DISPOSED", "Handshake host is disposed.");
    }
    pruneExpiredNonces();
    if (pendingNonces.size >= MAX_PENDING_NONCES) {
      const oldestKey = pendingNonces.keys().next().value;
      if (oldestKey !== void 0) {
        pendingNonces.delete(oldestKey);
      }
    }
    const nonce = generateHandshakeNonce();
    pendingNonces.set(nonce, {
      expiresAt: now() + Math.max(100, Number(nonceTtlMs) || DEFAULT_NONCE_TTL_MS),
      boundOrigin,
      boundSource
    });
    return nonce;
  }
  const onMessage = (event) => {
    if (disposed || !event || typeof event !== "object") {
      return;
    }
    if (!isOriginAllowed(event.origin, allowedOrigins)) {
      return;
    }
    const data = event.data;
    if (!data || typeof data !== "object") {
      return;
    }
    if (data.type === HANDSHAKE_REQUEST_TYPE) {
      if (typeof data.requestId !== "string" || !data.requestId || data.requestId.length > 128) {
        return;
      }
      const replyTarget = event.source;
      if (!replyTarget || typeof replyTarget.postMessage !== "function") {
        return;
      }
      const nonce = issueNonceInternal({
        boundOrigin: event.origin,
        boundSource: replyTarget
      });
      replyTarget.postMessage(
        {
          type: HANDSHAKE_CHALLENGE_TYPE,
          requestId: data.requestId,
          nonce
        },
        event.origin
      );
      return;
    }
    if (data.type !== HANDSHAKE_PROTOCOL_TYPE) {
      return;
    }
    pruneExpiredNonces();
    if (typeof data.nonce !== "string" || !pendingNonces.has(data.nonce)) {
      return;
    }
    const meta = pendingNonces.get(data.nonce);
    if (meta.boundOrigin && meta.boundOrigin !== event.origin) {
      return;
    }
    if (meta.boundSource && event.source !== meta.boundSource) {
      return;
    }
    const port = Array.isArray(event.ports) ? event.ports[0] : null;
    if (!port || typeof port.postMessage !== "function") {
      return;
    }
    pendingNonces.delete(data.nonce);
    activePorts.add(port);
    if (typeof port.start === "function") {
      port.start();
    }
    let closed = false;
    const closePort = () => {
      if (closed) {
        return;
      }
      closed = true;
      activePorts.delete(port);
      if (typeof port.close === "function") {
        port.close();
      }
    };
    port.postMessage({ type: HANDSHAKE_ACK_TYPE, accepted: true });
    onPortConnected({
      port,
      origin: event.origin,
      pluginId: typeof data.pluginId === "string" ? data.pluginId : null,
      close: closePort
    });
  };
  win.addEventListener("message", onMessage);
  return Object.freeze({
    issueNonce() {
      return issueNonceInternal();
    },
    pendingCount() {
      pruneExpiredNonces();
      return pendingNonces.size;
    },
    activePortCount() {
      return activePorts.size;
    },
    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      pendingNonces.clear();
      if (typeof win.removeEventListener === "function") {
        win.removeEventListener("message", onMessage);
      }
      for (const port of [...activePorts]) {
        activePorts.delete(port);
        if (typeof port.close === "function") {
          port.close();
        }
      }
    }
  });
}
function initiatePluginHandshake({
  targetWindow,
  targetOrigin,
  allowedOrigins,
  nonce,
  pluginId,
  MessageChannelCtor = globalThis.MessageChannel
}) {
  assertOriginAllowed(targetOrigin, allowedOrigins, "handshake targetOrigin");
  if (typeof nonce !== "string" || nonce.length < 16) {
    throw new SecurityPolicyError("ERR_INVALID_NONCE", "A cryptographic nonce is required.");
  }
  if (typeof MessageChannelCtor !== "function") {
    throw new SecurityPolicyError("ERR_NO_MESSAGE_CHANNEL", "MessageChannel is unavailable.");
  }
  const channel = new MessageChannelCtor();
  if (typeof channel.port1.start === "function") {
    channel.port1.start();
  }
  targetWindow.postMessage(
    {
      type: HANDSHAKE_PROTOCOL_TYPE,
      nonce,
      pluginId: typeof pluginId === "string" ? pluginId : null
    },
    targetOrigin,
    [channel.port2]
  );
  return channel.port1;
}
async function connectPluginHandshake({
  selfWindow,
  targetWindow,
  targetOrigin,
  allowedOrigins,
  pluginId,
  timeoutMs = 5e3,
  MessageChannelCtor = globalThis.MessageChannel
}) {
  assertOriginAllowed(targetOrigin, allowedOrigins, "handshake targetOrigin");
  if (!selfWindow || typeof selfWindow.addEventListener !== "function") {
    throw new SecurityPolicyError("ERR_INVALID_WINDOW", "selfWindow with event listeners is required.");
  }
  const requestId = generateHandshakeNonce(12);
  return new Promise((resolve, reject) => {
    let settled = false;
    let clientPort = null;
    const cleanup = () => {
      clearTimeout(timer);
      if (typeof selfWindow.removeEventListener === "function") {
        selfWindow.removeEventListener("message", onChallenge);
      }
    };
    const fail = (err) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (clientPort && typeof clientPort.close === "function") {
        clientPort.close();
      }
      reject(err);
    };
    const timer = setTimeout(() => {
      fail(new SecurityPolicyError("ERR_HANDSHAKE_TIMEOUT", "Plugin handshake timed out."));
    }, timeoutMs);
    const onChallenge = (event) => {
      if (settled || !event || event.origin !== targetOrigin || event.source !== targetWindow) {
        return;
      }
      const data = event.data;
      if (!data || data.type !== HANDSHAKE_CHALLENGE_TYPE || data.requestId !== requestId) {
        return;
      }
      cleanup();
      try {
        clientPort = initiatePluginHandshake({
          targetWindow,
          targetOrigin,
          allowedOrigins,
          nonce: data.nonce,
          pluginId,
          MessageChannelCtor
        });
      } catch (err) {
        fail(err);
        return;
      }
      const ackTimer = setTimeout(() => {
        fail(new SecurityPolicyError("ERR_HANDSHAKE_ACK_TIMEOUT", "Plugin handshake ACK timed out."));
      }, timeoutMs);
      const onAck = (ackEvent) => {
        const msg = ackEvent?.data;
        if (!msg || msg.type !== HANDSHAKE_ACK_TYPE || msg.accepted !== true) {
          return;
        }
        clearTimeout(ackTimer);
        if (typeof clientPort.removeEventListener === "function") {
          clientPort.removeEventListener("message", onAck);
        }
        if (!settled) {
          settled = true;
          resolve(clientPort);
        }
      };
      if (typeof clientPort.addEventListener === "function") {
        clientPort.addEventListener("message", onAck);
      } else {
        clientPort.onmessage = onAck;
      }
    };
    selfWindow.addEventListener("message", onChallenge);
    targetWindow.postMessage(
      {
        type: HANDSHAKE_REQUEST_TYPE,
        requestId
      },
      targetOrigin
    );
  });
}

// src/core/diagnostics.js
var DEFAULT_MAX_EVENTS = 200;
var DiagnosticsBus = class {
  #events = [];
  #listeners = /* @__PURE__ */ new Set();
  #maxEvents;
  constructor({ maxEvents = DEFAULT_MAX_EVENTS } = {}) {
    this.#maxEvents = Math.max(1, Number(maxEvents) || DEFAULT_MAX_EVENTS);
  }
  emit({ level = "info", code, source, message, detail = null }) {
    const entry = deepFreeze({
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      level,
      code: String(code || "UNKNOWN"),
      source: String(source || "core"),
      message: String(redactSecrets(message || "")),
      detail: detail === null || detail === void 0 ? null : redactSecrets(detail)
    });
    this.#events.push(entry);
    if (this.#events.length > this.#maxEvents) {
      this.#events.splice(0, this.#events.length - this.#maxEvents);
    }
    for (const listener of [...this.#listeners]) {
      try {
        listener(entry);
      } catch (_listenerErr) {
      }
    }
    return entry;
  }
  subscribe(listener) {
    if (typeof listener !== "function") {
      throw new TypeError("Diagnostics listener must be a function.");
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
};

// src/core/lifecycle.js
var DisposableStore = class {
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
    const fn = typeof disposable === "function" ? disposable : disposable && typeof disposable.dispose === "function" ? () => disposable.dispose() : null;
    if (!fn) {
      throw new TypeError("Disposable must be a function or an object with dispose().");
    }
    if (this.#disposed) {
      this.#invokeSafe(fn, "late-add");
      return () => {
      };
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
      this.#invokeSafe(fn, "manual-remove");
    };
  }
  dispose() {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    const toRun = this.#disposers.splice(0, this.#disposers.length).reverse();
    for (const fn of toRun) {
      this.#invokeSafe(fn, "store-dispose");
    }
  }
  #invokeSafe(fn, phase) {
    try {
      fn();
    } catch (err) {
      if (this.#diagnostics) {
        this.#diagnostics.emit({
          level: "error",
          code: "DISPOSE_FAILED",
          source: "core.lifecycle",
          message: `Disposer failed during ${phase}`,
          detail: err
        });
      }
    }
  }
};
var AsyncMutex = class {
  #tail = Promise.resolve();
  async runExclusive(taskFn) {
    if (typeof taskFn !== "function") {
      throw new TypeError("AsyncMutex taskFn must be a function.");
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
};
var EventChain = class {
  #handlers = /* @__PURE__ */ new Map();
  #nextId = 1;
  #hostGuard;
  #diagnostics;
  constructor({ hostGuard = null, diagnostics = null } = {}) {
    this.#hostGuard = typeof hostGuard === "function" ? hostGuard : null;
    this.#diagnostics = diagnostics;
  }
  get size() {
    return this.#handlers.size;
  }
  register(handler, { label = "anonymous" } = {}) {
    if (typeof handler !== "function") {
      throw new TypeError("EventChain handler must be a function.");
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
        if (result && typeof result.then === "function") {
          result.catch((err) => {
            if (this.#diagnostics) {
              this.#diagnostics.emit({
                level: "error",
                code: "EVENT_CHAIN_ASYNC_HANDLER_FAILED",
                source: "core.lifecycle",
                message: `Async handler "${label}" rejected during dispatch`,
                detail: err
              });
            }
          });
        }
      } catch (err) {
        if (this.#diagnostics) {
          this.#diagnostics.emit({
            level: "error",
            code: "EVENT_CHAIN_HANDLER_FAILED",
            source: "core.lifecycle",
            message: `Handler "${label}" threw during dispatch`,
            detail: err
          });
        }
      }
    }
    return { allowed: guardResult, invoked };
  }
  clear() {
    this.#handlers.clear();
  }
};
var SingleFlight = class {
  #inflight = /* @__PURE__ */ new Map();
  async run(key, taskFn) {
    if (typeof taskFn !== "function") {
      throw new TypeError("SingleFlight taskFn must be a function.");
    }
    const existing = this.#inflight.get(key);
    if (existing) {
      return existing;
    }
    const promise = Promise.resolve().then(() => taskFn()).finally(() => {
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
};

// src/core/ports.js
function assertPort(port, portName, requiredMethods) {
  if (!port || typeof port !== "object") {
    throw new TypeError(`Missing required port "${portName}".`);
  }
  for (const method of requiredMethods) {
    if (typeof port[method] !== "function") {
      throw new TypeError(`Port "${portName}" must implement method "${method}()".`);
    }
  }
  return port;
}
var PORT_CONTRACTS = Object.freeze({
  HostDiscoveryPort: Object.freeze(["listPlugins", "listSidecars"]),
  FramePromotionPort: Object.freeze(["acquireActiveFrame", "onFrameChange"]),
  SidecarRelayPort: Object.freeze(["requestJson", "buildUiUrl"]),
  SettingsReadPort: Object.freeze(["readPluginSettings"]),
  ThemeWorkspaceSyncPort: Object.freeze(["getThemeVariables", "getWorkspaceUris", "subscribe"]),
  ExtensionBridgePort: Object.freeze(["id", "pluginName", "mount", "dispose"]),
  HostSurfacePort: Object.freeze([
    "mountSlot",
    "unmountSlot",
    "injectStyle",
    "removeStyle",
    "listOwnedSlots",
    "onDispose",
    "dispose"
  ])
});
function validateDiscoveryPort(port) {
  return assertPort(port, "HostDiscoveryPort", PORT_CONTRACTS.HostDiscoveryPort);
}
function validateFramePromotionPort(port) {
  return assertPort(port, "FramePromotionPort", PORT_CONTRACTS.FramePromotionPort);
}
function validateSidecarRelayPort(port) {
  return assertPort(port, "SidecarRelayPort", PORT_CONTRACTS.SidecarRelayPort);
}
function validateSettingsReadPort(port) {
  return assertPort(port, "SettingsReadPort", PORT_CONTRACTS.SettingsReadPort);
}
function validateThemeWorkspaceSyncPort(port) {
  return assertPort(port, "ThemeWorkspaceSyncPort", PORT_CONTRACTS.ThemeWorkspaceSyncPort);
}
function validateHostSurfacePort(port) {
  return assertPort(port, "HostSurfacePort", PORT_CONTRACTS.HostSurfacePort);
}
function validateBridgeDescriptor(bridge) {
  if (!bridge || typeof bridge !== "object") {
    throw new TypeError("Bridge descriptor must be an object.");
  }
  if (typeof bridge.id !== "string" || !bridge.id.trim()) {
    throw new TypeError("Bridge descriptor must have a non-empty string id.");
  }
  if (typeof bridge.pluginName !== "string" || !bridge.pluginName.trim()) {
    throw new TypeError(`Bridge "${bridge.id}" must declare a non-empty pluginName.`);
  }
  if (typeof bridge.mount !== "function" || typeof bridge.dispose !== "function") {
    throw new TypeError(`Bridge "${bridge.id}" must implement mount() and dispose().`);
  }
  return bridge;
}

// src/core/orchestrator.js
function computeSidecarFingerprint(sidecar) {
  if (!sidecar || typeof sidecar !== "object") {
    return null;
  }
  return `${sidecar.sidecarId || ""}|${sidecar.host || "127.0.0.1"}|${sidecar.port || ""}|${sidecar.token || ""}`;
}
function buildDiscoveryFlightKey(context) {
  if (!context || typeof context !== "object" || !Array.isArray(context.workspaceUris)) {
    return "discovery:";
  }
  const normalized = context.workspaceUris.filter((uri) => typeof uri === "string" && uri.trim().length > 0).map((uri) => uri.trim()).sort();
  return `discovery:${normalized.join("\0")}`;
}
var RemoteOrchestrator = class {
  #discoveryPort;
  #framePort;
  #diagnostics;
  #bridges = /* @__PURE__ */ new Map();
  #mounted = /* @__PURE__ */ new Map();
  #mountedFingerprints = /* @__PURE__ */ new Map();
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
    const flightKey = buildDiscoveryFlightKey(context);
    return this.#singleFlight.run(flightKey, async () => {
      const [plugins, sidecars] = await Promise.all([
        this.#discoveryPort.listPlugins(context),
        this.#discoveryPort.listSidecars(context)
      ]);
      if (!Array.isArray(plugins)) {
        throw new TypeError("HostDiscoveryPort.listPlugins() must return an array.");
      }
      if (!Array.isArray(sidecars)) {
        throw new TypeError("HostDiscoveryPort.listSidecars() must return an array.");
      }
      const activePlugins = /* @__PURE__ */ new Map();
      for (const plugin of plugins) {
        if (!plugin || typeof plugin.name !== "string") {
          continue;
        }
        const isEnabled = plugin.disabled !== true && plugin.enabled !== false;
        if (isEnabled) {
          activePlugins.set(plugin.name, plugin);
          if (typeof plugin.dir === "string" && plugin.dir.trim()) {
            activePlugins.set(plugin.dir.trim(), plugin);
          }
        }
      }
      const activeSidecars = /* @__PURE__ */ new Map();
      for (const sidecar of sidecars) {
        if (!sidecar || typeof sidecar.sidecarId !== "string") {
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
      if (typeof unsubFrame === "function") {
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
      const sidecarRecord = bridge.sidecarId ? activeSidecars.get(bridge.sidecarId) ?? null : null;
      const isEligible = Boolean(pluginRecord) && (!bridge.requireSidecar || Boolean(sidecarRecord));
      if (!isEligible) {
        if (this.#mounted.has(bridgeId)) {
          this.#unmountBridge(bridgeId);
        }
        skippedIds.push(bridgeId);
        this.#diagnostics.emit({
          level: "info",
          code: "BRIDGE_SKIPPED_INACTIVE",
          source: "core.orchestrator",
          message: `Skipped bridge "${bridgeId}": authoritative plugin/sidecar not active`,
          detail: { bridgeId, pluginName: bridge.pluginName, sidecarId: bridge.sidecarId ?? null }
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
        this.#unmountBridge(bridgeId);
      }
      try {
        await bridge.mount({
          frame: this.#activeFrame,
          plugin: pluginRecord,
          sidecar: sidecarRecord,
          diagnostics: this.#diagnostics
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
          level: "error",
          code: "BRIDGE_MOUNT_FAILED",
          source: "core.orchestrator",
          message: `Failed to mount bridge "${bridgeId}"`,
          detail: err
        });
      }
    }
    return { mountedIds, skippedIds, failedIds, activePlugins, activeSidecars };
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
        if (typeof alias === "string" && activePlugins.has(alias)) {
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
        level: "error",
        code: "BRIDGE_DISPOSE_FAILED",
        source: "core.orchestrator",
        message: `Failed to dispose bridge "${bridgeId}"`,
        detail: err
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
};

// src/core/remote-plugin-contract.js
var REMOTE_PLUGIN_CONTRACT_VERSION = "remote-plugin.v1";
var ALLOWED_UI_SLOTS = Object.freeze([
  "title-bar",
  "sidebar",
  "status-bar",
  "composer-toolbar",
  "settings-pane",
  "aux-pane",
  "modal",
  "overlay",
  "theme",
  "custom"
]);
var ALLOWED_CAPABILITIES = Object.freeze([
  "badge",
  "panel",
  "actions",
  "subscribe"
]);
var ALLOWED_SLOT_SET = new Set(ALLOWED_UI_SLOTS);
var ALLOWED_CAPABILITY_SET = new Set(ALLOWED_CAPABILITIES);
var ALLOWED_TONES = /* @__PURE__ */ new Set(["neutral", "info", "ok", "warn", "error"]);
var ALLOWED_BUTTON_STYLES = /* @__PURE__ */ new Set(["primary", "secondary", "danger"]);
var ALLOWED_ACTION_STATUSES = /* @__PURE__ */ new Set([
  "ok",
  "confirmation_required",
  "conflict",
  "error"
]);
var FORBIDDEN_KEYS = /* @__PURE__ */ new Set(["__proto__", "constructor", "prototype"]);
var PLUGIN_ID_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
var SLOT_ID_RE = /^[a-z0-9][a-z0-9._-]{1,95}$/;
var ACTION_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$/;
var SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
var BIDI_CONTROL_RE = /[\u202A-\u202E\u2066-\u2069]/;
var DANGEROUS_URI_RE = /(?:javascript|vbscript|data)\s*:/i;
var RAW_MARKUP_RE = /<\s*(?:script|svg|iframe|object|embed|style|link|base)\b/i;
var MAX_TEXT_LENGTH = 1e3;
var MAX_SECTIONS = 24;
var MAX_ITEMS_PER_SECTION = 64;
function isPlainObject(val) {
  if (!val || typeof val !== "object" || Array.isArray(val)) {
    return false;
  }
  const proto = Object.getPrototypeOf(val);
  return proto === Object.prototype || proto === null;
}
function assertNoForbiddenKeys(obj, label) {
  if (!obj || typeof obj !== "object") {
    return;
  }
  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new SecurityPolicyError(
        "ERR_FORBIDDEN_KEY",
        `Forbidden key "${key}" detected in ${label}.`
      );
    }
  }
}
function assertSafeText(value, label, { maxLength = MAX_TEXT_LENGTH } = {}) {
  if (typeof value !== "string") {
    throw new SecurityPolicyError("ERR_INVALID_TEXT", `${label} must be a string.`);
  }
  if (value.length > maxLength) {
    throw new SecurityPolicyError(
      "ERR_TEXT_TOO_LONG",
      `${label} exceeds maximum allowed length (${maxLength}).`
    );
  }
  if (BIDI_CONTROL_RE.test(value)) {
    throw new SecurityPolicyError(
      "ERR_FORBIDDEN_BIDI_CONTROL",
      `${label} contains forbidden bidirectional override control characters.`
    );
  }
  const collapsed = value.replace(/[\u0000-\u0020\u007f]+/g, "");
  if (DANGEROUS_URI_RE.test(collapsed)) {
    throw new SecurityPolicyError(
      "ERR_FORBIDDEN_URI_SCHEME",
      `${label} contains a forbidden URI scheme.`
    );
  }
  if (RAW_MARKUP_RE.test(value)) {
    throw new SecurityPolicyError(
      "ERR_FORBIDDEN_MARKUP",
      `${label} contains forbidden active HTML or SVG markup.`
    );
  }
  return value;
}
function assertSafeLocalizedText(value, label) {
  if (typeof value === "string") {
    return assertSafeText(value, label);
  }
  if (!isPlainObject(value)) {
    throw new SecurityPolicyError(
      "ERR_INVALID_LOCALIZED_TEXT",
      `${label} must be a string or { ko, en } object.`
    );
  }
  assertNoForbiddenKeys(value, label);
  const hasKo = typeof value.ko === "string" && value.ko.length > 0;
  const hasEn = typeof value.en === "string" && value.en.length > 0;
  if (!hasKo && !hasEn) {
    throw new SecurityPolicyError(
      "ERR_EMPTY_LOCALIZED_TEXT",
      `${label} must provide at least one non-empty "ko" or "en" string.`
    );
  }
  const normalized = /* @__PURE__ */ Object.create(null);
  if (hasKo) {
    normalized.ko = assertSafeText(value.ko, `${label}.ko`);
  }
  if (hasEn) {
    normalized.en = assertSafeText(value.en, `${label}.en`);
  }
  return Object.freeze(normalized);
}
function resolveLocalizedText(value, locale = "ko") {
  if (typeof value === "string") {
    return value;
  }
  if (!value || typeof value !== "object") {
    return "";
  }
  if (locale === "en") {
    return typeof value.en === "string" ? value.en : typeof value.ko === "string" ? value.ko : "";
  }
  return typeof value.ko === "string" ? value.ko : typeof value.en === "string" ? value.en : "";
}
function validateRemotePlugin(plugin) {
  if (!plugin || typeof plugin !== "object" || Array.isArray(plugin)) {
    throw new SecurityPolicyError("ERR_INVALID_PLUGIN", "RemotePlugin.v1 descriptor must be an object.");
  }
  assertNoForbiddenKeys(plugin, "plugin");
  if (plugin.contractVersion !== REMOTE_PLUGIN_CONTRACT_VERSION) {
    throw new SecurityPolicyError(
      "ERR_UNSUPPORTED_CONTRACT_VERSION",
      `Plugin contractVersion must be "${REMOTE_PLUGIN_CONTRACT_VERSION}".`
    );
  }
  if (typeof plugin.mount === "function") {
    throw new SecurityPolicyError(
      "ERR_IMPERATIVE_MOUNT_FORBIDDEN",
      "RemotePlugin.v1 plugins must be declarative-only and cannot define imperative mount()."
    );
  }
  if (typeof plugin.id !== "string" || !PLUGIN_ID_RE.test(plugin.id) || FORBIDDEN_KEYS.has(plugin.id)) {
    throw new SecurityPolicyError("ERR_INVALID_PLUGIN_ID", "Invalid RemotePlugin.v1 id.");
  }
  if (typeof plugin.version !== "string" || !SEMVER_RE.test(plugin.version)) {
    throw new SecurityPolicyError("ERR_INVALID_PLUGIN_VERSION", "Plugin version must be valid SemVer.");
  }
  const displayName = assertSafeLocalizedText(plugin.displayName, "plugin.displayName");
  if (!isPlainObject(plugin.uiSlot)) {
    throw new SecurityPolicyError("ERR_INVALID_UI_SLOT", "Plugin must declare a uiSlot object.");
  }
  assertNoForbiddenKeys(plugin.uiSlot, "plugin.uiSlot");
  if (typeof plugin.uiSlot.slot !== "string" || !ALLOWED_SLOT_SET.has(plugin.uiSlot.slot)) {
    throw new SecurityPolicyError(
      "ERR_UNSUPPORTED_UI_SLOT",
      `Unsupported uiSlot.slot "${String(plugin.uiSlot.slot)}".`
    );
  }
  if (typeof plugin.uiSlot.slotId !== "string" || !SLOT_ID_RE.test(plugin.uiSlot.slotId) || FORBIDDEN_KEYS.has(plugin.uiSlot.slotId)) {
    throw new SecurityPolicyError("ERR_INVALID_SLOT_ID", "Invalid uiSlot.slotId.");
  }
  if (plugin.uiSlot.exclusive !== void 0 && typeof plugin.uiSlot.exclusive !== "boolean") {
    throw new SecurityPolicyError(
      "ERR_INVALID_EXCLUSIVE_FLAG",
      "uiSlot.exclusive must be a boolean when provided."
    );
  }
  const exclusive = plugin.uiSlot.exclusive === true;
  if (!Array.isArray(plugin.capabilities) || plugin.capabilities.length === 0) {
    throw new SecurityPolicyError(
      "ERR_INVALID_CAPABILITIES",
      "Plugin must declare at least one capability."
    );
  }
  const capabilities = [];
  const seenCaps = /* @__PURE__ */ new Set();
  for (const cap of plugin.capabilities) {
    if (typeof cap !== "string" || !ALLOWED_CAPABILITY_SET.has(cap)) {
      throw new SecurityPolicyError(
        "ERR_UNSUPPORTED_CAPABILITY",
        `Unsupported capability "${String(cap)}".`
      );
    }
    if (!seenCaps.has(cap)) {
      seenCaps.add(cap);
      capabilities.push(cap);
    }
  }
  if (typeof plugin.getSnapshot !== "function") {
    throw new SecurityPolicyError(
      "ERR_MISSING_GET_SNAPSHOT",
      "RemotePlugin.v1 requires a getSnapshot(ctx) method."
    );
  }
  if (seenCaps.has("actions") && typeof plugin.invoke !== "function") {
    throw new SecurityPolicyError(
      "ERR_MISSING_INVOKE",
      'Plugin declaring "actions" capability must implement invoke(actionId, invocation, ctx).'
    );
  }
  if (seenCaps.has("subscribe") && typeof plugin.subscribe !== "function") {
    throw new SecurityPolicyError(
      "ERR_MISSING_SUBSCRIBE",
      'Plugin declaring "subscribe" capability must implement subscribe(onDirty, ctx).'
    );
  }
  let loadOrder = 100;
  if (plugin.loadOrder !== void 0) {
    if (!Number.isInteger(plugin.loadOrder) || plugin.loadOrder < 0 || plugin.loadOrder > 1e3) {
      throw new SecurityPolicyError(
        "ERR_INVALID_LOAD_ORDER",
        "Plugin loadOrder must be an integer between 0 and 1000."
      );
    }
    loadOrder = plugin.loadOrder;
  }
  return Object.freeze({
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    id: plugin.id,
    version: plugin.version,
    displayName,
    uiSlot: Object.freeze({
      slot: plugin.uiSlot.slot,
      slotId: plugin.uiSlot.slotId,
      exclusive
    }),
    capabilities: Object.freeze(capabilities),
    loadOrder,
    getSnapshot: plugin.getSnapshot.bind(plugin),
    invoke: typeof plugin.invoke === "function" ? plugin.invoke.bind(plugin) : null,
    subscribe: typeof plugin.subscribe === "function" ? plugin.subscribe.bind(plugin) : null,
    dispose: typeof plugin.dispose === "function" ? plugin.dispose.bind(plugin) : null
  });
}
function validateTone(tone, fallback = "neutral") {
  if (tone === void 0) {
    return fallback;
  }
  if (typeof tone !== "string" || !ALLOWED_TONES.has(tone)) {
    throw new SecurityPolicyError("ERR_INVALID_TONE", `Invalid tone "${String(tone)}".`);
  }
  return tone;
}
function validateSection(section, index) {
  const label = `snapshot.sections[${index}]`;
  if (!isPlainObject(section)) {
    throw new SecurityPolicyError("ERR_INVALID_SECTION", `${label} must be a plain object.`);
  }
  assertNoForbiddenKeys(section, label);
  if (section.kind === "notice") {
    return Object.freeze({
      kind: "notice",
      text: assertSafeLocalizedText(section.text, `${label}.text`),
      tone: validateTone(section.tone, "info")
    });
  }
  if (section.kind === "metrics") {
    if (!Array.isArray(section.items) || section.items.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError("ERR_INVALID_SECTION_ITEMS", `${label}.items must be a bounded array.`);
    }
    const items = section.items.map((item, i) => {
      if (!isPlainObject(item)) {
        throw new SecurityPolicyError("ERR_INVALID_METRIC", `${label}.items[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(item, `${label}.items[${i}]`);
      return Object.freeze({
        label: assertSafeLocalizedText(item.label, `${label}.items[${i}].label`),
        value: assertSafeText(String(item.value ?? ""), `${label}.items[${i}].value`, { maxLength: 160 }),
        tone: validateTone(item.tone, "neutral")
      });
    });
    return Object.freeze({ kind: "metrics", items: Object.freeze(items) });
  }
  if (section.kind === "list") {
    if (!Array.isArray(section.items) || section.items.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError("ERR_INVALID_SECTION_ITEMS", `${label}.items must be a bounded array.`);
    }
    const title = section.title !== void 0 ? assertSafeLocalizedText(section.title, `${label}.title`) : null;
    const items = section.items.map((item, i) => {
      if (!isPlainObject(item)) {
        throw new SecurityPolicyError("ERR_INVALID_LIST_ITEM", `${label}.items[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(item, `${label}.items[${i}]`);
      return Object.freeze({
        id: assertSafeText(String(item.id ?? i), `${label}.items[${i}].id`, { maxLength: 128 }),
        primary: assertSafeLocalizedText(item.primary, `${label}.items[${i}].primary`),
        secondary: item.secondary !== void 0 ? assertSafeLocalizedText(item.secondary, `${label}.items[${i}].secondary`) : null,
        badge: item.badge !== void 0 ? assertSafeLocalizedText(item.badge, `${label}.items[${i}].badge`) : null
      });
    });
    return Object.freeze({ kind: "list", title, items: Object.freeze(items) });
  }
  if (section.kind === "key-value") {
    if (!Array.isArray(section.entries) || section.entries.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError("ERR_INVALID_SECTION_ITEMS", `${label}.entries must be a bounded array.`);
    }
    const title = section.title !== void 0 ? assertSafeLocalizedText(section.title, `${label}.title`) : null;
    const entries = section.entries.map((entry, i) => {
      if (!isPlainObject(entry)) {
        throw new SecurityPolicyError("ERR_INVALID_ENTRY", `${label}.entries[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(entry, `${label}.entries[${i}]`);
      return Object.freeze({
        key: assertSafeLocalizedText(entry.key, `${label}.entries[${i}].key`),
        value: assertSafeText(String(entry.value ?? ""), `${label}.entries[${i}].value`, { maxLength: 240 })
      });
    });
    return Object.freeze({ kind: "key-value", title, entries: Object.freeze(entries) });
  }
  if (section.kind === "actions") {
    if (!Array.isArray(section.items) || section.items.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError("ERR_INVALID_SECTION_ITEMS", `${label}.items must be a bounded array.`);
    }
    const title = section.title !== void 0 ? assertSafeLocalizedText(section.title, `${label}.title`) : null;
    const items = section.items.map((item, i) => {
      if (!isPlainObject(item)) {
        throw new SecurityPolicyError("ERR_INVALID_ACTION_ITEM", `${label}.items[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(item, `${label}.items[${i}]`);
      if (typeof item.id !== "string" || !ACTION_ID_RE.test(item.id)) {
        throw new SecurityPolicyError("ERR_INVALID_ACTION_ID", `Invalid action id in ${label}.items[${i}].`);
      }
      const style = item.style === void 0 ? "secondary" : item.style;
      if (typeof style !== "string" || !ALLOWED_BUTTON_STYLES.has(style)) {
        throw new SecurityPolicyError("ERR_INVALID_BUTTON_STYLE", `Invalid action style "${String(style)}".`);
      }
      return Object.freeze({
        id: item.id,
        label: assertSafeLocalizedText(item.label, `${label}.items[${i}].label`),
        style,
        disabled: Boolean(item.disabled)
      });
    });
    return Object.freeze({ kind: "actions", title, items: Object.freeze(items) });
  }
  throw new SecurityPolicyError(
    "ERR_UNSUPPORTED_SECTION_KIND",
    `Unsupported declarative section kind "${String(section.kind)}".`
  );
}
function validatePluginSnapshot(snapshot) {
  if (!isPlainObject(snapshot)) {
    throw new SecurityPolicyError("ERR_INVALID_SNAPSHOT", "Plugin snapshot must be a plain object.");
  }
  assertNoForbiddenKeys(snapshot, "snapshot");
  const revision = snapshot.revision !== void 0 && snapshot.revision !== null ? assertSafeText(String(snapshot.revision), "snapshot.revision", { maxLength: 128 }) : null;
  let badge = null;
  if (snapshot.badge !== void 0 && snapshot.badge !== null) {
    if (!isPlainObject(snapshot.badge)) {
      throw new SecurityPolicyError("ERR_INVALID_BADGE", "snapshot.badge must be a plain object.");
    }
    assertNoForbiddenKeys(snapshot.badge, "snapshot.badge");
    badge = Object.freeze({
      text: assertSafeLocalizedText(snapshot.badge.text, "snapshot.badge.text"),
      tone: validateTone(snapshot.badge.tone, "neutral")
    });
  }
  let notice = null;
  if (snapshot.notice !== void 0 && snapshot.notice !== null) {
    if (!isPlainObject(snapshot.notice)) {
      throw new SecurityPolicyError("ERR_INVALID_NOTICE", "snapshot.notice must be a plain object.");
    }
    assertNoForbiddenKeys(snapshot.notice, "snapshot.notice");
    notice = Object.freeze({
      text: assertSafeLocalizedText(snapshot.notice.text, "snapshot.notice.text"),
      tone: validateTone(snapshot.notice.tone, "info")
    });
  }
  const rawSections = snapshot.sections === void 0 ? [] : snapshot.sections;
  if (!Array.isArray(rawSections) || rawSections.length > MAX_SECTIONS) {
    throw new SecurityPolicyError(
      "ERR_INVALID_SECTIONS",
      `snapshot.sections must be an array with at most ${MAX_SECTIONS} items.`
    );
  }
  const sections = Object.freeze(rawSections.map((sec, idx) => validateSection(sec, idx)));
  return Object.freeze({
    revision,
    badge,
    notice,
    sections
  });
}
function validateActionInvocation(actionId, invocation = {}) {
  if (typeof actionId !== "string" || !ACTION_ID_RE.test(actionId)) {
    throw new SecurityPolicyError("ERR_INVALID_ACTION_ID", "Invalid actionId.");
  }
  if (!isPlainObject(invocation)) {
    throw new SecurityPolicyError("ERR_INVALID_INVOCATION", "Action invocation must be a plain object.");
  }
  assertNoForbiddenKeys(invocation, "invocation");
  const clean = /* @__PURE__ */ Object.create(null);
  if (invocation.expectedRevision !== void 0 && invocation.expectedRevision !== null) {
    clean.expectedRevision = assertSafeText(String(invocation.expectedRevision), "invocation.expectedRevision", {
      maxLength: 128
    });
  }
  if (invocation.params !== void 0 && invocation.params !== null) {
    if (!isPlainObject(invocation.params)) {
      throw new SecurityPolicyError("ERR_INVALID_PARAMS", "invocation.params must be a plain object.");
    }
    assertNoForbiddenKeys(invocation.params, "invocation.params");
    const safeParams = /* @__PURE__ */ Object.create(null);
    for (const [k, v] of Object.entries(invocation.params)) {
      if (typeof v === "string") {
        safeParams[k] = assertSafeText(v, `invocation.params.${k}`);
      } else if (typeof v === "number" && Number.isFinite(v)) {
        safeParams[k] = v;
      } else if (typeof v === "boolean") {
        safeParams[k] = v;
      } else {
        throw new SecurityPolicyError(
          "ERR_INVALID_PARAM_VALUE",
          `invocation.params.${k} must be a primitive string, finite number, or boolean.`
        );
      }
    }
    clean.params = Object.freeze(safeParams);
  }
  if (invocation.challengeResponse !== void 0 && invocation.challengeResponse !== null) {
    if (!isPlainObject(invocation.challengeResponse)) {
      throw new SecurityPolicyError(
        "ERR_INVALID_CHALLENGE_RESPONSE",
        "invocation.challengeResponse must be a plain object."
      );
    }
    assertNoForbiddenKeys(invocation.challengeResponse, "invocation.challengeResponse");
    const challengeId = assertSafeText(
      String(invocation.challengeResponse.challengeId ?? ""),
      "invocation.challengeResponse.challengeId",
      { maxLength: 128 }
    );
    if (!challengeId) {
      throw new SecurityPolicyError("ERR_INVALID_CHALLENGE_ID", "challengeId must be non-empty.");
    }
    if (typeof invocation.challengeResponse.confirmed !== "boolean") {
      throw new SecurityPolicyError(
        "ERR_INVALID_CHALLENGE_CONFIRMED",
        "challengeResponse.confirmed must be a boolean."
      );
    }
    clean.challengeResponse = Object.freeze({
      challengeId,
      confirmed: invocation.challengeResponse.confirmed
    });
  }
  return Object.freeze(clean);
}
function redactLocalizedMessage(value, label) {
  const validated = assertSafeLocalizedText(value, label);
  if (typeof validated === "string") {
    return redactUrl(validated);
  }
  const out = /* @__PURE__ */ Object.create(null);
  if (validated.ko) {
    out.ko = redactUrl(validated.ko);
  }
  if (validated.en) {
    out.en = redactUrl(validated.en);
  }
  return Object.freeze(out);
}
function validateActionResult(result) {
  if (!isPlainObject(result)) {
    throw new SecurityPolicyError("ERR_INVALID_ACTION_RESULT", "ActionResult.v1 must be a plain object.");
  }
  assertNoForbiddenKeys(result, "actionResult");
  if (typeof result.status !== "string" || !ALLOWED_ACTION_STATUSES.has(result.status)) {
    throw new SecurityPolicyError(
      "ERR_INVALID_ACTION_STATUS",
      `Invalid ActionResult status "${String(result.status)}".`
    );
  }
  if (result.status === "confirmation_required") {
    const challengeId = assertSafeText(String(result.challengeId ?? ""), "actionResult.challengeId", {
      maxLength: 128
    });
    if (!challengeId) {
      throw new SecurityPolicyError(
        "ERR_MISSING_CHALLENGE_ID",
        "confirmation_required result must include a non-empty challengeId."
      );
    }
    const message2 = redactLocalizedMessage(result.message, "actionResult.message");
    const confirmLabel = result.confirmLabel !== void 0 ? assertSafeLocalizedText(result.confirmLabel, "actionResult.confirmLabel") : null;
    return Object.freeze({
      status: "confirmation_required",
      challengeId,
      message: message2,
      confirmLabel
    });
  }
  if (result.status === "conflict") {
    const message2 = redactLocalizedMessage(
      result.message ?? { ko: "\uC0C1\uD0DC\uAC00 \uBCC0\uACBD\uB418\uC5C8\uC2B5\uB2C8\uB2E4. \uC0C8\uB85C\uACE0\uCE68 \uD6C4 \uB2E4\uC2DC \uC2DC\uB3C4\uD558\uC138\uC694.", en: "State changed. Refresh and retry." },
      "actionResult.message"
    );
    const currentRevision = result.currentRevision !== void 0 && result.currentRevision !== null ? assertSafeText(String(result.currentRevision), "actionResult.currentRevision", { maxLength: 128 }) : null;
    return Object.freeze({
      status: "conflict",
      message: message2,
      currentRevision
    });
  }
  if (result.status === "error") {
    const message2 = redactLocalizedMessage(
      result.message ?? { ko: "\uC791\uC5C5\uC744 \uC644\uB8CC\uD558\uC9C0 \uBABB\uD588\uC2B5\uB2C8\uB2E4.", en: "Action failed." },
      "actionResult.message"
    );
    return Object.freeze({
      status: "error",
      message: message2
    });
  }
  const message = result.message !== void 0 && result.message !== null ? redactLocalizedMessage(result.message, "actionResult.message") : null;
  const revision = result.revision !== void 0 && result.revision !== null ? assertSafeText(String(result.revision), "actionResult.revision", { maxLength: 128 }) : null;
  return Object.freeze({
    status: "ok",
    message,
    revision
  });
}

// src/core/remote-plugin-registry.js
var hasOwn = Object.hasOwn ? Object.hasOwn : (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
var RemotePluginRegistry = class {
  #plugins = /* @__PURE__ */ Object.create(null);
  #exclusiveSlotOwners = /* @__PURE__ */ Object.create(null);
  #slotIds = /* @__PURE__ */ Object.create(null);
  #unsubscribers = /* @__PURE__ */ Object.create(null);
  #listeners = /* @__PURE__ */ new Set();
  #diagnostics;
  #disposed = false;
  constructor({ diagnostics = new DiagnosticsBus() } = {}) {
    this.#diagnostics = diagnostics;
  }
  get diagnostics() {
    return this.#diagnostics;
  }
  register(rawPlugin, { locale = "ko" } = {}) {
    if (this.#disposed) {
      throw new SecurityPolicyError("ERR_REGISTRY_DISPOSED", "Cannot register plugin on a disposed registry.");
    }
    const plugin = validateRemotePlugin(rawPlugin);
    if (hasOwn(this.#plugins, plugin.id)) {
      throw new SecurityPolicyError(
        "ERR_DUPLICATE_PLUGIN_ID",
        `Remote plugin "${plugin.id}" is already registered.`
      );
    }
    if (hasOwn(this.#slotIds, plugin.uiSlot.slotId)) {
      throw new SecurityPolicyError(
        "ERR_DUPLICATE_SLOT_ID",
        `UI slotId "${plugin.uiSlot.slotId}" is already claimed by "${this.#slotIds[plugin.uiSlot.slotId]}".`
      );
    }
    if (plugin.uiSlot.exclusive && hasOwn(this.#exclusiveSlotOwners, plugin.uiSlot.slot)) {
      throw new SecurityPolicyError(
        "ERR_EXCLUSIVE_SLOT_CONFLICT",
        `Exclusive slot "${plugin.uiSlot.slot}" is already owned by "${this.#exclusiveSlotOwners[plugin.uiSlot.slot]}".`
      );
    }
    if (!plugin.uiSlot.exclusive && hasOwn(this.#exclusiveSlotOwners, plugin.uiSlot.slot)) {
      throw new SecurityPolicyError(
        "ERR_EXCLUSIVE_SLOT_CONFLICT",
        `Slot "${plugin.uiSlot.slot}" is exclusively owned by "${this.#exclusiveSlotOwners[plugin.uiSlot.slot]}".`
      );
    }
    if (plugin.uiSlot.exclusive) {
      for (const existingId of Object.keys(this.#plugins)) {
        if (this.#plugins[existingId].uiSlot.slot === plugin.uiSlot.slot) {
          throw new SecurityPolicyError(
            "ERR_EXCLUSIVE_SLOT_CONFLICT",
            `Cannot claim exclusive slot "${plugin.uiSlot.slot}" while "${existingId}" is registered in it.`
          );
        }
      }
    }
    this.#plugins[plugin.id] = plugin;
    this.#slotIds[plugin.uiSlot.slotId] = plugin.id;
    if (plugin.uiSlot.exclusive) {
      this.#exclusiveSlotOwners[plugin.uiSlot.slot] = plugin.id;
    }
    if (plugin.capabilities.includes("subscribe") && typeof plugin.subscribe === "function") {
      try {
        const unsub = plugin.subscribe(
          () => {
            if (!this.#disposed && hasOwn(this.#plugins, plugin.id)) {
              this.#emitChange({ type: "dirty", pluginId: plugin.id });
            }
          },
          { locale }
        );
        if (typeof unsub === "function") {
          this.#unsubscribers[plugin.id] = unsub;
        }
      } catch (err) {
        this.#diagnostics.emit({
          level: "error",
          code: "PLUGIN_SUBSCRIBE_FAILED",
          source: "core.remote-plugin-registry",
          message: `Plugin "${plugin.id}" subscribe() threw`,
          detail: err
        });
      }
    }
    this.#emitChange({ type: "registered", pluginId: plugin.id });
    let active = true;
    return () => {
      if (!active) {
        return;
      }
      active = false;
      this.unregister(plugin.id);
    };
  }
  unregister(pluginId) {
    if (typeof pluginId !== "string" || !hasOwn(this.#plugins, pluginId)) {
      return false;
    }
    const plugin = this.#plugins[pluginId];
    delete this.#plugins[pluginId];
    if (hasOwn(this.#slotIds, plugin.uiSlot.slotId) && this.#slotIds[plugin.uiSlot.slotId] === pluginId) {
      delete this.#slotIds[plugin.uiSlot.slotId];
    }
    if (hasOwn(this.#exclusiveSlotOwners, plugin.uiSlot.slot) && this.#exclusiveSlotOwners[plugin.uiSlot.slot] === pluginId) {
      delete this.#exclusiveSlotOwners[plugin.uiSlot.slot];
    }
    if (hasOwn(this.#unsubscribers, pluginId)) {
      const unsub = this.#unsubscribers[pluginId];
      delete this.#unsubscribers[pluginId];
      try {
        unsub();
      } catch (err) {
        this.#diagnostics.emit({
          level: "error",
          code: "PLUGIN_UNSUBSCRIBE_FAILED",
          source: "core.remote-plugin-registry",
          message: `Plugin "${pluginId}" unsubscribe failed`,
          detail: err
        });
      }
    }
    if (typeof plugin.dispose === "function") {
      try {
        plugin.dispose();
      } catch (err) {
        this.#diagnostics.emit({
          level: "error",
          code: "PLUGIN_DISPOSE_FAILED",
          source: "core.remote-plugin-registry",
          message: `Plugin "${pluginId}" dispose() threw`,
          detail: err
        });
      }
    }
    this.#emitChange({ type: "unregistered", pluginId });
    return true;
  }
  get(pluginId) {
    if (typeof pluginId !== "string" || !hasOwn(this.#plugins, pluginId)) {
      return null;
    }
    return this.#plugins[pluginId];
  }
  list() {
    return Object.keys(this.#plugins).map((id) => this.#plugins[id]).sort((a, b) => {
      if (a.loadOrder !== b.loadOrder) {
        return a.loadOrder - b.loadOrder;
      }
      return a.id.localeCompare(b.id);
    });
  }
  listBySlot(slot) {
    return this.list().filter((plugin) => plugin.uiSlot.slot === slot);
  }
  async readSnapshot(pluginId, ctx = { locale: "ko" }) {
    const plugin = this.get(pluginId);
    if (!plugin) {
      return Object.freeze({ ok: false, error: "Plugin not registered." });
    }
    try {
      const raw = await plugin.getSnapshot({ locale: ctx?.locale === "en" ? "en" : "ko" });
      const snapshot = validatePluginSnapshot(raw);
      return Object.freeze({ ok: true, snapshot });
    } catch (err) {
      const redacted = redactSecrets(err);
      this.#diagnostics.emit({
        level: "error",
        code: "PLUGIN_SNAPSHOT_FAILED",
        source: "core.remote-plugin-registry",
        message: `Plugin "${pluginId}" snapshot failed`,
        detail: err
      });
      return Object.freeze({
        ok: false,
        error: typeof redacted?.message === "string" && redacted.message ? redacted.message : "Snapshot failed."
      });
    }
  }
  async invokeAction(pluginId, actionId, invocation = {}, ctx = { locale: "ko" }) {
    const plugin = this.get(pluginId);
    if (!plugin) {
      return validateActionResult({
        status: "error",
        message: { ko: "\uB4F1\uB85D\uB418\uC9C0 \uC54A\uC740 \uD50C\uB7EC\uADF8\uC778\uC785\uB2C8\uB2E4.", en: "Plugin is not registered." }
      });
    }
    if (!plugin.capabilities.includes("actions") || typeof plugin.invoke !== "function") {
      return validateActionResult({
        status: "error",
        message: { ko: "\uC561\uC158\uC744 \uC9C0\uC6D0\uD558\uC9C0 \uC54A\uB294 \uD50C\uB7EC\uADF8\uC778\uC785\uB2C8\uB2E4.", en: "Plugin does not support actions." }
      });
    }
    let safeInvocation;
    try {
      safeInvocation = validateActionInvocation(actionId, invocation);
    } catch (err) {
      const redacted = redactSecrets(err);
      return validateActionResult({
        status: "error",
        message: redacted?.message || "Invalid action invocation."
      });
    }
    try {
      const rawResult = await plugin.invoke(actionId, safeInvocation, {
        locale: ctx?.locale === "en" ? "en" : "ko"
      });
      return validateActionResult(rawResult);
    } catch (err) {
      const redacted = redactSecrets(err);
      this.#diagnostics.emit({
        level: "error",
        code: "PLUGIN_INVOKE_FAILED",
        source: "core.remote-plugin-registry",
        message: `Plugin "${pluginId}" invoke("${actionId}") failed`,
        detail: err
      });
      return validateActionResult({
        status: "error",
        message: redacted?.message || "Plugin action failed."
      });
    }
  }
  onChange(listener) {
    if (typeof listener !== "function") {
      throw new TypeError("Registry onChange listener must be a function.");
    }
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }
  #emitChange(event) {
    for (const listener of [...this.#listeners]) {
      try {
        listener(event);
      } catch (err) {
        this.#diagnostics.emit({
          level: "error",
          code: "REGISTRY_LISTENER_FAILED",
          source: "core.remote-plugin-registry",
          message: "Registry change listener threw",
          detail: err
        });
      }
    }
  }
  dispose() {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    for (const id of Object.keys(this.#plugins).reverse()) {
      this.unregister(id);
    }
    this.#listeners.clear();
  }
};

// src/core/declarative-slot-renderer.js
var HOST_STYLE_ID = "remote-slot-host-css";
var HOST_SLOT_ID = "remote-slot-host.root";
var hasOwn2 = Object.hasOwn ? Object.hasOwn : (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
var SLOT_LABELS = Object.freeze({
  "title-bar": Object.freeze({ ko: "\uC0C1\uB2E8 \uD0C0\uC774\uD2C0 \uBC14", en: "Title Bar" }),
  "status-bar": Object.freeze({ ko: "\uC0C1\uD0DC \uD45C\uC2DC\uC904", en: "Status Bar" }),
  "composer-toolbar": Object.freeze({ ko: "\uC785\uB825 \uD234\uBC14", en: "Composer Toolbar" }),
  sidebar: Object.freeze({ ko: "\uC0AC\uC774\uB4DC\uBC14", en: "Sidebar" }),
  "settings-pane": Object.freeze({ ko: "\uC124\uC815 \uD328\uB110", en: "Settings Pane" }),
  "aux-pane": Object.freeze({ ko: "\uBCF4\uC870 \uD328\uB110", en: "Aux Pane" }),
  overlay: Object.freeze({ ko: "\uC624\uBC84\uB808\uC774", en: "Overlay" }),
  modal: Object.freeze({ ko: "\uBAA8\uB2EC", en: "Modal" }),
  theme: Object.freeze({ ko: "\uD14C\uB9C8", en: "Theme" }),
  custom: Object.freeze({ ko: "\uC0AC\uC6A9\uC790 \uC9C0\uC815", en: "Custom" })
});
var STRINGS = Object.freeze({
  ko: Object.freeze({
    title: "\uC6D0\uACA9 \uD50C\uB7EC\uADF8\uC778 \uD638\uC2A4\uD2B8",
    pillLabel: "\uC6D0\uACA9 \uD50C\uB7EC\uADF8\uC778 \uBA54\uB274 \uC5F4\uAE30",
    pillText: "\uD50C\uB7EC\uADF8\uC778",
    close: "\uB2EB\uAE30",
    refresh: "\uC0C8\uB85C\uACE0\uCE68",
    empty: "\uC5F0\uB3D9\uB41C RemotePlugin.v1 \uD50C\uB7EC\uADF8\uC778\uC774 \uC5C6\uC2B5\uB2C8\uB2E4. \uAC01 \uD50C\uB7EC\uADF8\uC778\uC774 \uD45C\uC900 \uC778\uD130\uD398\uC774\uC2A4\uB97C \uAD6C\uD604\uD574 \uB4F1\uB85D\uD558\uBA74 \uC9C0\uC815\uB41C UI \uC704\uCE58\uC5D0 \uD45C\uC2DC\uB429\uB2C8\uB2E4.",
    confirmTitle: "\uC791\uC5C5 \uD655\uC778 \uD544\uC694",
    confirmButton: "\uD655\uC778 \uD6C4 \uC2E4\uD589",
    cancelButton: "\uCDE8\uC18C",
    conflictRefresh: "\uB2E4\uC2DC \uBD88\uB7EC\uC624\uAE30",
    langToggle: "EN",
    langAria: "\uC601\uC5B4\uB85C \uC804\uD658",
    snapshotError: "\uC2A4\uB0C5\uC0F7 \uB85C\uB4DC \uC624\uB958",
    actionOk: "\uC791\uC5C5\uC774 \uC644\uB8CC\uB418\uC5C8\uC2B5\uB2C8\uB2E4."
  }),
  en: Object.freeze({
    title: "Remote Plugin Host",
    pillLabel: "Open Remote Plugins menu",
    pillText: "Plugins",
    close: "Close",
    refresh: "Refresh",
    empty: "No RemotePlugin.v1 plugins registered yet. Plugins implementing the standard interface appear in their declared UI slots.",
    confirmTitle: "Confirmation Required",
    confirmButton: "Confirm",
    cancelButton: "Cancel",
    conflictRefresh: "Reload",
    langToggle: "KO",
    langAria: "Switch to Korean",
    snapshotError: "Snapshot error",
    actionOk: "Action completed."
  })
});
var ACTION_OK_LOCALIZED = Object.freeze({
  ko: STRINGS.ko.actionOk,
  en: STRINGS.en.actionOk
});
var HOST_CSS = [
  `:host, .rph-root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; color-scheme: light dark; box-sizing: border-box; }`,
  `.rph-root * { box-sizing: border-box; }`,
  `.rph-titlebar { position: fixed; top: max(8px, env(safe-area-inset-top)); left: 50%; transform: translateX(-50%); max-width: calc(100vw - 24px); z-index: 2147482990; display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 10px; border-radius: 12px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); box-shadow: 0 6px 20px rgba(0,0,0,0.24); }`,
  `.rph-statusbar { position: fixed; left: max(10px, env(safe-area-inset-left)); bottom: max(12px, env(safe-area-inset-bottom)); max-width: calc(100vw - 132px); z-index: 2147482990; display: flex; flex-wrap: wrap; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 12px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); box-shadow: 0 6px 20px rgba(0,0,0,0.24); }`,
  `.rph-composerbar { position: fixed; left: max(10px, env(safe-area-inset-left)); bottom: max(68px, calc(env(safe-area-inset-bottom) + 58px)); max-width: calc(100vw - 24px); z-index: 2147482990; display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 10px; border-radius: 12px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); box-shadow: 0 6px 20px rgba(0,0,0,0.24); }`,
  `.rph-dock { position: fixed; right: max(10px, env(safe-area-inset-right)); bottom: max(12px, env(safe-area-inset-bottom)); z-index: 2147483000; display: flex; flex-direction: column; align-items: flex-end; gap: 8px; }`,
  `.rph-pill { min-width: 44px; min-height: 44px; padding: 0 14px; border-radius: 999px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); font-size: 13px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 6px 20px rgba(0,0,0,0.28); touch-action: manipulation; }`,
  `.rph-badge-count { min-width: 20px; height: 20px; padding: 0 6px; border-radius: 999px; background: #1a73e8; color: #ffffff; font-size: 11px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; }`,
  `.rph-drawer { width: min(360px, calc(100vw - 20px)); max-height: calc(100vh - 96px); max-height: calc(100dvh - 96px); overflow-y: auto; border-radius: 14px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); padding: 14px; box-shadow: 0 12px 32px rgba(0,0,0,0.38); display: flex; flex-direction: column; gap: 10px; }`,
  `.rph-drawer[hidden], .rph-titlebar[hidden], .rph-statusbar[hidden], .rph-composerbar[hidden], .rph-confirm[hidden] { display: none; }`,
  `.rph-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; }`,
  `.rph-title { margin: 0; font-size: 14px; font-weight: 700; }`,
  `.rph-header-actions { display: inline-flex; align-items: center; gap: 6px; }`,
  `.rph-btn { min-width: 44px; min-height: 44px; padding: 8px 12px; border-radius: 10px; border: 1px solid rgba(128,134,139,0.35); background: rgba(128,134,139,0.14); color: inherit; font-size: 13px; font-weight: 600; cursor: pointer; touch-action: manipulation; }`,
  `.rph-btn[data-style="primary"] { background: #1a73e8; border-color: #1a73e8; color: #ffffff; }`,
  `.rph-btn[data-style="danger"] { background: #d93025; border-color: #d93025; color: #ffffff; }`,
  `.rph-btn:disabled { opacity: 0.5; cursor: not-allowed; }`,
  `.rph-btn:focus-visible, .rph-pill:focus-visible { outline: 2px solid #4d90fe; outline-offset: 2px; }`,
  `.rph-slot-group { border-radius: 10px; border: 1px solid rgba(128,134,139,0.24); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `.rph-slot-heading { font-size: 11px; font-weight: 700; text-transform: uppercase; opacity: 0.72; letter-spacing: 0.03em; }`,
  `.rph-plugin-card { border-radius: 8px; border: 1px solid rgba(128,134,139,0.2); padding: 8px; display: flex; flex-direction: column; gap: 8px; }`,
  `.rph-plugin-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }`,
  `.rph-plugin-name { font-size: 13px; font-weight: 700; }`,
  `.rph-chip { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: rgba(128,134,139,0.18); }`,
  `.rph-chip[data-tone="ok"] { background: rgba(52,168,83,0.22); color: #34a853; }`,
  `.rph-chip[data-tone="warn"] { background: rgba(251,188,4,0.22); color: #f29900; }`,
  `.rph-chip[data-tone="error"] { background: rgba(234,67,53,0.22); color: #ea4335; }`,
  `.rph-metrics { display: flex; flex-wrap: wrap; gap: 8px; }`,
  `.rph-metric { display: inline-flex; align-items: baseline; gap: 5px; font-size: 12px; padding: 4px 8px; border-radius: 8px; background: rgba(128,134,139,0.12); }`,
  `.rph-metric-val { font-weight: 700; }`,
  `.rph-list { display: flex; flex-direction: column; gap: 6px; margin: 0; padding: 0; list-style: none; }`,
  `.rph-list-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 8px; border-radius: 8px; background: rgba(128,134,139,0.1); font-size: 12px; }`,
  `.rph-kv { display: flex; flex-direction: column; gap: 4px; font-size: 12px; }`,
  `.rph-kv-row { display: flex; justify-content: space-between; gap: 8px; word-break: break-word; }`,
  `.rph-actions { display: flex; flex-wrap: wrap; gap: 6px; }`,
  `.rph-notice { font-size: 12px; padding: 8px; border-radius: 8px; background: rgba(128,134,139,0.14); word-break: break-word; }`,
  `.rph-notice[data-tone="error"] { background: rgba(234,67,53,0.18); }`,
  `.rph-notice[data-tone="warn"] { background: rgba(251,188,4,0.18); }`,
  `.rph-confirm { border-radius: 10px; border: 1px solid #f29900; background: rgba(251,188,4,0.12); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `.rph-status-inline { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; flex-wrap: wrap; }`,
  `@media (prefers-color-scheme: light) { .rph-titlebar, .rph-statusbar, .rph-composerbar, .rph-pill, .rph-drawer { background: var(--card, #ffffff); color: var(--foreground, #1f2328); } }`
].join(" ");
function clearChildren(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}
function createDeclarativeSlotRenderer({
  win,
  doc,
  surface,
  registry,
  initialLocale = "ko"
}) {
  validateHostSurfacePort(surface);
  if (!doc || typeof doc.createElement !== "function") {
    throw new TypeError("DeclarativeSlotRenderer requires a DOM document.");
  }
  if (!registry || typeof registry.list !== "function") {
    throw new TypeError("DeclarativeSlotRenderer requires a RemotePluginRegistry.");
  }
  let locale = initialLocale === "en" ? "en" : "ko";
  let isOpen = false;
  let disposed = false;
  let renderSeq = 0;
  let actionGeneration = 0;
  let pendingChallenge = null;
  const feedbackByPlugin = /* @__PURE__ */ Object.create(null);
  const actionMutex = new AsyncMutex();
  surface.injectStyle(HOST_STYLE_ID, HOST_CSS);
  const slotRoot = surface.mountSlot(HOST_SLOT_ID);
  slotRoot.setAttribute("class", "rph-root");
  const titleBarEl = createSafeElement(doc, "div", {
    attrs: { class: "rph-titlebar", "data-remote-slot": "title-bar", hidden: "hidden" }
  });
  const statusBarEl = createSafeElement(doc, "div", {
    attrs: { class: "rph-statusbar", "data-remote-slot": "status-bar", hidden: "hidden" }
  });
  const composerBarEl = createSafeElement(doc, "div", {
    attrs: { class: "rph-composerbar", "data-remote-slot": "composer-toolbar", hidden: "hidden" }
  });
  const dockEl = createSafeElement(doc, "div", { attrs: { class: "rph-dock" } });
  const drawerEl = createSafeElement(doc, "section", {
    attrs: {
      class: "rph-drawer",
      role: "dialog",
      "aria-label": STRINGS[locale].title,
      hidden: "hidden"
    }
  });
  const headerEl = createSafeElement(doc, "div", { attrs: { class: "rph-header" } });
  const titleEl = createSafeElement(doc, "h2", {
    attrs: { class: "rph-title" },
    text: STRINGS[locale].title
  });
  const headerActions = createSafeElement(doc, "div", { attrs: { class: "rph-header-actions" } });
  const langBtn = createSafeElement(doc, "button", {
    attrs: {
      type: "button",
      class: "rph-btn",
      "data-rph-control": "lang-toggle",
      "aria-label": STRINGS[locale].langAria
    },
    text: STRINGS[locale].langToggle
  });
  const closeBtn = createSafeElement(doc, "button", {
    attrs: {
      type: "button",
      class: "rph-btn",
      "data-rph-control": "close",
      "aria-label": STRINGS[locale].close
    },
    text: "\xD7"
  });
  headerActions.appendChild(langBtn);
  headerActions.appendChild(closeBtn);
  headerEl.appendChild(titleEl);
  headerEl.appendChild(headerActions);
  const confirmBoxEl = createSafeElement(doc, "div", {
    attrs: {
      class: "rph-confirm",
      "data-rph-control": "confirm-box",
      role: "alertdialog",
      hidden: "hidden"
    }
  });
  const drawerBodyEl = createSafeElement(doc, "div", {
    attrs: { "data-rph-control": "drawer-body" }
  });
  drawerEl.appendChild(headerEl);
  drawerEl.appendChild(confirmBoxEl);
  drawerEl.appendChild(drawerBodyEl);
  const pillBtn = createSafeElement(doc, "button", {
    attrs: {
      type: "button",
      class: "rph-pill",
      "data-rph-control": "dock-pill",
      "aria-expanded": "false",
      "aria-label": STRINGS[locale].pillLabel
    }
  });
  const pillLabelSpan = createSafeElement(doc, "span", { text: STRINGS[locale].pillText });
  const pillCountSpan = createSafeElement(doc, "span", {
    attrs: { class: "rph-badge-count", "data-rph-control": "plugin-count" },
    text: "0"
  });
  pillBtn.appendChild(pillLabelSpan);
  pillBtn.appendChild(pillCountSpan);
  dockEl.appendChild(drawerEl);
  dockEl.appendChild(pillBtn);
  slotRoot.appendChild(titleBarEl);
  slotRoot.appendChild(composerBarEl);
  slotRoot.appendChild(statusBarEl);
  slotRoot.appendChild(dockEl);
  function pruneStalePluginState(activeIdSet) {
    if (pendingChallenge && !activeIdSet.has(pendingChallenge.pluginId)) {
      pendingChallenge = null;
    }
    for (const key of Object.keys(feedbackByPlugin)) {
      if (!activeIdSet.has(key)) {
        delete feedbackByPlugin[key];
      }
    }
  }
  function setOpen(nextOpen) {
    isOpen = Boolean(nextOpen);
    drawerEl.hidden = !isOpen;
    pillBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    if (!isOpen && typeof pillBtn.focus === "function") {
      pillBtn.focus();
    }
  }
  function updateChromeLocale() {
    const s = STRINGS[locale];
    titleEl.textContent = s.title;
    drawerEl.setAttribute("aria-label", s.title);
    langBtn.textContent = s.langToggle;
    langBtn.setAttribute("aria-label", s.langAria);
    closeBtn.setAttribute("aria-label", s.close);
    pillBtn.setAttribute("aria-label", s.pillLabel);
    pillLabelSpan.textContent = s.pillText;
  }
  function renderConfirmBox() {
    clearChildren(confirmBoxEl);
    if (!pendingChallenge || !registry.get(pendingChallenge.pluginId)) {
      pendingChallenge = null;
      confirmBoxEl.hidden = true;
      return;
    }
    const s = STRINGS[locale];
    confirmBoxEl.hidden = false;
    confirmBoxEl.appendChild(
      createSafeElement(doc, "div", { attrs: { class: "rph-plugin-name" }, text: s.confirmTitle })
    );
    confirmBoxEl.appendChild(
      createSafeElement(doc, "div", {
        attrs: { class: "rph-notice", "data-tone": "warn" },
        text: resolveLocalizedText(pendingChallenge.message, locale)
      })
    );
    const btnRow = createSafeElement(doc, "div", { attrs: { class: "rph-actions" } });
    const confirmBtn = createSafeElement(doc, "button", {
      attrs: {
        type: "button",
        class: "rph-btn",
        "data-style": "danger",
        "data-rph-control": "confirm-accept"
      },
      text: pendingChallenge.confirmLabel ? resolveLocalizedText(pendingChallenge.confirmLabel, locale) : s.confirmButton
    });
    const cancelBtn = createSafeElement(doc, "button", {
      attrs: {
        type: "button",
        class: "rph-btn",
        "data-rph-control": "confirm-cancel"
      },
      text: s.cancelButton
    });
    confirmBtn.addEventListener("click", () => {
      const active = pendingChallenge;
      pendingChallenge = null;
      renderConfirmBox();
      if (active) {
        void executePluginAction(active.pluginId, active.actionId, {
          expectedRevision: active.expectedRevision,
          challengeResponse: { challengeId: active.challengeId, confirmed: true }
        });
      }
    });
    cancelBtn.addEventListener("click", () => {
      pendingChallenge = null;
      renderConfirmBox();
    });
    btnRow.appendChild(confirmBtn);
    btnRow.appendChild(cancelBtn);
    confirmBoxEl.appendChild(btnRow);
  }
  async function executePluginAction(pluginId, actionId, invocation = {}) {
    const myGen = ++actionGeneration;
    return actionMutex.runExclusive(async () => {
      if (disposed || myGen !== actionGeneration || !registry.get(pluginId)) {
        return null;
      }
      const result = await registry.invokeAction(pluginId, actionId, invocation, { locale });
      if (disposed || myGen !== actionGeneration || !registry.get(pluginId)) {
        return null;
      }
      if (result.status === "confirmation_required") {
        pendingChallenge = {
          pluginId,
          actionId,
          expectedRevision: invocation.expectedRevision,
          challengeId: result.challengeId,
          message: result.message,
          confirmLabel: result.confirmLabel
        };
        setOpen(true);
        renderConfirmBox();
        return result;
      }
      if (pendingChallenge && pendingChallenge.pluginId === pluginId) {
        pendingChallenge = null;
      }
      if (result.status === "conflict") {
        feedbackByPlugin[pluginId] = {
          tone: "warn",
          message: result.message,
          needsRefresh: true
        };
      } else if (result.status === "error") {
        feedbackByPlugin[pluginId] = {
          tone: "error",
          message: result.message,
          needsRefresh: false
        };
      } else {
        feedbackByPlugin[pluginId] = {
          tone: "ok",
          message: result.message ?? ACTION_OK_LOCALIZED,
          needsRefresh: false
        };
      }
      await render();
      return result;
    });
  }
  function renderSection(plugin, snapshotRevision, section) {
    if (section.kind === "notice") {
      return createSafeElement(doc, "div", {
        attrs: { class: "rph-notice", "data-tone": section.tone },
        text: resolveLocalizedText(section.text, locale)
      });
    }
    if (section.kind === "metrics") {
      const wrap = createSafeElement(doc, "div", { attrs: { class: "rph-metrics" } });
      for (const item of section.items) {
        const box = createSafeElement(doc, "span", {
          attrs: { class: "rph-metric", "data-tone": item.tone }
        });
        box.appendChild(createSafeElement(doc, "span", { text: resolveLocalizedText(item.label, locale) }));
        box.appendChild(createSafeElement(doc, "span", { attrs: { class: "rph-metric-val" }, text: item.value }));
        wrap.appendChild(box);
      }
      return wrap;
    }
    if (section.kind === "list") {
      const box = createSafeElement(doc, "div", { attrs: { class: "rph-kv" } });
      if (section.title) {
        box.appendChild(
          createSafeElement(doc, "div", {
            attrs: { class: "rph-slot-heading" },
            text: resolveLocalizedText(section.title, locale)
          })
        );
      }
      const ul = createSafeElement(doc, "ul", { attrs: { class: "rph-list" } });
      for (const item of section.items) {
        const li = createSafeElement(doc, "li", { attrs: { class: "rph-list-item" } });
        const left = createSafeElement(doc, "div");
        left.appendChild(createSafeElement(doc, "div", { text: resolveLocalizedText(item.primary, locale) }));
        if (item.secondary) {
          left.appendChild(
            createSafeElement(doc, "div", {
              attrs: { class: "rph-slot-heading" },
              text: resolveLocalizedText(item.secondary, locale)
            })
          );
        }
        li.appendChild(left);
        if (item.badge) {
          li.appendChild(
            createSafeElement(doc, "span", {
              attrs: { class: "rph-chip" },
              text: resolveLocalizedText(item.badge, locale)
            })
          );
        }
        ul.appendChild(li);
      }
      box.appendChild(ul);
      return box;
    }
    if (section.kind === "key-value") {
      const box = createSafeElement(doc, "div", { attrs: { class: "rph-kv" } });
      if (section.title) {
        box.appendChild(
          createSafeElement(doc, "div", {
            attrs: { class: "rph-slot-heading" },
            text: resolveLocalizedText(section.title, locale)
          })
        );
      }
      for (const entry of section.entries) {
        const row = createSafeElement(doc, "div", { attrs: { class: "rph-kv-row" } });
        row.appendChild(createSafeElement(doc, "span", { text: resolveLocalizedText(entry.key, locale) }));
        row.appendChild(createSafeElement(doc, "strong", { text: entry.value }));
        box.appendChild(row);
      }
      return box;
    }
    if (section.kind === "actions") {
      if (!plugin.capabilities.includes("actions")) {
        return null;
      }
      const box = createSafeElement(doc, "div", { attrs: { class: "rph-kv" } });
      if (section.title) {
        box.appendChild(
          createSafeElement(doc, "div", {
            attrs: { class: "rph-slot-heading" },
            text: resolveLocalizedText(section.title, locale)
          })
        );
      }
      const row = createSafeElement(doc, "div", { attrs: { class: "rph-actions" } });
      for (const item of section.items) {
        const attrs = {
          type: "button",
          class: "rph-btn",
          "data-style": item.style,
          "data-plugin-id": plugin.id,
          "data-action-id": item.id
        };
        if (item.disabled) {
          attrs.disabled = "disabled";
        }
        const btn = createSafeElement(doc, "button", {
          attrs,
          text: resolveLocalizedText(item.label, locale)
        });
        btn.addEventListener("click", () => {
          void executePluginAction(
            plugin.id,
            item.id,
            snapshotRevision ? { expectedRevision: snapshotRevision } : {}
          );
        });
        row.appendChild(btn);
      }
      box.appendChild(row);
      return box;
    }
    return null;
  }
  function renderInlineBarPlugin(container, plugin, snapResult) {
    const itemWrap = createSafeElement(doc, "div", {
      attrs: {
        class: "rph-status-inline",
        "data-plugin-id": plugin.id,
        "data-slot-id": plugin.uiSlot.slotId
      }
    });
    itemWrap.appendChild(
      createSafeElement(doc, "span", {
        attrs: { class: "rph-plugin-name" },
        text: resolveLocalizedText(plugin.displayName, locale)
      })
    );
    if (!snapResult.ok) {
      itemWrap.appendChild(
        createSafeElement(doc, "span", {
          attrs: { class: "rph-chip", "data-tone": "error" },
          text: STRINGS[locale].snapshotError
        })
      );
      container.appendChild(itemWrap);
      return;
    }
    const { snapshot } = snapResult;
    if (snapshot.badge) {
      itemWrap.appendChild(
        createSafeElement(doc, "span", {
          attrs: { class: "rph-chip", "data-tone": snapshot.badge.tone },
          text: resolveLocalizedText(snapshot.badge.text, locale)
        })
      );
    }
    for (const sec of snapshot.sections) {
      if (sec.kind === "metrics" || sec.kind === "actions") {
        const rendered = renderSection(plugin, snapshot.revision, sec);
        if (rendered) {
          itemWrap.appendChild(rendered);
        }
      }
    }
    if (hasOwn2(feedbackByPlugin, plugin.id)) {
      const fb = feedbackByPlugin[plugin.id];
      itemWrap.appendChild(
        createSafeElement(doc, "span", {
          attrs: { class: "rph-chip", "data-tone": fb.tone, role: "status", "aria-live": "polite" },
          text: resolveLocalizedText(fb.message, locale)
        })
      );
    }
    container.appendChild(itemWrap);
  }
  function renderPluginCard(plugin, snapResult) {
    const card = createSafeElement(doc, "article", {
      attrs: {
        class: "rph-plugin-card",
        "data-plugin-id": plugin.id,
        "data-slot-id": plugin.uiSlot.slotId
      }
    });
    const head = createSafeElement(doc, "div", { attrs: { class: "rph-plugin-head" } });
    head.appendChild(
      createSafeElement(doc, "span", {
        attrs: { class: "rph-plugin-name" },
        text: resolveLocalizedText(plugin.displayName, locale)
      })
    );
    if (snapResult.ok && snapResult.snapshot.badge) {
      head.appendChild(
        createSafeElement(doc, "span", {
          attrs: { class: "rph-chip", "data-tone": snapResult.snapshot.badge.tone },
          text: resolveLocalizedText(snapResult.snapshot.badge.text, locale)
        })
      );
    }
    card.appendChild(head);
    if (!snapResult.ok) {
      card.appendChild(
        createSafeElement(doc, "div", {
          attrs: { class: "rph-notice", "data-tone": "error" },
          text: `${STRINGS[locale].snapshotError}: ${snapResult.error}`
        })
      );
      return card;
    }
    const { snapshot } = snapResult;
    if (snapshot.notice) {
      card.appendChild(
        createSafeElement(doc, "div", {
          attrs: { class: "rph-notice", "data-tone": snapshot.notice.tone },
          text: resolveLocalizedText(snapshot.notice.text, locale)
        })
      );
    }
    for (const sec of snapshot.sections) {
      const rendered = renderSection(plugin, snapshot.revision, sec);
      if (rendered) {
        card.appendChild(rendered);
      }
    }
    if (hasOwn2(feedbackByPlugin, plugin.id)) {
      const fb = feedbackByPlugin[plugin.id];
      card.appendChild(
        createSafeElement(doc, "div", {
          attrs: { class: "rph-notice", "data-tone": fb.tone, role: "status", "aria-live": "polite" },
          text: resolveLocalizedText(fb.message, locale)
        })
      );
      if (fb.needsRefresh) {
        const reloadBtn = createSafeElement(doc, "button", {
          attrs: { type: "button", class: "rph-btn", "data-rph-control": "conflict-reload" },
          text: STRINGS[locale].conflictRefresh
        });
        reloadBtn.addEventListener("click", () => {
          delete feedbackByPlugin[plugin.id];
          void render();
        });
        card.appendChild(reloadBtn);
      }
    }
    return card;
  }
  async function render() {
    if (disposed) {
      return;
    }
    const seq = ++renderSeq;
    const plugins = registry.list();
    const activeIds = new Set(plugins.map((p) => p.id));
    pruneStalePluginState(activeIds);
    const snapshots = await Promise.all(
      plugins.map(async (plugin) => ({
        plugin,
        snapResult: await registry.readSnapshot(plugin.id, { locale })
      }))
    );
    if (disposed || seq !== renderSeq) {
      return;
    }
    const liveIds = new Set(registry.list().map((p) => p.id));
    pruneStalePluginState(liveIds);
    updateChromeLocale();
    renderConfirmBox();
    pillCountSpan.textContent = String(plugins.length);
    clearChildren(titleBarEl);
    clearChildren(statusBarEl);
    clearChildren(composerBarEl);
    clearChildren(drawerBodyEl);
    const drawerGroups = /* @__PURE__ */ Object.create(null);
    let titleBarCount = 0;
    let statusBarCount = 0;
    let composerBarCount = 0;
    for (const entry of snapshots) {
      if (!liveIds.has(entry.plugin.id)) {
        continue;
      }
      const slot = entry.plugin.uiSlot.slot;
      if (slot === "title-bar") {
        renderInlineBarPlugin(titleBarEl, entry.plugin, entry.snapResult);
        titleBarCount += 1;
      } else if (slot === "status-bar") {
        renderInlineBarPlugin(statusBarEl, entry.plugin, entry.snapResult);
        statusBarCount += 1;
      } else if (slot === "composer-toolbar") {
        renderInlineBarPlugin(composerBarEl, entry.plugin, entry.snapResult);
        composerBarCount += 1;
      }
      if (!drawerGroups[slot]) {
        drawerGroups[slot] = [];
      }
      drawerGroups[slot].push(entry);
    }
    titleBarEl.hidden = titleBarCount === 0;
    statusBarEl.hidden = statusBarCount === 0;
    composerBarEl.hidden = composerBarCount === 0;
    const slotKeys = Object.keys(drawerGroups);
    if (slotKeys.length === 0) {
      drawerBodyEl.appendChild(
        createSafeElement(doc, "div", {
          attrs: { class: "rph-notice", "data-tone": "info" },
          text: STRINGS[locale].empty
        })
      );
      return;
    }
    for (const slot of slotKeys) {
      const groupEl = createSafeElement(doc, "div", {
        attrs: { class: "rph-slot-group", "data-remote-slot-group": slot }
      });
      const labelObj = SLOT_LABELS[slot] || { ko: slot, en: slot };
      groupEl.appendChild(
        createSafeElement(doc, "div", {
          attrs: { class: "rph-slot-heading" },
          text: `${resolveLocalizedText(labelObj, locale)} (${slot})`
        })
      );
      for (const entry of drawerGroups[slot]) {
        groupEl.appendChild(renderPluginCard(entry.plugin, entry.snapResult));
      }
      drawerBodyEl.appendChild(groupEl);
    }
  }
  const onPillClick = () => setOpen(!isOpen);
  const onCloseClick = () => setOpen(false);
  const onLangClick = () => {
    locale = locale === "ko" ? "en" : "ko";
    void render();
  };
  const onKeyDown = (e) => {
    if (e.isComposing || e.keyCode === 229) {
      return;
    }
    if (e.key === "Escape" && isOpen) {
      setOpen(false);
    }
  };
  pillBtn.addEventListener("click", onPillClick);
  closeBtn.addEventListener("click", onCloseClick);
  langBtn.addEventListener("click", onLangClick);
  if (win && typeof win.addEventListener === "function") {
    win.addEventListener("keydown", onKeyDown);
  }
  const unsubRegistry = registry.onChange((evt) => {
    if (evt && evt.type === "unregistered" && typeof evt.pluginId === "string") {
      actionGeneration += 1;
      if (pendingChallenge && pendingChallenge.pluginId === evt.pluginId) {
        pendingChallenge = null;
      }
      delete feedbackByPlugin[evt.pluginId];
    }
    void render();
  });
  const dispose = () => {
    if (disposed) {
      return;
    }
    disposed = true;
    actionGeneration += 1;
    pendingChallenge = null;
    unsubRegistry();
    pillBtn.removeEventListener("click", onPillClick);
    closeBtn.removeEventListener("click", onCloseClick);
    langBtn.removeEventListener("click", onLangClick);
    if (win && typeof win.removeEventListener === "function") {
      win.removeEventListener("keydown", onKeyDown);
    }
    surface.removeStyle(HOST_STYLE_ID);
    surface.unmountSlot(HOST_SLOT_ID);
  };
  surface.onDispose(dispose);
  void render();
  return Object.freeze({
    render,
    setOpen,
    toggleOpen() {
      setOpen(!isOpen);
    },
    setLocale(nextLocale) {
      locale = nextLocale === "en" ? "en" : "ko";
      return render();
    },
    getLocale() {
      return locale;
    },
    isOpen() {
      return isOpen;
    },
    executePluginAction,
    dispose
  });
}

// src/core/desktop-companion-view.js
var PANEL_STYLE_ID = "desktop-remote-companion-css";
var PANEL_CSS = [
  `.drc-panel { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; border-radius: 12px; border: 1px solid rgba(128,134,139,0.3); padding: 14px; display: flex; flex-direction: column; gap: 10px; max-width: 680px; }`,
  `.drc-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }`,
  `.drc-title { margin: 0; font-size: 15px; font-weight: 700; }`,
  `.drc-subtitle { margin: 0; font-size: 12px; opacity: 0.78; }`,
  `.drc-card { border-radius: 8px; border: 1px solid rgba(128,134,139,0.22); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `.drc-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; font-size: 13px; }`,
  `.drc-slots { display: flex; flex-wrap: wrap; gap: 6px; }`,
  `.drc-chip { padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: rgba(128,134,139,0.16); }`,
  `.drc-btn { min-height: 36px; padding: 6px 12px; border-radius: 8px; border: 1px solid rgba(128,134,139,0.35); background: rgba(128,134,139,0.14); color: inherit; font-size: 12px; font-weight: 600; cursor: pointer; }`,
  `.drc-btn:focus-visible { outline: 2px solid #4d90fe; outline-offset: 2px; }`,
  `.drc-status { font-size: 12px; opacity: 0.85; min-height: 18px; }`
].join(" ");
var COPY = Object.freeze({
  ko: Object.freeze({
    title: "\uC6D0\uACA9 \uD50C\uB7EC\uADF8\uC778 \uCEF4\uD328\uB2C8\uC5B8",
    subtitle: "AddonManifest.v1 \uD638\uC2A4\uD2B8 \uACA9\uB9AC \uC2AC\uB86F\uC5D0\uC11C \uB3D9\uC791\uD558\uB294 \uC6D0\uACA9 \uC5F0\uB3D9 \uC548\uB0B4 \uD328\uB110\uC785\uB2C8\uB2E4.",
    langToggle: "EN",
    contractLabel: "\uC6D0\uACA9 \uD50C\uB7EC\uADF8\uC778 \uD45C\uC900 \uACC4\uC57D",
    hostLabel: "\uB124\uC774\uD2F0\uBE0C \uD638\uC2A4\uD2B8 \uD504\uB85C\uD544",
    setupTitle: "\uC678\uBD80 \xB7 \uBAA8\uBC14\uC77C \uBE0C\uB77C\uC6B0\uC800 \uC6D0\uACA9 \uC5F0\uB3D9",
    copyBookmarklet: "\uBD81\uB9C8\uD074\uB9BF \uBCF5\uC0AC",
    copyUserscript: "\uC720\uC800\uC2A4\uD06C\uB9BD\uD2B8 \uACBD\uB85C \uBCF5\uC0AC",
    copiedBookmarklet: "\uBD81\uB9C8\uD074\uB9BF \uC2A4\uB2C8\uD3AB\uC744 \uD074\uB9BD\uBCF4\uB4DC\uC5D0 \uBCF5\uC0AC\uD588\uC2B5\uB2C8\uB2E4.",
    copiedUserscript: "\uC720\uC800\uC2A4\uD06C\uB9BD\uD2B8 \uACBD\uB85C\uB97C \uD074\uB9BD\uBCF4\uB4DC\uC5D0 \uBCF5\uC0AC\uD588\uC2B5\uB2C8\uB2E4.",
    copyFailed: "\uD074\uB9BD\uBCF4\uB4DC \uBCF5\uC0AC\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4. \uBC30\uD3EC \uD30C\uC77C\uC744 \uC9C1\uC811 \uC5F4\uC5B4 \uBCF5\uC0AC\uD558\uC138\uC694.",
    slotsTitle: "\uC9C0\uC6D0\uB418\uB294 \uC6D0\uACA9 UI \uC2AC\uB86F \uBC30\uCE58"
  }),
  en: Object.freeze({
    title: "Remote Plugin Companion",
    subtitle: "Remote integration settings panel running inside an isolated AddonManifest.v1 slot.",
    langToggle: "KO",
    contractLabel: "Remote Plugin Standard",
    hostLabel: "Native Host Profile",
    setupTitle: "External & Mobile Browser Setup",
    copyBookmarklet: "Copy Bookmarklet",
    copyUserscript: "Copy Userscript Path",
    copiedBookmarklet: "Bookmarklet snippet copied to clipboard.",
    copiedUserscript: "Userscript path copied to clipboard.",
    copyFailed: "Clipboard copy failed. Copy directly from the built dist artifact.",
    slotsTitle: "Supported Remote UI Slot Placements"
  })
});
function mountDesktopCompanionView({
  doc,
  surface,
  slotId,
  hostInfo = {},
  remoteArtifacts = {},
  clipboard = null,
  initialLocale = "ko"
}) {
  validateHostSurfacePort(surface);
  if (!doc || typeof doc.createElement !== "function") {
    throw new TypeError("DesktopCompanionView requires a DOM document.");
  }
  if (typeof slotId !== "string" || !slotId.trim()) {
    throw new TypeError("DesktopCompanionView requires a declared slotId.");
  }
  let locale = initialLocale === "en" ? "en" : "ko";
  let statusMessage = "";
  let disposed = false;
  surface.injectStyle(PANEL_STYLE_ID, PANEL_CSS);
  const container = surface.mountSlot(slotId);
  const bookmarkletText = typeof remoteArtifacts.bookmarklet === "string" && remoteArtifacts.bookmarklet.trim() ? remoteArtifacts.bookmarklet.trim() : "dist/bookmarklet.txt";
  const userscriptPath = typeof remoteArtifacts.userscriptPath === "string" && remoteArtifacts.userscriptPath.trim() ? remoteArtifacts.userscriptPath.trim() : "dist/remote-plugin.user.js";
  async function copyText(text, successKey) {
    if (!clipboard || typeof clipboard.writeText !== "function") {
      statusMessage = COPY[locale].copyFailed;
      render();
      return false;
    }
    try {
      await clipboard.writeText(text);
      statusMessage = COPY[locale][successKey];
      render();
      return true;
    } catch (_err) {
      statusMessage = COPY[locale].copyFailed;
      render();
      return false;
    }
  }
  function render() {
    if (disposed) {
      return;
    }
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
    const s = COPY[locale];
    const panel = createSafeElement(doc, "section", {
      attrs: { class: "drc-panel", "data-drc-locale": locale }
    });
    const header = createSafeElement(doc, "div", { attrs: { class: "drc-header" } });
    const headingWrap = createSafeElement(doc, "div");
    headingWrap.appendChild(createSafeElement(doc, "h3", { attrs: { class: "drc-title" }, text: s.title }));
    headingWrap.appendChild(createSafeElement(doc, "p", { attrs: { class: "drc-subtitle" }, text: s.subtitle }));
    const langBtn = createSafeElement(doc, "button", {
      attrs: { type: "button", class: "drc-btn", "data-drc-action": "toggle-locale" },
      text: s.langToggle
    });
    langBtn.addEventListener("click", () => {
      locale = locale === "ko" ? "en" : "ko";
      statusMessage = "";
      render();
    });
    header.appendChild(headingWrap);
    header.appendChild(langBtn);
    panel.appendChild(header);
    const metaCard = createSafeElement(doc, "div", { attrs: { class: "drc-card" } });
    const row1 = createSafeElement(doc, "div", { attrs: { class: "drc-row" } });
    row1.appendChild(createSafeElement(doc, "span", { text: s.contractLabel }));
    row1.appendChild(createSafeElement(doc, "strong", { text: REMOTE_PLUGIN_CONTRACT_VERSION }));
    const row2 = createSafeElement(doc, "div", { attrs: { class: "drc-row" } });
    row2.appendChild(createSafeElement(doc, "span", { text: s.hostLabel }));
    row2.appendChild(
      createSafeElement(doc, "strong", {
        text: `${hostInfo.hostProfileId || "default"} (${hostInfo.hostVersion || "1.0.1"})`
      })
    );
    metaCard.appendChild(row1);
    metaCard.appendChild(row2);
    panel.appendChild(metaCard);
    const setupCard = createSafeElement(doc, "div", { attrs: { class: "drc-card" } });
    setupCard.appendChild(createSafeElement(doc, "strong", { text: s.setupTitle }));
    const btnRow = createSafeElement(doc, "div", { attrs: { class: "drc-slots" } });
    const copyBmBtn = createSafeElement(doc, "button", {
      attrs: { type: "button", class: "drc-btn", "data-drc-action": "copy-bookmarklet" },
      text: s.copyBookmarklet
    });
    copyBmBtn.addEventListener("click", () => {
      void copyText(bookmarkletText, "copiedBookmarklet");
    });
    const copyUsBtn = createSafeElement(doc, "button", {
      attrs: { type: "button", class: "drc-btn", "data-drc-action": "copy-userscript" },
      text: s.copyUserscript
    });
    copyUsBtn.addEventListener("click", () => {
      void copyText(userscriptPath, "copiedUserscript");
    });
    btnRow.appendChild(copyBmBtn);
    btnRow.appendChild(copyUsBtn);
    setupCard.appendChild(btnRow);
    setupCard.appendChild(
      createSafeElement(doc, "div", {
        attrs: { class: "drc-status", role: "status", "aria-live": "polite", "data-drc-status": "true" },
        text: statusMessage
      })
    );
    panel.appendChild(setupCard);
    const slotCard = createSafeElement(doc, "div", { attrs: { class: "drc-card" } });
    slotCard.appendChild(createSafeElement(doc, "strong", { text: s.slotsTitle }));
    const chips = createSafeElement(doc, "div", { attrs: { class: "drc-slots" } });
    for (const slot of ALLOWED_UI_SLOTS) {
      chips.appendChild(createSafeElement(doc, "span", { attrs: { class: "drc-chip" }, text: slot }));
    }
    slotCard.appendChild(chips);
    panel.appendChild(slotCard);
    container.appendChild(panel);
  }
  const dispose = () => {
    if (disposed) {
      return;
    }
    disposed = true;
    surface.removeStyle(PANEL_STYLE_ID);
    surface.unmountSlot(slotId);
  };
  surface.onDispose(dispose);
  render();
  return Object.freeze({
    render,
    setLocale(nextLocale) {
      locale = nextLocale === "en" ? "en" : "ko";
      render();
    },
    getLocale() {
      return locale;
    },
    dispose
  });
}

// src/bridges/dom-overlay-bridge.js
function stripSensitiveSettings(rawSettings) {
  if (!rawSettings || typeof rawSettings !== "object" || Array.isArray(rawSettings)) {
    return Object.freeze({});
  }
  return stripSensitiveDeep(rawSettings) || Object.freeze({});
}
function createDomOverlayBridge({
  id,
  pluginName,
  pluginAliases = [],
  createOverlay,
  settingsPort = null,
  sanitizeSettings = stripSensitiveSettings,
  onStatus = null
}) {
  if (typeof createOverlay !== "function") {
    throw new TypeError("DomOverlayBridge requires a createOverlay factory function.");
  }
  if (typeof sanitizeSettings !== "function") {
    throw new TypeError("DomOverlayBridge sanitizeSettings must be a function.");
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
          "MISSING_PROMOTED_FRAME",
          `Bridge "${id}" requires a promoted frame with win and doc.`
        );
      }
      const myEpoch = ++mountEpoch;
      return mutex.runExclusive(async () => {
        if (myEpoch !== mountEpoch) {
          return { skipped: true };
        }
        teardownCurrent();
        const resolvedPluginName = plugin?.name || pluginName;
        const rawSettings = settingsPort ? await settingsPort.readPluginSettings(resolvedPluginName) : {};
        if (myEpoch !== mountEpoch) {
          return { skipped: true };
        }
        const safeSettings = Object.freeze({ ...sanitizeSettings(rawSettings) });
        const statusCallback = (statusPayload) => {
          if (typeof onStatus === "function") {
            onStatus(statusPayload);
          }
          if (diagnostics) {
            diagnostics.emit({
              level: "info",
              code: "OVERLAY_STATUS",
              source: `bridge.${id}`,
              message: "Overlay status updated",
              detail: statusPayload
            });
          }
        };
        const instance = createOverlay({
          win: frame.win,
          doc: frame.doc,
          settings: safeSettings,
          onStatus: statusCallback
        });
        if (!instance || typeof instance.start !== "function" || typeof instance.dispose !== "function") {
          throw new TypeError(
            `Overlay factory for "${id}" must return { start(), dispose() }.`
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
      if (activeInstance && typeof activeInstance.updateSettings === "function") {
        activeInstance.updateSettings(safeNext);
      }
      return safeNext;
    },
    dispose() {
      mountEpoch += 1;
      teardownCurrent();
    }
  };
}

// src/bridges/sidecar-ui-bridge.js
function deriveSidecarOrigin(sidecar) {
  if (!sidecar || typeof sidecar !== "object") {
    throw new SecurityPolicyError("INVALID_SIDECAR", "Sidecar descriptor is required.");
  }
  const rawHost = sidecar.host || "127.0.0.1";
  if (!isLoopbackHostname(rawHost)) {
    throw new SecurityPolicyError(
      "NON_LOOPBACK_SIDECAR",
      "Sidecar bridge only permits loopback sidecar origins."
    );
  }
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError("INVALID_SIDECAR_PORT", "Sidecar port must be a valid TCP port.");
  }
  const host = formatHostForUrl(rawHost);
  let parsed;
  try {
    parsed = new URL(`http://${host}:${port}/`);
  } catch (_err) {
    throw new SecurityPolicyError("INVALID_SIDECAR_ORIGIN", "Sidecar origin is not a valid URL.");
  }
  return parsed.origin.toLowerCase();
}
function createSidecarUiBridge({
  id,
  pluginName,
  sidecarId,
  relayPort,
  themeWorkspacePort = null,
  allowedOrigins = [],
  allowedApiPaths = [],
  allowedInboundEvents = [],
  conversationIdProvider = null,
  onInboundEvent = null
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
    return Array.isArray(allowedOrigins) && allowedOrigins.length > 0 ? isOriginAllowed(normalized.origin, allowedOrigins) : false;
  }
  function pushThemeAndWorkspace(targetWindow) {
    if (!targetWindow || typeof targetWindow.postMessage !== "function" || !activeSidecarOrigin) {
      return;
    }
    if (!themeWorkspacePort) {
      return;
    }
    const vars = themeWorkspacePort.getThemeVariables();
    if (vars && typeof vars === "object") {
      targetWindow.postMessage(
        { type: "theme-change", payload: { cssVariables: { ...vars } } },
        activeSidecarOrigin
      );
    }
    const uris = themeWorkspacePort.getWorkspaceUris();
    targetWindow.postMessage(
      { type: "workspace-change", payload: { workspaceUris: Array.isArray(uris) ? [...uris] : [] } },
      activeSidecarOrigin
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
          "SIDECAR_NOT_ACTIVE",
          `Cannot mount "${id}": sidecar "${sidecarId}" is not active.`
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
        if (frame && frame.doc && typeof frame.doc.createElement === "function") {
          const conversationId = typeof conversationIdProvider === "function" ? conversationIdProvider() : frame.conversationId || "";
          const uiUrl = relayPort.buildUiUrl({ sidecar, conversationId });
          const iframe = createSafeElement(frame.doc, "iframe", {
            attrs: {
              src: uiUrl,
              "data-remote-sidecar-id": sidecarId,
              sandbox: "allow-scripts allow-same-origin allow-forms"
            }
          });
          mountedIframe = iframe;
          const hasLoadEvents = typeof iframe.addEventListener === "function";
          if (hasLoadEvents) {
            const onLoad = () => {
              iframeLoaded = true;
              if (mountedIframe === iframe && iframe.contentWindow) {
                pushThemeAndWorkspace(iframe.contentWindow);
              }
            };
            iframe.addEventListener("load", onLoad);
            store.add(() => {
              if (typeof iframe.removeEventListener === "function") {
                iframe.removeEventListener("load", onLoad);
              }
            });
          }
          const mountContainer = frame.panelContainer || frame.doc.body || null;
          if (mountContainer && typeof mountContainer.appendChild === "function") {
            mountContainer.appendChild(iframe);
            store.add(() => {
              if (typeof iframe.remove === "function") {
                iframe.remove();
              } else if (mountContainer && typeof mountContainer.removeChild === "function") {
                mountContainer.removeChild(iframe);
              }
            });
          }
          if (!hasLoadEvents && iframe.contentWindow) {
            iframeLoaded = true;
            pushThemeAndWorkspace(iframe.contentWindow);
          }
        }
        if (themeWorkspacePort) {
          const unsubSync = themeWorkspacePort.subscribe((change) => {
            const targetWin = mountedIframe?.contentWindow || null;
            if (!targetWin || !activeSidecarOrigin || !iframeLoaded) {
              return;
            }
            if (change?.type === "theme-change") {
              this.postThemeChange(targetWin, activeSidecarOrigin, change.cssVariables);
            } else if (change?.type === "workspace-change") {
              this.postWorkspaceChange(targetWin, activeSidecarOrigin, change.workspaceUris);
            }
          });
          if (typeof unsubSync === "function") {
            store.add(unsubSync);
          }
        }
        if (frame && frame.win && typeof frame.win.addEventListener === "function") {
          const onMessage = (event) => {
            this.handleInboundMessage(event);
          };
          frame.win.addEventListener("message", onMessage);
          store.add(() => {
            if (typeof frame.win.removeEventListener === "function") {
              frame.win.removeEventListener("message", onMessage);
            }
          });
        }
      } catch (mountErr) {
        this.dispose();
        throw mountErr;
      }
      return { sidecarId: sidecar.sidecarId, origin: sidecarOrigin };
    },
    buildUiUrl({ conversationId = "" } = {}) {
      if (!activeSidecar) {
        throw new SecurityPolicyError("BRIDGE_NOT_MOUNTED", `Bridge "${id}" is not mounted.`);
      }
      return relayPort.buildUiUrl({
        sidecar: activeSidecar,
        conversationId
      });
    },
    async relayApi(path, payload = {}, method = "POST") {
      if (!activeSidecar) {
        throw new SecurityPolicyError("BRIDGE_NOT_MOUNTED", `Bridge "${id}" is not mounted.`);
      }
      if (!permittedPaths.has(path)) {
        throw new SecurityPolicyError(
          "API_PATH_NOT_ALLOWED",
          `Blocked sidecar API path "${path}" outside allowlist.`
        );
      }
      return relayPort.requestJson({
        sidecar: activeSidecar,
        path,
        method,
        body: payload
      });
    },
    postThemeChange(targetWindow, targetOrigin, cssVariables) {
      if (!isOriginTrustedForActiveSidecar(targetOrigin)) {
        throw new SecurityPolicyError(
          "ORIGIN_NOT_ALLOWED",
          "Refused to post theme-change to untrusted origin."
        );
      }
      targetWindow.postMessage(
        {
          type: "theme-change",
          payload: { cssVariables: { ...cssVariables || {} } }
        },
        targetOrigin
      );
    },
    postWorkspaceChange(targetWindow, targetOrigin, workspaceUris) {
      if (!isOriginTrustedForActiveSidecar(targetOrigin)) {
        throw new SecurityPolicyError(
          "ORIGIN_NOT_ALLOWED",
          "Refused to post workspace-change to untrusted origin."
        );
      }
      targetWindow.postMessage(
        {
          type: "workspace-change",
          payload: { workspaceUris: Array.isArray(workspaceUris) ? [...workspaceUris] : [] }
        },
        targetOrigin
      );
    },
    handleInboundMessage(event, expectedSource = null) {
      if (!event || typeof event !== "object") {
        return { accepted: false, reason: "INVALID_EVENT" };
      }
      if (!activeSidecarOrigin || !isOriginTrustedForActiveSidecar(event.origin)) {
        if (activeDiagnostics) {
          activeDiagnostics.emit({
            level: "warn",
            code: "UNTRUSTED_POSTMESSAGE_ORIGIN",
            source: `bridge.${id}`,
            message: "Dropped inbound postMessage from untrusted origin",
            detail: { origin: event.origin }
          });
        }
        return { accepted: false, reason: "UNTRUSTED_ORIGIN" };
      }
      const requiredSource = expectedSource ?? mountedIframe?.contentWindow ?? null;
      if (!requiredSource) {
        return { accepted: false, reason: "SOURCE_UNAVAILABLE" };
      }
      if (event.source !== requiredSource) {
        if (activeDiagnostics) {
          activeDiagnostics.emit({
            level: "warn",
            code: "POSTMESSAGE_SOURCE_MISMATCH",
            source: `bridge.${id}`,
            message: "Dropped inbound postMessage from unexpected window source",
            detail: { origin: event.origin }
          });
        }
        return { accepted: false, reason: "SOURCE_MISMATCH" };
      }
      const type = event.data?.type;
      if (typeof type !== "string" || !permittedEvents.has(type)) {
        return { accepted: false, reason: "UNSUPPORTED_EVENT_TYPE" };
      }
      if (typeof onInboundEvent === "function") {
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
    }
  };
}

// src/bridges/mcp-extension-slot.js
var DEFAULT_PROTECTED_CONFIG_PATTERNS = Object.freeze([
  /(?:^|\/)config\/config\.json$/i,
  /(?:^|\/)plugins\/[^/]+\/mcp_config\.json$/i
]);
var CONTROL_CHAR_PATTERN = /[\u0000-\u001f\u007f]/;
function canonicalizeConfigPath(rawPath) {
  if (typeof rawPath !== "string" || !rawPath.trim()) {
    throw new SecurityPolicyError(
      "INVALID_CONFIG_PATH",
      "A non-empty targetConfigPath is required for MCP configuration mutations."
    );
  }
  if (CONTROL_CHAR_PATTERN.test(rawPath)) {
    throw new SecurityPolicyError(
      "INVALID_CONFIG_PATH",
      "Configuration path contains forbidden NUL or ASCII control characters."
    );
  }
  let normalized = rawPath.trim().replace(/\\/g, "/");
  if (/^[a-zA-Z]:[^/]/.test(normalized)) {
    throw new SecurityPolicyError(
      "INVALID_CONFIG_PATH",
      "Ambiguous drive-relative Windows configuration paths are forbidden."
    );
  }
  if (normalized === "~" || normalized.startsWith("~/")) {
    normalized = `/__home__${normalized.slice(1)}`;
  }
  const driveMatch = normalized.match(/^([a-zA-Z]:)(\/.*)?$/);
  const prefix = driveMatch ? driveMatch[1].toLowerCase() : normalized.startsWith("/") ? "/" : "";
  const body = driveMatch ? driveMatch[2] || "" : normalized;
  const segments = body.split("/");
  const resolved = [];
  for (const seg of segments) {
    if (!seg || seg === ".") {
      continue;
    }
    if (seg === "..") {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== "..") {
        resolved.pop();
      } else if (!prefix) {
        resolved.push("..");
      }
      continue;
    }
    resolved.push(seg);
  }
  const joined = resolved.join("/");
  if (driveMatch) {
    return `${prefix}/${joined}`;
  }
  return prefix ? `/${joined}` : joined;
}
function assertWritableConfigPath(targetPath, extraProtectedPatterns = []) {
  const canonical = canonicalizeConfigPath(targetPath);
  const allPatterns = [...DEFAULT_PROTECTED_CONFIG_PATTERNS, ...extraProtectedPatterns];
  for (const pattern of allPatterns) {
    if (pattern.test(canonical)) {
      throw new SecurityPolicyError(
        "PROTECTED_CONFIG_PATH",
        "Direct modification of protected host or plugin MCP configuration files is forbidden."
      );
    }
  }
  return canonical;
}
function isStdioMutation({ transport, serverConfig }) {
  const normalizedTransport = typeof transport === "string" ? transport.trim().toLowerCase() : "";
  if (normalizedTransport === "stdio") {
    return true;
  }
  if (serverConfig && typeof serverConfig === "object") {
    if (typeof serverConfig.command === "string" && serverConfig.command.trim().length > 0) {
      return true;
    }
  }
  return false;
}
function assertRemoteMcpMutationAllowed({ transport, serverConfig = null, userConfirmed }) {
  if (isStdioMutation({ transport, serverConfig }) && userConfirmed !== true) {
    throw new SecurityPolicyError(
      "UNCONFIRMED_REMOTE_STDIO",
      "Adding or executing a stdio MCP command over a remote channel requires explicit user confirmation."
    );
  }
}
function createMcpExtensionSlot({
  id = "mcp-extension-slot",
  pluginName,
  sidecarId = null,
  protectedConfigPatterns = [],
  delegate = null
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
          level: "info",
          code: "MCP_SLOT_MOUNTED",
          source: `bridge.${id}`,
          message: "Optional MCP extension slot mounted in decoupled mode",
          detail: { hasDelegate: Boolean(delegate) }
        });
      }
      return { decoupled: !delegate };
    },
    async requestServerMutation({ targetConfigPath, transport, serverConfig, userConfirmed = false }) {
      if (!mounted) {
        throw new SecurityPolicyError("BRIDGE_NOT_MOUNTED", `Slot "${id}" is not mounted.`);
      }
      const canonicalPath = assertWritableConfigPath(targetConfigPath, protectedConfigPatterns);
      assertRemoteMcpMutationAllowed({ transport, serverConfig, userConfirmed });
      if (!delegate || typeof delegate.applyMutation !== "function") {
        return {
          applied: false,
          reason: "NO_DELEGATE_ATTACHED",
          targetConfigPath: canonicalPath,
          sanitizedPreview: redactSecrets(serverConfig)
        };
      }
      return delegate.applyMutation({
        targetConfigPath: canonicalPath,
        transport,
        serverConfig,
        userConfirmed
      });
    },
    sanitizeServerView(serverConfig) {
      return redactSecrets(serverConfig);
    },
    dispose() {
      mounted = false;
    }
  };
}

// src/bridges/remote-plugin-port-bridge.js
var PORT_MSG = Object.freeze({
  REGISTER: "remote-plugin-v1:register",
  REGISTER_RESULT: "remote-plugin-v1:register-result",
  UNREGISTER: "remote-plugin-v1:unregister",
  DISCONNECT: "remote-plugin-v1:disconnect",
  DIRTY: "remote-plugin-v1:dirty",
  LIST: "remote-plugin-v1:list",
  LIST_RESULT: "remote-plugin-v1:list-result",
  SNAPSHOT_REQ: "remote-plugin-v1:snapshot-req",
  SNAPSHOT_RES: "remote-plugin-v1:snapshot-res",
  INVOKE_REQ: "remote-plugin-v1:invoke-req",
  INVOKE_RES: "remote-plugin-v1:invoke-res"
});
var DEFAULT_RPC_TIMEOUT_MS = 5e3;
function attachRemotePluginPortBridge({
  port,
  registry,
  diagnostics = null,
  onClose = null,
  rpcTimeoutMs = DEFAULT_RPC_TIMEOUT_MS
}) {
  if (!port || typeof port.postMessage !== "function") {
    throw new TypeError("attachRemotePluginPortBridge requires a MessagePort.");
  }
  if (!registry || typeof registry.register !== "function") {
    throw new TypeError("attachRemotePluginPortBridge requires a RemotePluginRegistry.");
  }
  let closed = false;
  let reqCounter = 0;
  let registeredPluginId = null;
  let unregisterFn = null;
  let dirtyCallback = null;
  const pendingRpc = /* @__PURE__ */ new Map();
  function rejectAllPending(reason) {
    for (const [id, entry] of pendingRpc.entries()) {
      clearTimeout(entry.timer);
      pendingRpc.delete(id);
      entry.reject(new Error(reason));
    }
  }
  function sendRpc(reqType, payload) {
    if (closed) {
      return Promise.reject(new SecurityPolicyError("ERR_PORT_CLOSED", "Remote plugin port is closed."));
    }
    const requestId = `rpc-${++reqCounter}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingRpc.delete(requestId);
        reject(new Error(`RPC ${reqType} timed out`));
      }, rpcTimeoutMs);
      pendingRpc.set(requestId, { resolve, reject, timer });
      try {
        port.postMessage({ type: reqType, requestId, ...payload });
      } catch (err) {
        clearTimeout(timer);
        pendingRpc.delete(requestId);
        reject(err);
      }
    });
  }
  function teardownLocalPlugin() {
    dirtyCallback = null;
    if (typeof unregisterFn === "function") {
      const unreg = unregisterFn;
      unregisterFn = null;
      registeredPluginId = null;
      unreg();
    } else {
      registeredPluginId = null;
    }
  }
  function closeBridge() {
    if (closed) {
      return;
    }
    closed = true;
    rejectAllPending("Remote plugin port disconnected.");
    teardownLocalPlugin();
    if (typeof port.removeEventListener === "function") {
      port.removeEventListener("message", onMessage);
    } else if (port.onmessage === onMessage) {
      port.onmessage = null;
    }
    if (typeof onClose === "function") {
      onClose();
    } else if (typeof port.close === "function") {
      port.close();
    }
  }
  function onMessage(event) {
    if (closed) {
      return;
    }
    const msg = event?.data;
    if (!msg || typeof msg !== "object") {
      return;
    }
    if (msg.type === PORT_MSG.SNAPSHOT_RES || msg.type === PORT_MSG.INVOKE_RES) {
      const entry = pendingRpc.get(msg.requestId);
      if (!entry) {
        return;
      }
      clearTimeout(entry.timer);
      pendingRpc.delete(msg.requestId);
      if (msg.ok) {
        entry.resolve(msg.result);
      } else {
        entry.reject(new Error(typeof msg.error === "string" ? msg.error : "Remote RPC error"));
      }
      return;
    }
    if (msg.type === PORT_MSG.LIST) {
      port.postMessage({
        type: PORT_MSG.LIST_RESULT,
        requestId: msg.requestId ?? null,
        plugins: registry.list().map((p) => ({
          id: p.id,
          version: p.version,
          uiSlot: p.uiSlot,
          capabilities: p.capabilities
        }))
      });
      return;
    }
    if (msg.type === PORT_MSG.REGISTER) {
      const desc = msg.descriptor;
      if (!desc || typeof desc !== "object" || Array.isArray(desc)) {
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: false,
          error: "Invalid plugin descriptor."
        });
        return;
      }
      if (registeredPluginId) {
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: false,
          error: "Port already registered a plugin."
        });
        return;
      }
      const caps = Array.isArray(desc.capabilities) ? desc.capabilities : [];
      const proxy = {
        contractVersion: desc.contractVersion ?? REMOTE_PLUGIN_CONTRACT_VERSION,
        id: desc.id,
        version: desc.version,
        displayName: desc.displayName,
        uiSlot: desc.uiSlot,
        capabilities: caps,
        loadOrder: desc.loadOrder,
        getSnapshot(ctx) {
          return sendRpc(PORT_MSG.SNAPSHOT_REQ, { ctx });
        },
        ...caps.includes("actions") ? {
          invoke(actionId, invocation, ctx) {
            return sendRpc(PORT_MSG.INVOKE_REQ, { actionId, invocation, ctx });
          }
        } : {},
        ...caps.includes("subscribe") ? {
          subscribe(onDirty) {
            dirtyCallback = onDirty;
            return () => {
              if (dirtyCallback === onDirty) {
                dirtyCallback = null;
              }
            };
          }
        } : {},
        dispose() {
          if (!closed) {
            try {
              port.postMessage({ type: PORT_MSG.DISCONNECT });
            } catch (err) {
              if (diagnostics) {
                diagnostics.emit({
                  level: "warn",
                  code: "PORT_DISCONNECT_SEND_FAILED",
                  source: "bridge.remote-plugin-port",
                  message: "Failed sending disconnect over port",
                  detail: err
                });
              }
            }
          }
          closeBridge();
        }
      };
      try {
        unregisterFn = registry.register(proxy);
        registeredPluginId = desc.id;
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: true,
          pluginId: desc.id
        });
      } catch (err) {
        const redacted = redactSecrets(err);
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: false,
          error: redacted?.message || "Registration failed.",
          code: err?.code || "ERR_REGISTER_FAILED"
        });
      }
      return;
    }
    if (msg.type === PORT_MSG.DIRTY) {
      if (typeof dirtyCallback === "function") {
        dirtyCallback();
      }
      return;
    }
    if (msg.type === PORT_MSG.UNREGISTER) {
      teardownLocalPlugin();
      return;
    }
    if (msg.type === PORT_MSG.DISCONNECT) {
      closeBridge();
    }
  }
  if (typeof port.addEventListener === "function") {
    port.addEventListener("message", onMessage);
    if (typeof port.start === "function") {
      port.start();
    }
  } else {
    port.onmessage = onMessage;
  }
  return Object.freeze({
    getRegisteredPluginId() {
      return registeredPluginId;
    },
    close: closeBridge
  });
}
function serveRemotePluginOverPort({ port, plugin, timeoutMs = DEFAULT_RPC_TIMEOUT_MS }) {
  if (!port || typeof port.postMessage !== "function") {
    throw new TypeError("serveRemotePluginOverPort requires a MessagePort.");
  }
  if (!plugin || typeof plugin !== "object") {
    throw new TypeError("serveRemotePluginOverPort requires a RemotePlugin.v1 object.");
  }
  let unsubDirty = null;
  let closed = false;
  const onMessage = async (event) => {
    if (closed) {
      return;
    }
    const msg = event?.data;
    if (!msg || typeof msg !== "object") {
      return;
    }
    if (msg.type === PORT_MSG.SNAPSHOT_REQ) {
      try {
        const result = await plugin.getSnapshot(msg.ctx || { locale: "ko" });
        port.postMessage({ type: PORT_MSG.SNAPSHOT_RES, requestId: msg.requestId, ok: true, result });
      } catch (err) {
        const redacted = redactSecrets(err);
        port.postMessage({
          type: PORT_MSG.SNAPSHOT_RES,
          requestId: msg.requestId,
          ok: false,
          error: redacted?.message || "Snapshot failed"
        });
      }
      return;
    }
    if (msg.type === PORT_MSG.INVOKE_REQ) {
      try {
        if (typeof plugin.invoke !== "function") {
          throw new Error("Plugin does not implement invoke().");
        }
        const result = await plugin.invoke(msg.actionId, msg.invocation || {}, msg.ctx || { locale: "ko" });
        port.postMessage({ type: PORT_MSG.INVOKE_RES, requestId: msg.requestId, ok: true, result });
      } catch (err) {
        const redacted = redactSecrets(err);
        port.postMessage({
          type: PORT_MSG.INVOKE_RES,
          requestId: msg.requestId,
          ok: false,
          error: redacted?.message || "Invoke failed"
        });
      }
      return;
    }
    if (msg.type === PORT_MSG.DISCONNECT) {
      disconnect();
    }
  };
  if (typeof port.addEventListener === "function") {
    port.addEventListener("message", onMessage);
    if (typeof port.start === "function") {
      port.start();
    }
  } else {
    port.onmessage = onMessage;
  }
  function disconnect() {
    if (closed) {
      return;
    }
    closed = true;
    if (typeof unsubDirty === "function") {
      unsubDirty();
      unsubDirty = null;
    }
    try {
      port.postMessage({ type: PORT_MSG.DISCONNECT });
    } catch (_err) {
      closed = true;
    }
    if (typeof port.removeEventListener === "function") {
      port.removeEventListener("message", onMessage);
    } else if (port.onmessage === onMessage) {
      port.onmessage = null;
    }
    if (typeof port.close === "function") {
      port.close();
    }
  }
  const registerPromise = new Promise((resolve, reject) => {
    const requestId = "reg-1";
    const timer = setTimeout(() => {
      reject(new Error("Remote plugin registration over MessagePort timed out."));
    }, timeoutMs);
    const onRegResult = (event) => {
      const msg = event?.data;
      if (!msg || msg.type !== PORT_MSG.REGISTER_RESULT || msg.requestId !== requestId) {
        return;
      }
      clearTimeout(timer);
      if (typeof port.removeEventListener === "function") {
        port.removeEventListener("message", onRegResult);
      }
      if (msg.ok) {
        if (typeof plugin.subscribe === "function") {
          const maybeUnsub = plugin.subscribe(
            () => {
              if (!closed) {
                port.postMessage({ type: PORT_MSG.DIRTY });
              }
            },
            { locale: "ko" }
          );
          if (typeof maybeUnsub === "function") {
            unsubDirty = maybeUnsub;
          }
        }
        resolve(msg);
      } else {
        const err = new Error(msg.error || "Registration rejected");
        err.code = msg.code || "ERR_REGISTER_FAILED";
        reject(err);
      }
    };
    if (typeof port.addEventListener === "function") {
      port.addEventListener("message", onRegResult);
    }
    port.postMessage({
      type: PORT_MSG.REGISTER,
      requestId,
      descriptor: {
        contractVersion: plugin.contractVersion,
        id: plugin.id,
        version: plugin.version,
        displayName: plugin.displayName,
        uiSlot: plugin.uiSlot,
        capabilities: plugin.capabilities,
        loadOrder: plugin.loadOrder
      }
    });
  });
  return Object.freeze({
    ready: registerPromise,
    notifyDirty() {
      if (!closed) {
        port.postMessage({ type: PORT_MSG.DIRTY });
      }
    },
    disconnect
  });
}

// src/adapters/addon-host/addon-host-surface-adapter.js
var REQUIRED_ADDON_HOST_METHODS = Object.freeze([
  "mountSlot",
  "unmountSlot",
  "injectStyle",
  "removeStyle",
  "listOwnedSlots",
  "onDispose",
  "dispose"
]);
function createAddonHostSurfaceAdapter(addonHost, { diagnostics = null } = {}) {
  if (!addonHost || typeof addonHost !== "object") {
    throw new SecurityPolicyError(
      "ERR_MISSING_ADDON_HOST",
      "AddonHostSurfaceAdapter requires a scoped addonHost capability handle."
    );
  }
  assertPort(addonHost, "addonHost", REQUIRED_ADDON_HOST_METHODS);
  let disposed = false;
  const ownedSlots = /* @__PURE__ */ new Set();
  const ownedStyles = /* @__PURE__ */ new Set();
  const localDisposers = [];
  function runLocalTeardown() {
    if (disposed) {
      return;
    }
    disposed = true;
    for (const fn of localDisposers.splice(0, localDisposers.length).reverse()) {
      try {
        fn();
      } catch (err) {
        if (diagnostics && typeof diagnostics.emit === "function") {
          diagnostics.emit({
            level: "error",
            code: "SURFACE_DISPOSER_FAILED",
            source: "adapter.addon-host-surface",
            message: "Desktop surface disposer threw during teardown",
            detail: err
          });
        }
      }
    }
    ownedSlots.clear();
    ownedStyles.clear();
  }
  addonHost.onDispose(runLocalTeardown);
  return Object.freeze({
    pluginId: typeof addonHost.pluginId === "string" ? addonHost.pluginId : "antigravity-remote-plugin",
    hostVersion: typeof addonHost.hostVersion === "string" ? addonHost.hostVersion : "1.0.1",
    hostProfileId: typeof addonHost.hostProfileId === "string" ? addonHost.hostProfileId : "antigravity-desktop",
    storageNamespace: typeof addonHost.storageNamespace === "string" ? addonHost.storageNamespace : "antigravity-remote-plugin",
    mountSlot(slotId, parentEl) {
      if (disposed) {
        throw new SecurityPolicyError("ERR_SURFACE_DISPOSED", "HostSurfacePort is already disposed.");
      }
      const el = addonHost.mountSlot(slotId, parentEl);
      ownedSlots.add(slotId);
      return el;
    },
    unmountSlot(slotId) {
      if (disposed) {
        return false;
      }
      ownedSlots.delete(slotId);
      return Boolean(addonHost.unmountSlot(slotId));
    },
    injectStyle(styleId, cssText) {
      if (disposed) {
        throw new SecurityPolicyError("ERR_SURFACE_DISPOSED", "HostSurfacePort is already disposed.");
      }
      const el = addonHost.injectStyle(styleId, String(cssText || ""));
      ownedStyles.add(styleId);
      return el;
    },
    removeStyle(styleId) {
      if (disposed) {
        return false;
      }
      ownedStyles.delete(styleId);
      return Boolean(addonHost.removeStyle(styleId));
    },
    listOwnedSlots() {
      if (disposed) {
        return [];
      }
      return [...ownedSlots];
    },
    onDispose(fn) {
      if (disposed || typeof fn !== "function") {
        return;
      }
      localDisposers.push(fn);
    },
    dispose() {
      if (disposed) {
        return;
      }
      runLocalTeardown();
      addonHost.dispose();
    }
  });
}

// src/adapters/remote-web/shadow-surface-adapter.js
var hasOwn3 = Object.hasOwn ? Object.hasOwn : (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
function createShadowSurfaceAdapter({
  doc,
  ownerId = "antigravity-remote-plugin",
  mountTarget = null,
  diagnostics = null
} = {}) {
  if (!doc || typeof doc.createElement !== "function") {
    throw new SecurityPolicyError("ERR_INVALID_DOCUMENT", "ShadowSurfaceAdapter requires a DOM document.");
  }
  const hostEl = createSafeElement(doc, "div", {
    attrs: {
      translate: "no",
      "data-addon-host-owner": ownerId,
      "data-remote-host-surface": "closed-shadow"
    }
  });
  const shadowRoot = typeof hostEl.attachShadow === "function" ? hostEl.attachShadow({ mode: "closed" }) : hostEl;
  const parent = mountTarget || doc.body || doc.documentElement;
  if (parent && typeof parent.appendChild === "function") {
    parent.appendChild(hostEl);
  }
  const slots = /* @__PURE__ */ Object.create(null);
  const styles = /* @__PURE__ */ Object.create(null);
  const disposers = [];
  let disposed = false;
  return Object.freeze({
    ownerId,
    hostElement: hostEl,
    mountSlot(slotId) {
      if (disposed) {
        throw new SecurityPolicyError("ERR_SURFACE_DISPOSED", "HostSurfacePort is already disposed.");
      }
      if (typeof slotId !== "string" || !slotId.trim()) {
        throw new SecurityPolicyError("ERR_INVALID_SLOT_ID", "slotId must be a non-empty string.");
      }
      if (hasOwn3(slots, slotId)) {
        return slots[slotId];
      }
      const el = createSafeElement(doc, "div", {
        attrs: {
          translate: "no",
          "data-addon-host-owner": ownerId,
          "data-addon-host-slot": slotId
        }
      });
      slots[slotId] = el;
      shadowRoot.appendChild(el);
      return el;
    },
    unmountSlot(slotId) {
      if (!hasOwn3(slots, slotId)) {
        return false;
      }
      const el = slots[slotId];
      delete slots[slotId];
      if (el && el.parentNode && typeof el.parentNode.removeChild === "function") {
        el.parentNode.removeChild(el);
      }
      return true;
    },
    injectStyle(styleId, cssText) {
      if (disposed) {
        throw new SecurityPolicyError("ERR_SURFACE_DISPOSED", "HostSurfacePort is already disposed.");
      }
      if (typeof styleId !== "string" || !styleId.trim()) {
        throw new SecurityPolicyError("ERR_INVALID_STYLE_ID", "styleId must be a non-empty string.");
      }
      let styleEl = hasOwn3(styles, styleId) ? styles[styleId] : null;
      if (!styleEl) {
        styleEl = createSafeElement(doc, "style", {
          attrs: {
            "data-addon-host-owner": ownerId,
            "data-addon-host-style": `${ownerId}:${styleId}`
          }
        });
        styles[styleId] = styleEl;
        shadowRoot.appendChild(styleEl);
      }
      styleEl.textContent = String(cssText || "");
      return styleEl;
    },
    removeStyle(styleId) {
      if (!hasOwn3(styles, styleId)) {
        return false;
      }
      const el = styles[styleId];
      delete styles[styleId];
      if (el && el.parentNode && typeof el.parentNode.removeChild === "function") {
        el.parentNode.removeChild(el);
      }
      return true;
    },
    listOwnedSlots() {
      return Object.keys(slots);
    },
    onDispose(fn) {
      if (disposed || typeof fn !== "function") {
        return;
      }
      disposers.push(fn);
    },
    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      for (const fn of disposers.splice(0, disposers.length).reverse()) {
        try {
          fn();
        } catch (err) {
          if (diagnostics && typeof diagnostics.emit === "function") {
            diagnostics.emit({
              level: "error",
              code: "SURFACE_DISPOSER_FAILED",
              source: "adapter.shadow-surface",
              message: "Surface disposer threw during teardown",
              detail: err
            });
          }
        }
      }
      for (const key of Object.keys(slots)) {
        const el = slots[key];
        delete slots[key];
        if (el && el.parentNode && typeof el.parentNode.removeChild === "function") {
          el.parentNode.removeChild(el);
        }
      }
      for (const key of Object.keys(styles)) {
        const el = styles[key];
        delete styles[key];
        if (el && el.parentNode && typeof el.parentNode.removeChild === "function") {
          el.parentNode.removeChild(el);
        }
      }
      if (hostEl.parentNode && typeof hostEl.parentNode.removeChild === "function") {
        hostEl.parentNode.removeChild(hostEl);
      }
    }
  });
}

// src/adapters/antigravity/discovery-adapter.js
var RPC_BASE_PATH = "/exa.language_server_pb.LanguageServerService";
function validateLoopbackAddress(lsAddress) {
  if (typeof lsAddress !== "string" || !lsAddress.trim()) {
    throw new SecurityPolicyError("INVALID_LS_ADDRESS", "Language server address is required.");
  }
  const raw = lsAddress.trim();
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
  const normalized = hasScheme ? raw : `http://${raw}`;
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_err) {
    throw new SecurityPolicyError("INVALID_LS_ADDRESS", "Language server address is not a valid URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SecurityPolicyError(
      "INVALID_LS_PROTOCOL",
      `Language server RPC adapter only permits http/https protocols, got "${parsed.protocol}".`
    );
  }
  if (!isLoopbackHostname(parsed.hostname)) {
    throw new SecurityPolicyError(
      "NON_LOOPBACK_LS_ADDRESS",
      "Language server RPC adapter only permits loopback addresses."
    );
  }
  const host = formatHostForUrl(parsed.hostname);
  const portSuffix = parsed.port ? `:${parsed.port}` : "";
  return `${parsed.protocol}//${host}${portSuffix}`;
}
function validateCsrfToken(csrfToken) {
  if (typeof csrfToken !== "string" || csrfToken.trim().length < 8) {
    throw new SecurityPolicyError(
      "MISSING_CSRF_TOKEN",
      "A real host-issued CSRF token is required; synthetic tokens are forbidden."
    );
  }
  const lowered = csrfToken.trim().toLowerCase();
  if (lowered === "csrf_token" || lowered === "placeholder" || lowered === "dummy") {
    throw new SecurityPolicyError(
      "SYNTHETIC_CSRF_TOKEN",
      "Synthetic placeholder CSRF tokens are forbidden."
    );
  }
  return csrfToken.trim();
}
function extractInstallDir(rawPath, fallbackName) {
  if (typeof rawPath !== "string" || !rawPath.trim()) {
    return fallbackName;
  }
  const stripped = rawPath.trim().replace(/\\/g, "/").replace(/\/+$/, "");
  const segment = stripped.split("/").pop();
  return segment || fallbackName;
}
function createAntigravityDiscoveryAdapter({
  lsAddress,
  csrfToken,
  fetchImpl = typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : void 0
}) {
  const origin = validateLoopbackAddress(lsAddress);
  const validToken = validateCsrfToken(csrfToken);
  if (typeof fetchImpl !== "function") {
    throw new TypeError("AntigravityDiscoveryAdapter requires a fetch implementation.");
  }
  async function callRpc(methodName, payload = {}) {
    const response = await fetchImpl(`${origin}${RPC_BASE_PATH}/${methodName}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-codeium-csrf-token": validToken
      },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error(`LanguageServerService/${methodName} failed with HTTP ${response.status}`);
    }
    return response.json();
  }
  return {
    async listPlugins({ workspaceUris = [] } = {}) {
      const body = Array.isArray(workspaceUris) && workspaceUris.length > 0 ? { workspaceUris } : {};
      const data = await callRpc("GetAllPlugins", body);
      if (!data || !Array.isArray(data.plugins)) {
        throw new Error('LanguageServerService/GetAllPlugins returned invalid payload: missing "plugins" array.');
      }
      return data.plugins.map((plugin) => ({
        name: plugin.name,
        path: plugin.path || "",
        dir: extractInstallDir(plugin.path, plugin.name),
        disabled: Boolean(plugin.disabled),
        enabled: !plugin.disabled,
        isGlobal: Boolean(plugin.isGlobal)
      }));
    },
    async listSidecars({ workspaceUris = [] } = {}) {
      const body = Array.isArray(workspaceUris) && workspaceUris.length > 0 ? { workspaceUris } : {};
      const data = await callRpc("GetSidecars", body);
      if (!data || !Array.isArray(data.sidecars)) {
        throw new Error('LanguageServerService/GetSidecars returned invalid payload: missing "sidecars" array.');
      }
      return data.sidecars.map((sc) => ({
        sidecarId: sc.sidecarId || sc.id || "",
        pluginName: sc.pluginName || "",
        port: Number(sc.port || sc.webPort || 0),
        host: sc.host || "127.0.0.1",
        token: sc.token || sc.uiToken || "",
        running: sc.running !== false && sc.status !== "stopped",
        disabled: Boolean(sc.disabled)
      }));
    }
  };
}

// src/adapters/antigravity/frame-adapter.js
var DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS = Object.freeze([
  "https://antigravity.google.com",
  "https://*.antigravity.google.com"
]);
function assertValidFrame(frame, allowedOrigins, label) {
  if (!frame || typeof frame !== "object") {
    throw new SecurityPolicyError("INVALID_FRAME", `Invalid ${label}: expected frame object.`);
  }
  assertOriginAllowed(frame.origin, allowedOrigins, label);
  if (!frame.win || !frame.doc) {
    throw new SecurityPolicyError(
      "INCOMPLETE_FRAME",
      `Invalid ${label}: frame must expose both win and doc.`
    );
  }
}
function createAntigravityFrameAdapter({
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  trustedTypesApi = globalThis.trustedTypes ?? null,
  policyName = "antigravity-remote-bridge-v1",
  hostLoadGuard = null,
  diagnostics = null,
  initialFrame = null
} = {}) {
  const ttPolicy = createScopedTrustedTypesPolicy({
    trustedTypesApi,
    policyName,
    validateScriptUrl: (url) => isTrustedWorkerOrScriptUrl(url, allowedOrigins)
  });
  const guardFn = typeof hostLoadGuard === "function" ? hostLoadGuard : null;
  const frameChain = new EventChain({
    hostGuard: null,
    diagnostics
  });
  let currentFrame = null;
  if (initialFrame !== null) {
    assertValidFrame(initialFrame, allowedOrigins, "initial remote frame");
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
        assertValidFrame(currentFrame, allowedOrigins, "active remote frame");
      }
      return currentFrame;
    },
    onFrameChange(handler) {
      return frameChain.register(handler, { label: "frame-change" });
    },
    notifyFramePromoted(nextFrame) {
      if (nextFrame !== null) {
        assertValidFrame(nextFrame, allowedOrigins, "promoted frame");
      }
      return applyAndDispatchFrame(nextFrame);
    },
    /**
     * Promotes an accessible remote iframe element into a validated frame descriptor
     * (`{ win, doc, origin, iframeEl }`). Translates cross-origin DOMException into
     * `CROSS_ORIGIN_IFRAME_DENIED` and cross-checks `targetOrigin` against actual
     * `iframe.contentWindow.location.origin`.
     */
    promoteRemoteIframe(iframeEl, { targetOrigin = "", conversationId = "" } = {}) {
      if (!iframeEl || typeof iframeEl !== "object") {
        throw new SecurityPolicyError("INVALID_IFRAME", "An iframe element is required for promotion.");
      }
      let win;
      let doc;
      let actualOrigin;
      try {
        win = iframeEl.contentWindow;
        actualOrigin = win?.location?.origin || "";
        doc = iframeEl.contentDocument || win?.document;
      } catch (_err) {
        throw new SecurityPolicyError(
          "CROSS_ORIGIN_IFRAME_DENIED",
          "Cannot access cross-origin iframe document without host-sanctioned promotion."
        );
      }
      if (!win || !doc) {
        throw new SecurityPolicyError(
          "UNAVAILABLE_IFRAME_DOCUMENT",
          "Remote iframe does not expose an accessible contentWindow/contentDocument."
        );
      }
      if (!actualOrigin || actualOrigin === "null") {
        throw new SecurityPolicyError(
          "UNAVAILABLE_IFRAME_ORIGIN",
          "Remote iframe does not expose a verifiable origin."
        );
      }
      const resolvedOrigin = targetOrigin || actualOrigin;
      assertOriginAllowed(resolvedOrigin, allowedOrigins, "remote iframe");
      if (targetOrigin) {
        const expectedNorm = normalizeOrigin(targetOrigin);
        const actualNorm = normalizeOrigin(actualOrigin);
        if (!expectedNorm || !actualNorm || expectedNorm.origin !== actualNorm.origin) {
          throw new SecurityPolicyError(
            "ORIGIN_MISMATCH",
            "Supplied targetOrigin does not match the actual accessible iframe origin."
          );
        }
      }
      const promoted = {
        win,
        doc,
        origin: resolvedOrigin,
        iframeEl,
        conversationId
      };
      const dispatchResult = applyAndDispatchFrame(promoted);
      return dispatchResult.allowed ? promoted : null;
    },
    createSafeWorkerBlobUrl({ scriptUrl, createBlobUrl }) {
      return createGuardedWorkerBlobUrl({
        scriptUrl,
        allowlist: allowedOrigins,
        createBlobUrl,
        trustedTypesPolicy: ttPolicy
      });
    }
  };
}

// src/adapters/antigravity/sidecar-adapter.js
function assertLoopbackSidecar(sidecar) {
  if (!sidecar || typeof sidecar !== "object") {
    throw new SecurityPolicyError("INVALID_SIDECAR", "Sidecar descriptor is required.");
  }
  const rawHost = sidecar.host || "127.0.0.1";
  if (!isLoopbackHostname(rawHost)) {
    throw new SecurityPolicyError(
      "NON_LOOPBACK_SIDECAR",
      "Sidecar relay only permits loopback (127.0.0.1 / localhost / ::1) sidecar servers."
    );
  }
  const host = formatHostForUrl(rawHost);
  const port = Number(sidecar.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SecurityPolicyError("INVALID_SIDECAR_PORT", "Sidecar port must be a valid TCP port.");
  }
  return { host, port };
}
function createAntigravitySidecarAdapter({
  fetchImpl = typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : void 0
} = {}) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("AntigravitySidecarAdapter requires a fetch implementation.");
  }
  return {
    /**
     * Builds the loopback sidecar UI URL without embedding secrets in query parameters.
     * Authentication tokens are sent strictly via the `X-Sidecar-Token` request header.
     */
    buildUiUrl({ sidecar, conversationId = "" }) {
      const { host, port } = assertLoopbackSidecar(sidecar);
      const url = new URL(`http://${host}:${port}/`);
      if (conversationId) {
        url.searchParams.set("conversationId", String(conversationId));
      }
      return url.toString();
    },
    async requestJson({ sidecar, path, method = "POST", body = {} }) {
      const { host, port } = assertLoopbackSidecar(sidecar);
      if (typeof path !== "string" || !path.startsWith("/")) {
        throw new SecurityPolicyError("INVALID_API_PATH", 'Sidecar API path must start with "/".');
      }
      const headers = { "Content-Type": "application/json" };
      if (sidecar.token) {
        headers["X-Sidecar-Token"] = String(sidecar.token);
      }
      const response = await fetchImpl(`http://${host}:${port}${path}`, {
        method: method.toUpperCase(),
        headers,
        body: method.toUpperCase() === "GET" ? void 0 : JSON.stringify(body)
      });
      if (!response.ok) {
        throw new Error(`Sidecar API ${path} failed with HTTP ${response.status}`);
      }
      return response.json();
    }
  };
}

// src/adapters/antigravity/settings-adapter.js
var DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER = "google-translate";
var TRANSLATOR_PLUGIN_NAMES = /* @__PURE__ */ new Set([
  "antigravity-ko-translator",
  "ko-thought-translator"
]);
var ALLOWED_TRANSLATOR_SETTING_KEYS = Object.freeze([
  "enabled",
  "translateThinking",
  "translateStaticUi",
  "provider",
  "customEndpoint"
]);
function sanitizeTranslatorSettings(rawSettings, { remoteFallbackProvider = DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER } = {}) {
  const input = rawSettings && typeof rawSettings === "object" ? rawSettings : {};
  const sanitized = {
    enabled: input.enabled !== false,
    translateThinking: input.translateThinking !== false,
    translateStaticUi: input.translateStaticUi !== false,
    provider: typeof input.provider === "string" && input.provider.trim() ? input.provider.trim() : remoteFallbackProvider,
    customEndpoint: null
  };
  if (typeof input.customEndpoint === "string" && input.customEndpoint.trim()) {
    try {
      const parsed = new URL(input.customEndpoint.trim());
      if (parsed.protocol === "https:" && !parsed.username && !parsed.password) {
        sanitized.customEndpoint = parsed.toString();
      }
    } catch (_err) {
      sanitized.customEndpoint = null;
    }
  }
  const lowerProvider = sanitized.provider.toLowerCase();
  if (lowerProvider === "local-llm" || lowerProvider === "custom-https" && !sanitized.customEndpoint) {
    sanitized.provider = sanitized.customEndpoint ? "custom-https" : remoteFallbackProvider;
  }
  const locked = {};
  for (const key of ALLOWED_TRANSLATOR_SETTING_KEYS) {
    locked[key] = sanitized[key];
  }
  return Object.freeze(locked);
}
function sanitizeGenericSettings(rawSettings) {
  if (!rawSettings || typeof rawSettings !== "object" || Array.isArray(rawSettings)) {
    return Object.freeze({});
  }
  return stripSensitiveDeep(rawSettings) || Object.freeze({});
}
function createAntigravitySettingsAdapter({
  readSettingsFile,
  remoteFallbackProvider = DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER
} = {}) {
  if (typeof readSettingsFile !== "function") {
    throw new TypeError("AntigravitySettingsAdapter requires a readSettingsFile callback.");
  }
  return {
    async readPluginSettings(pluginName) {
      const raw = await readSettingsFile(pluginName);
      if (TRANSLATOR_PLUGIN_NAMES.has(String(pluginName || "").trim())) {
        return sanitizeTranslatorSettings(raw, { remoteFallbackProvider });
      }
      return sanitizeGenericSettings(raw);
    }
  };
}

// src/adapters/antigravity/theme-workspace-adapter.js
function createAntigravityThemeWorkspaceAdapter({
  initialThemeVariables = {},
  initialWorkspaceUris = []
} = {}) {
  let themeVariables = { ...initialThemeVariables || {} };
  let workspaceUris = Array.isArray(initialWorkspaceUris) ? [...initialWorkspaceUris] : [];
  const listeners = /* @__PURE__ */ new Set();
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
      if (typeof listener !== "function") {
        throw new TypeError("ThemeWorkspaceSyncPort listener must be a function.");
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    updateTheme(nextVariables) {
      themeVariables = { ...nextVariables || {} };
      notify({ type: "theme-change", cssVariables: { ...themeVariables } });
    },
    updateWorkspaces(nextUris) {
      workspaceUris = Array.isArray(nextUris) ? [...nextUris] : [];
      notify({ type: "workspace-change", workspaceUris: [...workspaceUris] });
    }
  };
}

// src/runtime/bootstrap.js
var ANTIGRAVITY_STATUSBAR_API_PATHS = Object.freeze([
  "/api/telemetry",
  "/api/context-limit",
  "/api/compact"
]);
var ANTIGRAVITY_SIDECAR_INBOUND_EVENTS = Object.freeze([
  "sidecar-key-event",
  "toggle-aux-pane",
  "toggle-conversation",
  "add-artifact-comment",
  "request-credential-refresh"
]);
var ANTIGRAVITY_PROTECTED_MCP_PATHS = Object.freeze([
  /(?:^|\/)\.gemini\/config\/config\.json$/i,
  /(?:^|\/)\.gemini\/config\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/antigravity\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/config\/plugins\/[^/]+\/mcp_config\.json$/i,
  /(?:^|\/)\.gemini\/config\/plugins\/[^/]+\/config\.json$/i
]);
function bootstrapAntigravityRemoteBridge({
  lsAddress,
  csrfToken,
  fetchImpl = typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : void 0,
  trustedTypesApi = globalThis.trustedTypes ?? null,
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  readSettingsFile = async () => ({}),
  createKoTranslator = null,
  mcpDelegate = null,
  initialFrame = null,
  initialThemeVariables = {},
  initialWorkspaceUris = [],
  hostLoadGuard = null,
  onSidecarEvent = null
}) {
  const diagnostics = new DiagnosticsBus();
  const discoveryPort = createAntigravityDiscoveryAdapter({
    lsAddress,
    csrfToken,
    fetchImpl
  });
  const framePort = createAntigravityFrameAdapter({
    allowedOrigins,
    trustedTypesApi,
    hostLoadGuard,
    diagnostics,
    initialFrame
  });
  const sidecarRelayPort = createAntigravitySidecarAdapter({ fetchImpl });
  const settingsPort = createAntigravitySettingsAdapter({
    readSettingsFile,
    remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER
  });
  const themeWorkspacePort = createAntigravityThemeWorkspaceAdapter({
    initialThemeVariables,
    initialWorkspaceUris
  });
  const orchestrator = new RemoteOrchestrator({
    discoveryPort,
    framePort,
    diagnostics
  });
  const bridges = {};
  if (typeof createKoTranslator === "function") {
    const koBridge = createDomOverlayBridge({
      id: "ko-translator-overlay",
      pluginName: "antigravity-ko-translator",
      pluginAliases: ["ko-thought-translator"],
      createOverlay: createKoTranslator,
      settingsPort,
      sanitizeSettings: (raw) => sanitizeTranslatorSettings(raw, {
        remoteFallbackProvider: DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER
      })
    });
    orchestrator.registerBridge(koBridge);
    bridges.koTranslator = koBridge;
  }
  const statusbarBridge = createSidecarUiBridge({
    id: "statusbar-sidecar",
    pluginName: "antigravity-statusbar",
    sidecarId: "antigravity-statusbar/statusbar",
    relayPort: sidecarRelayPort,
    themeWorkspacePort,
    allowedOrigins: [],
    allowedApiPaths: ANTIGRAVITY_STATUSBAR_API_PATHS,
    allowedInboundEvents: ANTIGRAVITY_SIDECAR_INBOUND_EVENTS,
    onInboundEvent: onSidecarEvent
  });
  orchestrator.registerBridge(statusbarBridge);
  bridges.statusbar = statusbarBridge;
  const mcpSlot = createMcpExtensionSlot({
    id: "mcp-manager-slot",
    pluginName: "antigravity-mcp-manager",
    protectedConfigPatterns: ANTIGRAVITY_PROTECTED_MCP_PATHS,
    delegate: mcpDelegate
  });
  orchestrator.registerBridge(mcpSlot);
  bridges.mcpManager = mcpSlot;
  return {
    orchestrator,
    diagnostics,
    framePort,
    themeWorkspacePort,
    bridges
  };
}

// src/runtime/desktop-addon-runtime.js
var DESKTOP_SETTINGS_SLOT_ID = "antigravity-remote-plugin.settings";
function mountDesktopAddon(addonHost, {
  doc = globalThis.document,
  clipboard = globalThis.navigator?.clipboard ?? null,
  remoteArtifacts = {
    bookmarklet: "dist/bookmarklet.txt",
    userscriptPath: "dist/antigravity-remote.user.js"
  },
  initialLocale = "ko",
  diagnostics = null
} = {}) {
  const surface = createAddonHostSurfaceAdapter(addonHost, { diagnostics });
  const view = mountDesktopCompanionView({
    doc,
    surface,
    slotId: DESKTOP_SETTINGS_SLOT_ID,
    hostInfo: {
      hostProfileId: surface.hostProfileId,
      hostVersion: surface.hostVersion
    },
    remoteArtifacts,
    clipboard,
    initialLocale
  });
  return Object.freeze({
    pluginId: surface.pluginId,
    slotId: DESKTOP_SETTINGS_SLOT_ID,
    surface,
    view,
    dispose() {
      surface.dispose();
    }
  });
}

// src/runtime/remote-web-runtime.js
var REMOTE_HOST_VERSION = "2.0.0";
var mountedHostsByWindow = /* @__PURE__ */ new WeakMap();
function mountRemotePluginHost({
  win = globalThis.window,
  doc = globalThis.document,
  allowedOrigins = DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  initialLocale = "ko",
  ownerId = "antigravity-remote-plugin"
} = {}) {
  if (!win || !doc) {
    return null;
  }
  const currentOrigin = win.location?.origin || "";
  if (!isOriginAllowed(currentOrigin, allowedOrigins)) {
    return null;
  }
  const existing = mountedHostsByWindow.get(win);
  if (existing) {
    existing.toggleDock();
    return existing.publicApi;
  }
  const existingDesc = Object.getOwnPropertyDescriptor(win, "antigravityRemoteHost");
  if (existingDesc && existingDesc.writable === false && existingDesc.enumerable === false && existingDesc.value && existingDesc.value.contractVersion === REMOTE_PLUGIN_CONTRACT_VERSION && typeof existingDesc.value.toggleDock === "function") {
    existingDesc.value.toggleDock();
    return existingDesc.value;
  }
  const diagnostics = new DiagnosticsBus();
  const registry = new RemotePluginRegistry({ diagnostics });
  const surface = createShadowSurfaceAdapter({ doc, ownerId, diagnostics });
  const renderer = createDeclarativeSlotRenderer({
    win,
    doc,
    surface,
    registry,
    initialLocale
  });
  const activePortBridges = /* @__PURE__ */ new Set();
  const handshake = createPluginHandshakeHost({
    win,
    allowedOrigins,
    onPortConnected({ port, origin, pluginId, close }) {
      diagnostics.emit({
        level: "info",
        code: "REMOTE_PLUGIN_HANDSHAKE_CONNECTED",
        source: "runtime.remote-web",
        message: "Closed MessageChannel handshake established",
        detail: { origin, pluginId }
      });
      const bridge = attachRemotePluginPortBridge({
        port,
        registry,
        diagnostics,
        onClose() {
          activePortBridges.delete(bridge);
          close();
        }
      });
      activePortBridges.add(bridge);
    }
  });
  let disposed = false;
  const publicApi = Object.freeze({
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    version: REMOTE_HOST_VERSION,
    register(plugin) {
      if (disposed) {
        return () => {
        };
      }
      return registry.register(plugin, { locale: renderer.getLocale() });
    },
    listSlots() {
      return Object.freeze([...ALLOWED_UI_SLOTS]);
    },
    toggleDock() {
      if (!disposed) {
        renderer.toggleOpen();
      }
    },
    setLocale(locale) {
      if (disposed) {
        return Promise.resolve();
      }
      return renderer.setLocale(locale);
    },
    getLocale() {
      return renderer.getLocale();
    }
  });
  const dispose = () => {
    if (disposed) {
      return;
    }
    disposed = true;
    mountedHostsByWindow.delete(win);
    for (const bridge of [...activePortBridges]) {
      bridge.close();
    }
    activePortBridges.clear();
    handshake.dispose();
    registry.dispose();
    surface.dispose();
    if (win.antigravityRemoteHost === publicApi) {
      delete win.antigravityRemoteHost;
    }
  };
  const controller = Object.freeze({
    publicApi,
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    version: REMOTE_HOST_VERSION,
    register: publicApi.register,
    listSlots: publicApi.listSlots,
    listPlugins() {
      return registry.list();
    },
    toggleDock: publicApi.toggleDock,
    setOpen(open) {
      if (!disposed) {
        renderer.setOpen(open);
      }
    },
    isOpen() {
      return renderer.isOpen();
    },
    setLocale: publicApi.setLocale,
    getLocale: publicApi.getLocale,
    activePortCount() {
      return handshake.activePortCount();
    },
    dispose
  });
  mountedHostsByWindow.set(win, controller);
  Object.defineProperty(win, "antigravityRemoteHost", {
    value: publicApi,
    writable: false,
    enumerable: false,
    configurable: true
  });
  return controller;
}

// virtual-remote-bridge-entry.js
var BUILD_VERSION = "2.0.0";
export {
  ALLOWED_CAPABILITIES,
  ALLOWED_UI_SLOTS,
  ANTIGRAVITY_PROTECTED_MCP_PATHS,
  ANTIGRAVITY_SIDECAR_INBOUND_EVENTS,
  ANTIGRAVITY_STATUSBAR_API_PATHS,
  AsyncMutex,
  BUILD_VERSION,
  DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
  DESKTOP_SETTINGS_SLOT_ID,
  DiagnosticsBus,
  DisposableStore,
  EventChain,
  HANDSHAKE_ACK_TYPE,
  HANDSHAKE_CHALLENGE_TYPE,
  HANDSHAKE_PROTOCOL_TYPE,
  HANDSHAKE_REQUEST_TYPE,
  PORT_CONTRACTS,
  PORT_MSG,
  REDACTED,
  REMOTE_HOST_VERSION,
  REMOTE_PLUGIN_CONTRACT_VERSION,
  RESERVED_TRUSTED_TYPES_POLICIES,
  RemoteOrchestrator,
  RemotePluginRegistry,
  SecurityPolicyError,
  SingleFlight,
  assertAllowedPolicyName,
  assertOriginAllowed,
  assertPort,
  assertRemoteMcpMutationAllowed,
  assertSafeAttribute,
  assertSafeLocalizedText,
  assertSafeTagName,
  assertSafeText,
  assertTrustedScriptUrl,
  assertWritableConfigPath,
  attachRemotePluginPortBridge,
  bootstrapAntigravityRemoteBridge,
  canonicalizeConfigPath,
  connectPluginHandshake,
  createAddonHostSurfaceAdapter,
  createAntigravityDiscoveryAdapter,
  createAntigravityFrameAdapter,
  createAntigravitySettingsAdapter,
  createAntigravitySidecarAdapter,
  createAntigravityThemeWorkspaceAdapter,
  createDeclarativeSlotRenderer,
  createDomOverlayBridge,
  createGuardedWorkerBlobUrl,
  createMcpExtensionSlot,
  createPluginHandshakeHost,
  createSafeElement,
  createScopedTrustedTypesPolicy,
  createShadowSurfaceAdapter,
  createSidecarUiBridge,
  deepFreeze,
  deriveSidecarOrigin,
  formatHostForUrl,
  generateHandshakeNonce,
  initiatePluginHandshake,
  isLoopbackHostname,
  isOriginAllowed,
  isSensitiveKey,
  isTrustedBlobUrl,
  isTrustedScriptUrl,
  isTrustedWorkerOrScriptUrl,
  matchesDomainBoundary,
  mountDesktopAddon,
  mountDesktopCompanionView,
  mountRemotePluginHost,
  normalizeOrigin,
  redactSecrets,
  redactUrl,
  resolveLocalizedText,
  sanitizeTranslatorSettings,
  serveRemotePluginOverPort,
  stripSensitiveDeep,
  stripSensitiveSettings,
  validateActionInvocation,
  validateActionResult,
  validateBridgeDescriptor,
  validateDiscoveryPort,
  validateFramePromotionPort,
  validateHostSurfacePort,
  validatePluginSnapshot,
  validateRemotePlugin,
  validateSettingsReadPort,
  validateSidecarRelayPort,
  validateThemeWorkspaceSyncPort
};
