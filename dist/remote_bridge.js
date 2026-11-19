// antigravity-remote-plugin v1.1.0 — standalone self-contained ESM bundle
// Built deterministically with esbuild from 18 source modules.

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
  ExtensionBridgePort: Object.freeze(["id", "pluginName", "mount", "dispose"])
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

// virtual-remote-bridge-entry.js
var BUILD_VERSION = "1.1.0";
export {
  ANTIGRAVITY_PROTECTED_MCP_PATHS,
  ANTIGRAVITY_SIDECAR_INBOUND_EVENTS,
  ANTIGRAVITY_STATUSBAR_API_PATHS,
  AsyncMutex,
  BUILD_VERSION,
  DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS,
  DEFAULT_ANTIGRAVITY_REMOTE_TRANSLATOR_PROVIDER,
  DiagnosticsBus,
  DisposableStore,
  EventChain,
  PORT_CONTRACTS,
  REDACTED,
  RESERVED_TRUSTED_TYPES_POLICIES,
  RemoteOrchestrator,
  SecurityPolicyError,
  SingleFlight,
  assertAllowedPolicyName,
  assertOriginAllowed,
  assertPort,
  assertRemoteMcpMutationAllowed,
  assertSafeAttribute,
  assertSafeTagName,
  assertTrustedScriptUrl,
  assertWritableConfigPath,
  bootstrapAntigravityRemoteBridge,
  canonicalizeConfigPath,
  createAntigravityDiscoveryAdapter,
  createAntigravityFrameAdapter,
  createAntigravitySettingsAdapter,
  createAntigravitySidecarAdapter,
  createAntigravityThemeWorkspaceAdapter,
  createDomOverlayBridge,
  createGuardedWorkerBlobUrl,
  createMcpExtensionSlot,
  createSafeElement,
  createScopedTrustedTypesPolicy,
  createSidecarUiBridge,
  deepFreeze,
  deriveSidecarOrigin,
  formatHostForUrl,
  isLoopbackHostname,
  isOriginAllowed,
  isSensitiveKey,
  isTrustedBlobUrl,
  isTrustedScriptUrl,
  isTrustedWorkerOrScriptUrl,
  matchesDomainBoundary,
  normalizeOrigin,
  redactSecrets,
  redactUrl,
  sanitizeTranslatorSettings,
  stripSensitiveDeep,
  stripSensitiveSettings,
  validateBridgeDescriptor,
  validateDiscoveryPort,
  validateFramePromotionPort,
  validateSettingsReadPort,
  validateSidecarRelayPort,
  validateThemeWorkspaceSyncPort
};
