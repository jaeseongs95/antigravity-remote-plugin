// ==UserScript==
// @name         Antigravity Remote Companion
// @namespace    https://github.com/jaeseongs95/antigravity-remote-plugin
// @version      2.0.0
// @description  Cross-device (iOS/Android/Desktop) remote web companion for Antigravity ko-translator, statusbar, and mcp-manager.
// @author       jaeseongs95
// @match        https://antigravity.google.com/*
// @match        https://*.antigravity.google.com/*
// @grant        GM_xmlhttpRequest
// @connect      translate.googleapis.com
// @run-at       document-idle
// ==/UserScript==
(() => {
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

  // src/bridges/remote-translator-engine.js
  var EXCLUDED_TAGS = /* @__PURE__ */ new Set([
    "SCRIPT",
    "STYLE",
    "NOSCRIPT",
    "PRE",
    "CODE",
    "KBD",
    "SAMP",
    "TEXTAREA",
    "INPUT",
    "SELECT",
    "OPTION",
    "SVG",
    "CANVAS",
    "IFRAME"
  ]);
  var PROTECTED_SPAN_PATTERN = /(`[^`\n]+`|https?:\/\/[^\s)]+|(?:[a-zA-Z]:\\|\/(?:[a-zA-Z0-9._-]+\/)+)[a-zA-Z0-9._-]+)/g;
  var LATIN_LETTER_PATTERN = /[A-Za-z]{2,}/;
  var MAX_CACHE_ENTRIES = 500;
  var MAX_CONCURRENCY = 4;
  function protectTechnicalTokens(text) {
    const tokens = [];
    const masked = String(text).replace(PROTECTED_SPAN_PATTERN, (match) => {
      const idx = tokens.length;
      tokens.push(match);
      return `__TOK${idx}__`;
    });
    return { masked, tokens };
  }
  function restoreTechnicalTokens(translatedText, tokens) {
    let out = String(translatedText);
    for (let i = 0; i < tokens.length; i += 1) {
      out = out.split(`__TOK${i}__`).join(tokens[i]);
    }
    return out;
  }
  function isExcludedElement(el) {
    let cur = el;
    while (cur && cur.nodeType === 1) {
      const tag = typeof cur.tagName === "string" ? cur.tagName.toUpperCase() : "";
      if (EXCLUDED_TAGS.has(tag)) {
        return true;
      }
      if (typeof cur.getAttribute === "function") {
        if (cur.getAttribute("data-remote-dock-ignore") === "true") {
          return true;
        }
        const ce = cur.getAttribute("contenteditable");
        if (ce === "" || ce === "true") {
          return true;
        }
        if (cur.getAttribute("role") === "textbox") {
          return true;
        }
      }
      const cls = typeof cur.className === "string" ? cur.className : "";
      if (/\b(?:xterm|monaco-editor|cm-editor|diff-line|code-block)\b/.test(cls)) {
        return true;
      }
      cur = cur.parentElement || cur.parentNode;
    }
    return false;
  }
  function collectTranslatableTextNodes(root) {
    const result = [];
    if (!root) {
      return result;
    }
    const walk = (node) => {
      if (!node) {
        return;
      }
      if (node.nodeType === 3) {
        const val = typeof node.nodeValue === "string" ? node.nodeValue : "";
        if (val.trim().length >= 2 && LATIN_LETTER_PATTERN.test(val)) {
          if (!isExcludedElement(node.parentElement || node.parentNode)) {
            result.push(node);
          }
        }
        return;
      }
      if (node.nodeType === 1) {
        if (isExcludedElement(node)) {
          return;
        }
        const children = node.childNodes || [];
        for (let i = 0; i < children.length; i += 1) {
          walk(children[i]);
        }
      }
    };
    walk(root);
    return result;
  }
  function createRemoteTranslatorEngine({
    win,
    doc,
    settings = {},
    translateText,
    onStatus = null
  } = {}) {
    if (!win || !doc) {
      throw new SecurityPolicyError("INCOMPLETE_FRAME", "Remote translator requires win and doc.");
    }
    if (typeof translateText !== "function") {
      throw new TypeError("Remote translator requires a translateText(text, opts) function.");
    }
    let currentSettings = {
      enabled: settings.enabled !== false,
      targetLang: typeof settings.targetLang === "string" && settings.targetLang.trim() ? settings.targetLang.trim() : "ko"
    };
    const originals = /* @__PURE__ */ new Map();
    const cache = /* @__PURE__ */ new Map();
    const pendingNodes = /* @__PURE__ */ new Set();
    let observer = null;
    let abortController = null;
    let active = false;
    let translatedCount = 0;
    let errorCount = 0;
    let inFlight = 0;
    const queue = [];
    function emitStatus(phase, lastError = null) {
      if (typeof onStatus === "function") {
        onStatus({
          enabled: currentSettings.enabled,
          active,
          phase,
          translatedCount,
          errorCount,
          lastError
        });
      }
    }
    function cacheSet(key, val) {
      if (cache.size >= MAX_CACHE_ENTRIES) {
        const oldestKey = cache.keys().next().value;
        if (oldestKey !== void 0) {
          cache.delete(oldestKey);
        }
      }
      cache.set(key, val);
    }
    function restoreAllOriginals() {
      for (const [node, originalText] of originals.entries()) {
        if (node && typeof node.nodeValue === "string") {
          node.nodeValue = originalText;
        }
      }
      originals.clear();
      pendingNodes.clear();
      translatedCount = 0;
    }
    function pumpQueue() {
      while (active && currentSettings.enabled && inFlight < MAX_CONCURRENCY && queue.length > 0) {
        const node = queue.shift();
        if (!node || !pendingNodes.has(node)) {
          continue;
        }
        inFlight += 1;
        void processNode(node).finally(() => {
          inFlight -= 1;
          pumpQueue();
        });
      }
    }
    async function processNode(node) {
      const signal = abortController?.signal;
      if (!active || !currentSettings.enabled || signal?.aborted) {
        pendingNodes.delete(node);
        return;
      }
      const raw = typeof node.nodeValue === "string" ? node.nodeValue : "";
      const trimmed = raw.trim();
      if (trimmed.length < 2 || !LATIN_LETTER_PATTERN.test(trimmed)) {
        pendingNodes.delete(node);
        return;
      }
      const leadingWs = raw.match(/^\s*/)?.[0] || "";
      const trailingWs = raw.match(/\s*$/)?.[0] || "";
      const cacheKey = `${currentSettings.targetLang}:${trimmed}`;
      try {
        let translated = cache.get(cacheKey);
        if (translated === void 0) {
          const { masked, tokens } = protectTechnicalTokens(trimmed);
          const translatedMasked = await translateText(masked, {
            targetLang: currentSettings.targetLang,
            signal
          });
          if (!active || !currentSettings.enabled || signal?.aborted) {
            pendingNodes.delete(node);
            return;
          }
          translated = restoreTechnicalTokens(translatedMasked, tokens);
          cacheSet(cacheKey, translated);
        }
        if (!originals.has(node)) {
          originals.set(node, raw);
        }
        node.nodeValue = `${leadingWs}${translated}${trailingWs}`;
        translatedCount = originals.size;
        emitStatus("translated");
      } catch (err) {
        if (err?.name !== "AbortError") {
          errorCount += 1;
          emitStatus("error", String(err?.message || "Translation failed"));
        }
      } finally {
        pendingNodes.delete(node);
      }
    }
    function enqueueRoot(root) {
      if (!active || !currentSettings.enabled || !root) {
        return;
      }
      const nodes = collectTranslatableTextNodes(root);
      for (const node of nodes) {
        if (originals.has(node) || pendingNodes.has(node)) {
          continue;
        }
        pendingNodes.add(node);
        queue.push(node);
      }
      pumpQueue();
    }
    function startObserver() {
      const ObserverCtor = win.MutationObserver || globalThis.MutationObserver;
      if (typeof ObserverCtor !== "function" || !doc.body) {
        return;
      }
      observer = new ObserverCtor((mutations) => {
        if (!active || !currentSettings.enabled) {
          return;
        }
        for (const mutation of mutations) {
          if (mutation.type === "childList") {
            for (const added of mutation.addedNodes || []) {
              enqueueRoot(added);
            }
          }
        }
      });
      observer.observe(doc.body, { childList: true, subtree: true });
    }
    function stopObserver() {
      if (observer) {
        observer.disconnect();
        observer = null;
      }
    }
    return {
      start() {
        if (active) {
          return;
        }
        active = true;
        abortController = new AbortController();
        if (currentSettings.enabled) {
          startObserver();
          enqueueRoot(doc.body || doc.documentElement);
          emitStatus("running");
        } else {
          emitStatus("paused");
        }
      },
      updateSettings(nextSettings = {}) {
        const nextEnabled = nextSettings.enabled !== void 0 ? Boolean(nextSettings.enabled) : currentSettings.enabled;
        const nextLang = typeof nextSettings.targetLang === "string" && nextSettings.targetLang.trim() ? nextSettings.targetLang.trim() : currentSettings.targetLang;
        const langChanged = nextLang !== currentSettings.targetLang;
        currentSettings = { enabled: nextEnabled, targetLang: nextLang };
        if (!active) {
          return;
        }
        if (!currentSettings.enabled) {
          stopObserver();
          queue.length = 0;
          if (abortController) {
            abortController.abort();
            abortController = new AbortController();
          }
          restoreAllOriginals();
          emitStatus("paused");
          return;
        }
        if (langChanged) {
          restoreAllOriginals();
        }
        if (!observer) {
          startObserver();
        }
        enqueueRoot(doc.body || doc.documentElement);
        emitStatus("running");
      },
      getStats() {
        return {
          enabled: currentSettings.enabled,
          active,
          translatedCount,
          errorCount
        };
      },
      dispose() {
        active = false;
        stopObserver();
        queue.length = 0;
        if (abortController) {
          abortController.abort();
          abortController = null;
        }
        restoreAllOriginals();
        emitStatus("disposed");
      }
    };
  }

  // src/security/trusted-types.js
  var RESERVED_TRUSTED_TYPES_POLICIES = Object.freeze([
    "default",
    "dompurify",
    "angular"
  ]);

  // src/adapters/antigravity/frame-adapter.js
  var DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS = Object.freeze([
    "https://antigravity.google.com",
    "https://*.antigravity.google.com"
  ]);

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

  // src/adapters/antigravity/remote-dock-ui.js
  var DOCK_STYLE_ID = "arp-remote-dock-style-v2";
  var DOCK_ROOT_ID = "arp-remote-dock-root-v2";
  var DOCK_CSS = [
    `#${DOCK_ROOT_ID} { position: fixed; right: max(12px, env(safe-area-inset-right)); bottom: max(14px, env(safe-area-inset-bottom)); z-index: 2147483000; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; color-scheme: light dark; }`,
    `#${DOCK_ROOT_ID} * { box-sizing: border-box; }`,
    `#${DOCK_ROOT_ID} .arp-pill { min-width: 44px; min-height: 44px; padding: 0 14px; border-radius: 999px; border: 1px solid rgba(128, 134, 139, 0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); font-size: 13px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 6px 20px rgba(0, 0, 0, 0.28); touch-action: manipulation; }`,
    `#${DOCK_ROOT_ID} .arp-dot { width: 8px; height: 8px; border-radius: 50%; background: #34a853; flex-shrink: 0; }`,
    `#${DOCK_ROOT_ID} .arp-dot[data-off="true"] { background: #9aa0a6; }`,
    `#${DOCK_ROOT_ID} .arp-popover { position: absolute; right: 0; bottom: 54px; width: min(320px, calc(100vw - 24px)); max-height: calc(100vh - 96px); overflow-y: auto; border-radius: 14px; border: 1px solid rgba(128, 134, 139, 0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); padding: 14px; box-shadow: 0 12px 32px rgba(0, 0, 0, 0.36); display: flex; flex-direction: column; gap: 10px; }`,
    `#${DOCK_ROOT_ID} .arp-popover[hidden] { display: none; }`,
    `#${DOCK_ROOT_ID} .arp-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; }`,
    `#${DOCK_ROOT_ID} .arp-title { margin: 0; font-size: 14px; font-weight: 700; }`,
    `#${DOCK_ROOT_ID} .arp-close { min-width: 44px; min-height: 44px; border-radius: 10px; border: 1px solid rgba(128, 134, 139, 0.3); background: transparent; color: inherit; font-size: 16px; cursor: pointer; touch-action: manipulation; }`,
    `#${DOCK_ROOT_ID} .arp-section { border-radius: 10px; border: 1px solid rgba(128, 134, 139, 0.24); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
    `#${DOCK_ROOT_ID} .arp-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }`,
    `#${DOCK_ROOT_ID} .arp-label { font-size: 13px; font-weight: 600; }`,
    `#${DOCK_ROOT_ID} .arp-meta { font-size: 12px; opacity: 0.78; }`,
    `#${DOCK_ROOT_ID} .arp-btn { min-height: 44px; padding: 8px 12px; border-radius: 10px; border: 1px solid rgba(128, 134, 139, 0.35); background: rgba(128, 134, 139, 0.14); color: inherit; font-size: 13px; font-weight: 600; cursor: pointer; touch-action: manipulation; }`,
    `#${DOCK_ROOT_ID} .arp-btn[data-active="true"] { background: #1a73e8; border-color: #1a73e8; color: #ffffff; }`,
    `#${DOCK_ROOT_ID} .arp-pill:focus-visible, #${DOCK_ROOT_ID} .arp-close:focus-visible, #${DOCK_ROOT_ID} .arp-btn:focus-visible { outline: 2px solid #4d90fe; outline-offset: 2px; }`,
    `@media (prefers-color-scheme: light) { #${DOCK_ROOT_ID} .arp-pill, #${DOCK_ROOT_ID} .arp-popover { background: var(--card, #ffffff); color: var(--foreground, #1f2328); } }`
  ].join(" ");
  function createRemoteDockUi({
    win,
    doc,
    initialTranslateEnabled = true,
    onToggleTranslation,
    onOpenSidecar
  } = {}) {
    const existing = doc.getElementById(DOCK_ROOT_ID);
    if (existing && typeof existing.remove === "function") {
      existing.remove();
    }
    let styleEl = doc.getElementById(DOCK_STYLE_ID);
    if (!styleEl) {
      styleEl = doc.createElement("style");
      styleEl.id = DOCK_STYLE_ID;
      styleEl.textContent = DOCK_CSS;
      (doc.head || doc.documentElement).appendChild(styleEl);
    }
    let isOpen = false;
    let translateEnabled = Boolean(initialTranslateEnabled);
    const root = createSafeElement(doc, "div", {
      attrs: { id: DOCK_ROOT_ID, "data-remote-dock-ignore": "true" }
    });
    const popover = createSafeElement(doc, "section", {
      attrs: {
        class: "arp-popover",
        role: "dialog",
        "aria-label": "Antigravity Remote Companion",
        hidden: "hidden"
      }
    });
    const header = createSafeElement(doc, "div", { attrs: { class: "arp-header" } });
    const title = createSafeElement(doc, "h2", {
      attrs: { class: "arp-title" },
      text: "Antigravity Remote"
    });
    const closeBtn = createSafeElement(doc, "button", {
      attrs: { type: "button", class: "arp-close", "aria-label": "\uB2EB\uAE30" },
      text: "\xD7"
    });
    header.appendChild(title);
    header.appendChild(closeBtn);
    popover.appendChild(header);
    const trSection = createSafeElement(doc, "div", { attrs: { class: "arp-section" } });
    const trRow = createSafeElement(doc, "div", { attrs: { class: "arp-row" } });
    const trLabel = createSafeElement(doc, "span", {
      attrs: { class: "arp-label" },
      text: "\uD55C\uAE00 \uBC88\uC5ED (ko-translator)"
    });
    const trToggleBtn = createSafeElement(doc, "button", {
      attrs: {
        type: "button",
        class: "arp-btn",
        id: "arp-toggle-translate",
        "data-active": translateEnabled ? "true" : "false",
        "aria-pressed": translateEnabled ? "true" : "false"
      },
      text: translateEnabled ? "\uCF1C\uC9D0" : "\uAEBC\uC9D0"
    });
    trRow.appendChild(trLabel);
    trRow.appendChild(trToggleBtn);
    const trStatus = createSafeElement(doc, "div", {
      attrs: { class: "arp-meta", id: "arp-translate-status", role: "status", "aria-live": "polite" },
      text: translateEnabled ? "\uC6D0\uACA9 \uD398\uC774\uC9C0 \uC2E4\uC2DC\uAC04 \uBC88\uC5ED \uD65C\uC131" : "\uC6D0\uBB38 \uD45C\uC2DC \uC911"
    });
    trSection.appendChild(trRow);
    trSection.appendChild(trStatus);
    popover.appendChild(trSection);
    const sidecarSection = createSafeElement(doc, "div", { attrs: { class: "arp-section" } });
    const sidecarLabel = createSafeElement(doc, "span", {
      attrs: { class: "arp-label" },
      text: "\uB3D9\uBC18 \uC0AC\uC774\uB4DC\uCE74 \uD328\uB110"
    });
    const sidecarRow = createSafeElement(doc, "div", { attrs: { class: "arp-row" } });
    const statusbarBtn = createSafeElement(doc, "button", {
      attrs: { type: "button", class: "arp-btn", id: "arp-open-statusbar" },
      text: "Statusbar \uC5F4\uAE30"
    });
    const mcpBtn = createSafeElement(doc, "button", {
      attrs: { type: "button", class: "arp-btn", id: "arp-open-mcp" },
      text: "MCP Manager \uC5F4\uAE30"
    });
    sidecarRow.appendChild(statusbarBtn);
    sidecarRow.appendChild(mcpBtn);
    const sidecarFeedback = createSafeElement(doc, "div", {
      attrs: { class: "arp-meta", id: "arp-sidecar-feedback", role: "status", "aria-live": "polite" },
      text: "Antigravity \uACF5\uC2DD AUX_PANE \uAC8C\uC774\uD2B8\uC6E8\uC774\uB85C \uC5F0\uACB0\uB429\uB2C8\uB2E4."
    });
    sidecarSection.appendChild(sidecarLabel);
    sidecarSection.appendChild(sidecarRow);
    sidecarSection.appendChild(sidecarFeedback);
    popover.appendChild(sidecarSection);
    const pillBtn = createSafeElement(doc, "button", {
      attrs: {
        type: "button",
        class: "arp-pill",
        id: "arp-dock-pill",
        "aria-expanded": "false",
        "aria-label": "Antigravity Remote \uBA54\uB274 \uC5F4\uAE30"
      }
    });
    const dot = createSafeElement(doc, "span", {
      attrs: { class: "arp-dot", "data-off": translateEnabled ? "false" : "true" }
    });
    const pillText = createSafeElement(doc, "span", { text: "Remote" });
    pillBtn.appendChild(dot);
    pillBtn.appendChild(pillText);
    root.appendChild(popover);
    root.appendChild(pillBtn);
    (doc.body || doc.documentElement).appendChild(root);
    function setOpen(nextOpen) {
      isOpen = Boolean(nextOpen);
      popover.hidden = !isOpen;
      pillBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      if (!isOpen && typeof pillBtn.focus === "function") {
        pillBtn.focus();
      }
    }
    function updateTranslateUi(enabled, statusText) {
      translateEnabled = Boolean(enabled);
      trToggleBtn.setAttribute("data-active", translateEnabled ? "true" : "false");
      trToggleBtn.setAttribute("aria-pressed", translateEnabled ? "true" : "false");
      trToggleBtn.textContent = translateEnabled ? "\uCF1C\uC9D0" : "\uAEBC\uC9D0";
      dot.setAttribute("data-off", translateEnabled ? "false" : "true");
      if (typeof statusText === "string") {
        trStatus.textContent = statusText;
      }
    }
    const onPillClick = () => setOpen(!isOpen);
    const onCloseClick = () => setOpen(false);
    const onTranslateClick = () => {
      const next = !translateEnabled;
      updateTranslateUi(next, next ? "\uBC88\uC5ED \uC801\uC6A9 \uC911..." : "\uC6D0\uBB38\uC73C\uB85C \uBCF5\uC6D0\uB428");
      if (typeof onToggleTranslation === "function") {
        onToggleTranslation(next);
      }
    };
    const onStatusbarClick = () => {
      if (typeof onOpenSidecar === "function") {
        onOpenSidecar("antigravity-statusbar/statusbar");
      }
      sidecarFeedback.textContent = "Statusbar \uBCF4\uC870 \uD328\uB110 \uD1A0\uAE00 \uC694\uCCAD\uC744 \uBCF4\uB0C8\uC2B5\uB2C8\uB2E4.";
    };
    const onMcpClick = () => {
      if (typeof onOpenSidecar === "function") {
        onOpenSidecar("antigravity-mcp-manager/mcp_manager");
      }
      sidecarFeedback.textContent = "MCP Manager \uBCF4\uC870 \uD328\uB110 \uD1A0\uAE00 \uC694\uCCAD\uC744 \uBCF4\uB0C8\uC2B5\uB2C8\uB2E4.";
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
    trToggleBtn.addEventListener("click", onTranslateClick);
    statusbarBtn.addEventListener("click", onStatusbarClick);
    mcpBtn.addEventListener("click", onMcpClick);
    win.addEventListener("keydown", onKeyDown);
    return {
      setOpen,
      toggleOpen() {
        setOpen(!isOpen);
      },
      setTranslationStatus(stats) {
        if (!stats) {
          return;
        }
        if (!stats.enabled) {
          updateTranslateUi(false, "\uC6D0\uBB38 \uD45C\uC2DC \uC911");
          return;
        }
        if (stats.lastError) {
          updateTranslateUi(true, `\uBC88\uC5ED \uC624\uB958: ${stats.lastError}`);
          return;
        }
        updateTranslateUi(true, `\uBC88\uC5ED \uD65C\uC131 \xB7 ${stats.translatedCount || 0}\uAC1C \uAD6C\uAC04 \uBC88\uC5ED\uB428`);
      },
      dispose() {
        pillBtn.removeEventListener("click", onPillClick);
        closeBtn.removeEventListener("click", onCloseClick);
        trToggleBtn.removeEventListener("click", onTranslateClick);
        statusbarBtn.removeEventListener("click", onStatusbarClick);
        mcpBtn.removeEventListener("click", onMcpClick);
        win.removeEventListener("keydown", onKeyDown);
        if (typeof root.remove === "function") {
          root.remove();
        }
      }
    };
  }

  // src/runtime/remote-web-entry.js
  var DEFAULT_TRANSLATE_API_BASE = "https://translate.googleapis.com/translate_a/single";
  function validateTranslateEndpoint(rawUrl) {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (_err) {
      throw new SecurityPolicyError("INVALID_TRANSLATE_ENDPOINT", "Invalid translation endpoint URL.");
    }
    const isHttps = parsed.protocol === "https:";
    const isLoopbackHttp = parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname);
    if (!isHttps && !isLoopbackHttp) {
      throw new SecurityPolicyError(
        "UNSAFE_TRANSLATE_ENDPOINT",
        "Remote translation endpoint must use HTTPS (or loopback HTTP for local testing)."
      );
    }
    if (parsed.username || parsed.password) {
      throw new SecurityPolicyError("UNSAFE_TRANSLATE_ENDPOINT", "Embedded credentials in endpoint URL are forbidden.");
    }
    return parsed.toString();
  }
  function parseGoogleTranslateResponse(data) {
    if (data && typeof data === "object" && typeof data.translatedText === "string") {
      return data.translatedText;
    }
    if (Array.isArray(data) && Array.isArray(data[0])) {
      return data[0].map((seg) => Array.isArray(seg) && typeof seg[0] === "string" ? seg[0] : "").join("");
    }
    throw new Error("Unexpected translation response format.");
  }
  function createRemoteHttpTranslator({ win, endpointBase = DEFAULT_TRANSLATE_API_BASE }) {
    const safeBase = validateTranslateEndpoint(endpointBase);
    const gmXhr = typeof win?.GM_xmlhttpRequest === "function" ? win.GM_xmlhttpRequest : typeof globalThis.GM_xmlhttpRequest === "function" ? globalThis.GM_xmlhttpRequest : null;
    return async function translateText(text, { targetLang = "ko", signal } = {}) {
      const url = new URL(safeBase);
      url.searchParams.set("client", "gtx");
      url.searchParams.set("sl", "auto");
      url.searchParams.set("tl", targetLang);
      url.searchParams.set("dt", "t");
      url.searchParams.set("q", text);
      if (gmXhr) {
        return new Promise((resolve, reject) => {
          gmXhr({
            method: "GET",
            url: url.toString(),
            onload(resp2) {
              if (resp2.status < 200 || resp2.status >= 300) {
                reject(new Error(`Translation HTTP ${resp2.status}`));
                return;
              }
              try {
                resolve(parseGoogleTranslateResponse(JSON.parse(resp2.responseText)));
              } catch (parseErr) {
                reject(parseErr);
              }
            },
            onerror() {
              reject(new Error("Translation network error"));
            }
          });
        });
      }
      const fetchFn = typeof win?.fetch === "function" ? win.fetch.bind(win) : globalThis.fetch.bind(globalThis);
      const resp = await fetchFn(url.toString(), { method: "GET", signal });
      if (!resp.ok) {
        throw new Error(`Translation HTTP ${resp.status}`);
      }
      const json = await resp.json();
      return parseGoogleTranslateResponse(json);
    };
  }
  function mountAntigravityRemoteCompanion(win = globalThis.window, doc = globalThis.document) {
    if (!win || !doc) {
      return null;
    }
    if (win.__antigravityRemoteCompanion && typeof win.__antigravityRemoteCompanion.toggleDock === "function") {
      win.__antigravityRemoteCompanion.toggleDock();
      return win.__antigravityRemoteCompanion;
    }
    const allowedOrigins = Array.isArray(win.__ARP_ALLOWED_ORIGINS__) && win.__ARP_ALLOWED_ORIGINS__.length > 0 ? win.__ARP_ALLOWED_ORIGINS__ : DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS;
    const currentOrigin = win.location?.origin || "";
    if (!isOriginAllowed(currentOrigin, allowedOrigins)) {
      return null;
    }
    const endpointBase = typeof win.__ARP_TRANSLATE_ENDPOINT__ === "string" && win.__ARP_TRANSLATE_ENDPOINT__.trim() ? win.__ARP_TRANSLATE_ENDPOINT__.trim() : DEFAULT_TRANSLATE_API_BASE;
    let dock = null;
    const translateText = createRemoteHttpTranslator({ win, endpointBase });
    const translator = typeof win.__agyCreateKoTranslator === "function" ? win.__agyCreateKoTranslator({
      win,
      doc,
      settings: { enabled: true, provider: "google-translate" },
      onStatus: (stats) => dock?.setTranslationStatus(stats)
    }) : createRemoteTranslatorEngine({
      win,
      doc,
      settings: { enabled: true, targetLang: "ko" },
      translateText,
      onStatus: (stats) => dock?.setTranslationStatus(stats)
    });
    dock = createRemoteDockUi({
      win,
      doc,
      initialTranslateEnabled: true,
      onToggleTranslation(nextEnabled) {
        translator.updateSettings({ enabled: nextEnabled });
      },
      onOpenSidecar(sidecarId) {
        const targetWin = win.parent && win.parent !== win ? win.parent : win;
        targetWin.postMessage(
          {
            type: "toggle-aux-pane",
            payload: { sidecarId, viewPath: "/" }
          },
          currentOrigin
        );
      }
    });
    translator.start();
    const handle = {
      version: "2.0.0",
      translator,
      dock,
      toggleDock() {
        dock.toggleOpen();
      },
      dispose() {
        translator.dispose();
        dock.dispose();
        if (win.__antigravityRemoteCompanion === handle) {
          delete win.__antigravityRemoteCompanion;
        }
      }
    };
    win.__antigravityRemoteCompanion = handle;
    return handle;
  }
  if (typeof window !== "undefined" && typeof document !== "undefined" && window.__ARP_AUTO_MOUNT__ !== false) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        mountAntigravityRemoteCompanion(window, document);
      }, { once: true });
    } else {
      mountAntigravityRemoteCompanion(window, document);
    }
  }
})();
