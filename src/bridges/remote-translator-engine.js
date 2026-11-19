import { SecurityPolicyError } from '../security/origin-policy.js';

const EXCLUDED_TAGS = new Set([
  'SCRIPT',
  'STYLE',
  'NOSCRIPT',
  'PRE',
  'CODE',
  'KBD',
  'SAMP',
  'TEXTAREA',
  'INPUT',
  'SELECT',
  'OPTION',
  'SVG',
  'CANVAS',
  'IFRAME',
]);

const PROTECTED_SPAN_PATTERN =
  /(`[^`\n]+`|https?:\/\/[^\s)]+|(?:[a-zA-Z]:\\|\/(?:[a-zA-Z0-9._-]+\/)+)[a-zA-Z0-9._-]+)/g;

const LATIN_LETTER_PATTERN = /[A-Za-z]{2,}/;
const MAX_CACHE_ENTRIES = 500;
const MAX_CONCURRENCY = 4;

export function protectTechnicalTokens(text) {
  const tokens = [];
  const masked = String(text).replace(PROTECTED_SPAN_PATTERN, (match) => {
    const idx = tokens.length;
    tokens.push(match);
    return `__TOK${idx}__`;
  });
  return { masked, tokens };
}

export function restoreTechnicalTokens(translatedText, tokens) {
  let out = String(translatedText);
  for (let i = 0; i < tokens.length; i += 1) {
    out = out.split(`__TOK${i}__`).join(tokens[i]);
  }
  return out;
}

function isExcludedElement(el) {
  let cur = el;
  while (cur && cur.nodeType === 1) {
    const tag = typeof cur.tagName === 'string' ? cur.tagName.toUpperCase() : '';
    if (EXCLUDED_TAGS.has(tag)) {
      return true;
    }
    if (typeof cur.getAttribute === 'function') {
      if (cur.getAttribute('data-remote-dock-ignore') === 'true') {
        return true;
      }
      const ce = cur.getAttribute('contenteditable');
      if (ce === '' || ce === 'true') {
        return true;
      }
      if (cur.getAttribute('role') === 'textbox') {
        return true;
      }
    }
    const cls = typeof cur.className === 'string' ? cur.className : '';
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
      const val = typeof node.nodeValue === 'string' ? node.nodeValue : '';
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

/**
 * Vendor-independent pure DOM translation engine.
 * Translates visible prose text nodes while strictly excluding code blocks,
 * terminals, and editable inputs, preserving inline technical tokens, and
 * restoring original text cleanly when disabled or disposed.
 */
export function createRemoteTranslatorEngine({
  win,
  doc,
  settings = {},
  translateText,
  onStatus = null,
} = {}) {
  if (!win || !doc) {
    throw new SecurityPolicyError('INCOMPLETE_FRAME', 'Remote translator requires win and doc.');
  }
  if (typeof translateText !== 'function') {
    throw new TypeError('Remote translator requires a translateText(text, opts) function.');
  }

  let currentSettings = {
    enabled: settings.enabled !== false,
    targetLang: typeof settings.targetLang === 'string' && settings.targetLang.trim()
      ? settings.targetLang.trim()
      : 'ko',
  };

  const originals = new Map();
  const cache = new Map();
  const pendingNodes = new Set();
  let observer = null;
  let abortController = null;
  let active = false;
  let translatedCount = 0;
  let errorCount = 0;
  let inFlight = 0;
  const queue = [];

  function emitStatus(phase, lastError = null) {
    if (typeof onStatus === 'function') {
      onStatus({
        enabled: currentSettings.enabled,
        active,
        phase,
        translatedCount,
        errorCount,
        lastError,
      });
    }
  }

  function cacheSet(key, val) {
    if (cache.size >= MAX_CACHE_ENTRIES) {
      const oldestKey = cache.keys().next().value;
      if (oldestKey !== undefined) {
        cache.delete(oldestKey);
      }
    }
    cache.set(key, val);
  }

  function restoreAllOriginals() {
    for (const [node, originalText] of originals.entries()) {
      if (node && typeof node.nodeValue === 'string') {
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
    const raw = typeof node.nodeValue === 'string' ? node.nodeValue : '';
    const trimmed = raw.trim();
    if (trimmed.length < 2 || !LATIN_LETTER_PATTERN.test(trimmed)) {
      pendingNodes.delete(node);
      return;
    }

    const leadingWs = raw.match(/^\s*/)?.[0] || '';
    const trailingWs = raw.match(/\s*$/)?.[0] || '';
    const cacheKey = `${currentSettings.targetLang}:${trimmed}`;

    try {
      let translated = cache.get(cacheKey);
      if (translated === undefined) {
        const { masked, tokens } = protectTechnicalTokens(trimmed);
        const translatedMasked = await translateText(masked, {
          targetLang: currentSettings.targetLang,
          signal,
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
      emitStatus('translated');
    } catch (err) {
      if (err?.name !== 'AbortError') {
        errorCount += 1;
        emitStatus('error', String(err?.message || 'Translation failed'));
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
    if (typeof ObserverCtor !== 'function' || !doc.body) {
      return;
    }
    observer = new ObserverCtor((mutations) => {
      if (!active || !currentSettings.enabled) {
        return;
      }
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
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
        emitStatus('running');
      } else {
        emitStatus('paused');
      }
    },

    updateSettings(nextSettings = {}) {
      const nextEnabled = nextSettings.enabled !== undefined
        ? Boolean(nextSettings.enabled)
        : currentSettings.enabled;
      const nextLang = typeof nextSettings.targetLang === 'string' && nextSettings.targetLang.trim()
        ? nextSettings.targetLang.trim()
        : currentSettings.targetLang;

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
        emitStatus('paused');
        return;
      }

      if (langChanged) {
        restoreAllOriginals();
      }
      if (!observer) {
        startObserver();
      }
      enqueueRoot(doc.body || doc.documentElement);
      emitStatus('running');
    },

    getStats() {
      return {
        enabled: currentSettings.enabled,
        active,
        translatedCount,
        errorCount,
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
      emitStatus('disposed');
    },
  };
}
