import { createRemoteTranslatorEngine } from '../bridges/remote-translator-engine.js';
import { DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS } from '../adapters/antigravity/frame-adapter.js';
import { createRemoteDockUi } from '../adapters/antigravity/remote-dock-ui.js';
import {
  isLoopbackHostname,
  isOriginAllowed,
  SecurityPolicyError,
} from '../security/origin-policy.js';

const DEFAULT_TRANSLATE_API_BASE = 'https://translate.googleapis.com/translate_a/single';

function validateTranslateEndpoint(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_err) {
    throw new SecurityPolicyError('INVALID_TRANSLATE_ENDPOINT', 'Invalid translation endpoint URL.');
  }
  const isHttps = parsed.protocol === 'https:';
  const isLoopbackHttp = parsed.protocol === 'http:' && isLoopbackHostname(parsed.hostname);
  if (!isHttps && !isLoopbackHttp) {
    throw new SecurityPolicyError(
      'UNSAFE_TRANSLATE_ENDPOINT',
      'Remote translation endpoint must use HTTPS (or loopback HTTP for local testing).',
    );
  }
  if (parsed.username || parsed.password) {
    throw new SecurityPolicyError('UNSAFE_TRANSLATE_ENDPOINT', 'Embedded credentials in endpoint URL are forbidden.');
  }
  return parsed.toString();
}

function parseGoogleTranslateResponse(data) {
  if (data && typeof data === 'object' && typeof data.translatedText === 'string') {
    return data.translatedText;
  }
  if (Array.isArray(data) && Array.isArray(data[0])) {
    return data[0]
      .map((seg) => (Array.isArray(seg) && typeof seg[0] === 'string' ? seg[0] : ''))
      .join('');
  }
  throw new Error('Unexpected translation response format.');
}

function createRemoteHttpTranslator({ win, endpointBase = DEFAULT_TRANSLATE_API_BASE }) {
  const safeBase = validateTranslateEndpoint(endpointBase);
  const gmXhr =
    typeof win?.GM_xmlhttpRequest === 'function'
      ? win.GM_xmlhttpRequest
      : typeof globalThis.GM_xmlhttpRequest === 'function'
        ? globalThis.GM_xmlhttpRequest
        : null;

  return async function translateText(text, { targetLang = 'ko', signal } = {}) {
    const url = new URL(safeBase);
    url.searchParams.set('client', 'gtx');
    url.searchParams.set('sl', 'auto');
    url.searchParams.set('tl', targetLang);
    url.searchParams.set('dt', 't');
    url.searchParams.set('q', text);

    if (gmXhr) {
      return new Promise((resolve, reject) => {
        gmXhr({
          method: 'GET',
          url: url.toString(),
          onload(resp) {
            if (resp.status < 200 || resp.status >= 300) {
              reject(new Error(`Translation HTTP ${resp.status}`));
              return;
            }
            try {
              resolve(parseGoogleTranslateResponse(JSON.parse(resp.responseText)));
            } catch (parseErr) {
              reject(parseErr);
            }
          },
          onerror() {
            reject(new Error('Translation network error'));
          },
        });
      });
    }

    const fetchFn = typeof win?.fetch === 'function'
      ? win.fetch.bind(win)
      : globalThis.fetch.bind(globalThis);
    const resp = await fetchFn(url.toString(), { method: 'GET', signal });
    if (!resp.ok) {
      throw new Error(`Translation HTTP ${resp.status}`);
    }
    const json = await resp.json();
    return parseGoogleTranslateResponse(json);
  };
}

export function mountAntigravityRemoteCompanion(win = globalThis.window, doc = globalThis.document) {
  if (!win || !doc) {
    return null;
  }

  // Idempotent on repeated bookmarklet taps: toggle popover instead of duplicating DOM.
  if (win.__antigravityRemoteCompanion && typeof win.__antigravityRemoteCompanion.toggleDock === 'function') {
    win.__antigravityRemoteCompanion.toggleDock();
    return win.__antigravityRemoteCompanion;
  }

  const allowedOrigins = Array.isArray(win.__ARP_ALLOWED_ORIGINS__) && win.__ARP_ALLOWED_ORIGINS__.length > 0
    ? win.__ARP_ALLOWED_ORIGINS__
    : DEFAULT_ANTIGRAVITY_REMOTE_ORIGINS;

  const currentOrigin = win.location?.origin || '';
  if (!isOriginAllowed(currentOrigin, allowedOrigins)) {
    return null;
  }

  const endpointBase =
    typeof win.__ARP_TRANSLATE_ENDPOINT__ === 'string' && win.__ARP_TRANSLATE_ENDPOINT__.trim()
      ? win.__ARP_TRANSLATE_ENDPOINT__.trim()
      : DEFAULT_TRANSLATE_API_BASE;

  let dock = null;
  const translateText = createRemoteHttpTranslator({ win, endpointBase });

  const translator =
    typeof win.__agyCreateKoTranslator === 'function'
      ? win.__agyCreateKoTranslator({
          win,
          doc,
          settings: { enabled: true, provider: 'google-translate' },
          onStatus: (stats) => dock?.setTranslationStatus(stats),
        })
      : createRemoteTranslatorEngine({
          win,
          doc,
          settings: { enabled: true, targetLang: 'ko' },
          translateText,
          onStatus: (stats) => dock?.setTranslationStatus(stats),
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
          type: 'toggle-aux-pane',
          payload: { sidecarId, viewPath: '/' },
        },
        currentOrigin,
      );
    },
  });

  translator.start();

  const handle = {
    version: '2.0.0',
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
    },
  };

  win.__antigravityRemoteCompanion = handle;
  return handle;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined' && window.__ARP_AUTO_MOUNT__ !== false) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      mountAntigravityRemoteCompanion(window, document);
    }, { once: true });
  } else {
    mountAntigravityRemoteCompanion(window, document);
  }
}
