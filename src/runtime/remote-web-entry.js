import { mountRemotePluginHost } from './remote-web-runtime.js';

function bootRemoteWebHost() {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return;
  }
  mountRemotePluginHost({ win: window, doc: document });
}

if (typeof document !== 'undefined' && document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootRemoteWebHost, { once: true });
} else {
  bootRemoteWebHost();
}
