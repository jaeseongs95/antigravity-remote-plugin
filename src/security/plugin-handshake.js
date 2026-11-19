import { assertOriginAllowed, isOriginAllowed, SecurityPolicyError } from './origin-policy.js';

export const HANDSHAKE_PROTOCOL_TYPE = 'remote-plugin-v1:handshake-init';
export const HANDSHAKE_ACK_TYPE = 'remote-plugin-v1:handshake-ack';

export function generateHandshakeNonce(byteLength = 24) {
  const bytes = new Uint8Array(byteLength);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new SecurityPolicyError(
      'ERR_CRYPTO_UNAVAILABLE',
      'Web Crypto API is required to generate cryptographic handshake nonces.',
    );
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Closed MessageChannel handshake host for isolated plugin registration.
 * Strictly validates `event.origin` against an explicit allowlist and requires
 * a single-use cryptographic nonce plus a transferred MessagePort.
 * Never calls postMessage with wildcard targetOrigin '*'.
 */
export function createPluginHandshakeHost({ win, allowedOrigins, onPortConnected }) {
  if (!win || typeof win.addEventListener !== 'function') {
    throw new SecurityPolicyError('ERR_INVALID_WINDOW', 'A window with event listeners is required.');
  }
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
    throw new SecurityPolicyError('ERR_EMPTY_ALLOWLIST', 'An explicit allowedOrigins array is required.');
  }
  if (typeof onPortConnected !== 'function') {
    throw new TypeError('onPortConnected callback is required.');
  }

  const pendingNonces = new Set();
  const activePorts = new Set();
  let disposed = false;

  const onMessage = (event) => {
    if (disposed || !event || typeof event !== 'object') {
      return;
    }
    if (!isOriginAllowed(event.origin, allowedOrigins)) {
      return;
    }
    const data = event.data;
    if (!data || typeof data !== 'object' || data.type !== HANDSHAKE_PROTOCOL_TYPE) {
      return;
    }
    if (typeof data.nonce !== 'string' || !pendingNonces.has(data.nonce)) {
      return;
    }
    const port = Array.isArray(event.ports) ? event.ports[0] : null;
    if (!port || typeof port.postMessage !== 'function') {
      return;
    }

    // Consume single-use nonce immediately to prevent replay.
    pendingNonces.delete(data.nonce);
    activePorts.add(port);

    if (typeof port.start === 'function') {
      port.start();
    }
    port.postMessage({ type: HANDSHAKE_ACK_TYPE, accepted: true });
    onPortConnected({
      port,
      origin: event.origin,
      pluginId: typeof data.pluginId === 'string' ? data.pluginId : null,
      close() {
        activePorts.delete(port);
        if (typeof port.close === 'function') {
          port.close();
        }
      },
    });
  };

  win.addEventListener('message', onMessage);

  return Object.freeze({
    issueNonce() {
      if (disposed) {
        throw new SecurityPolicyError('ERR_HANDSHAKE_DISPOSED', 'Handshake host is disposed.');
      }
      const nonce = generateHandshakeNonce();
      pendingNonces.add(nonce);
      return nonce;
    },
    pendingCount() {
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
      if (typeof win.removeEventListener === 'function') {
        win.removeEventListener('message', onMessage);
      }
      for (const port of activePorts) {
        if (typeof port.close === 'function') {
          port.close();
        }
      }
      activePorts.clear();
    },
  });
}

export function initiatePluginHandshake({
  targetWindow,
  targetOrigin,
  allowedOrigins,
  nonce,
  pluginId,
  MessageChannelCtor = globalThis.MessageChannel,
}) {
  assertOriginAllowed(targetOrigin, allowedOrigins, 'handshake targetOrigin');
  if (typeof nonce !== 'string' || nonce.length < 16) {
    throw new SecurityPolicyError('ERR_INVALID_NONCE', 'A cryptographic nonce is required.');
  }
  if (typeof MessageChannelCtor !== 'function') {
    throw new SecurityPolicyError('ERR_NO_MESSAGE_CHANNEL', 'MessageChannel is unavailable.');
  }
  const channel = new MessageChannelCtor();
  if (typeof channel.port1.start === 'function') {
    channel.port1.start();
  }
  targetWindow.postMessage(
    {
      type: HANDSHAKE_PROTOCOL_TYPE,
      nonce,
      pluginId: typeof pluginId === 'string' ? pluginId : null,
    },
    targetOrigin,
    [channel.port2],
  );
  return channel.port1;
}
