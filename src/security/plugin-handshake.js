import { assertOriginAllowed, isOriginAllowed, SecurityPolicyError } from './origin-policy.js';

export const HANDSHAKE_REQUEST_TYPE = 'remote-plugin-v1:handshake-request';
export const HANDSHAKE_CHALLENGE_TYPE = 'remote-plugin-v1:handshake-challenge';
export const HANDSHAKE_PROTOCOL_TYPE = 'remote-plugin-v1:handshake-init';
export const HANDSHAKE_ACK_TYPE = 'remote-plugin-v1:handshake-ack';

const DEFAULT_NONCE_TTL_MS = 30_000;
const MAX_PENDING_NONCES = 128;

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
 * Closed MessageChannel handshake host for isolated / cross-context plugin registration.
 * - Strictly validates `event.origin` against an explicit allowlist.
 * - Supports origin+source-bound challenge-response (`handshake-request` -> `handshake-challenge`)
 *   so isolated iframes obtain a single-use TTL-bounded nonce without any global nonce emitter on window.
 * - Never calls postMessage with wildcard targetOrigin '*'.
 * - Automatically prunes expired nonces and tracks active MessagePorts with explicit close cleanup.
 */
export function createPluginHandshakeHost({
  win,
  allowedOrigins,
  onPortConnected,
  nonceTtlMs = DEFAULT_NONCE_TTL_MS,
  now = () => Date.now(),
}) {
  if (!win || typeof win.addEventListener !== 'function') {
    throw new SecurityPolicyError('ERR_INVALID_WINDOW', 'A window with event listeners is required.');
  }
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
    throw new SecurityPolicyError('ERR_EMPTY_ALLOWLIST', 'An explicit allowedOrigins array is required.');
  }
  if (typeof onPortConnected !== 'function') {
    throw new TypeError('onPortConnected callback is required.');
  }

  const pendingNonces = new Map(); // nonce -> { expiresAt, boundOrigin, boundSource }
  const activePorts = new Set();
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
      throw new SecurityPolicyError('ERR_HANDSHAKE_DISPOSED', 'Handshake host is disposed.');
    }
    pruneExpiredNonces();
    if (pendingNonces.size >= MAX_PENDING_NONCES) {
      const oldestKey = pendingNonces.keys().next().value;
      if (oldestKey !== undefined) {
        pendingNonces.delete(oldestKey);
      }
    }
    const nonce = generateHandshakeNonce();
    pendingNonces.set(nonce, {
      expiresAt: now() + Math.max(100, Number(nonceTtlMs) || DEFAULT_NONCE_TTL_MS),
      boundOrigin,
      boundSource,
    });
    return nonce;
  }

  const onMessage = (event) => {
    if (disposed || !event || typeof event !== 'object') {
      return;
    }
    if (!isOriginAllowed(event.origin, allowedOrigins)) {
      return;
    }
    const data = event.data;
    if (!data || typeof data !== 'object') {
      return;
    }

    // Step 1 (optional cross-context challenge): issue origin+source-bound single-use nonce
    if (data.type === HANDSHAKE_REQUEST_TYPE) {
      if (typeof data.requestId !== 'string' || !data.requestId || data.requestId.length > 128) {
        return;
      }
      const replyTarget = event.source;
      if (!replyTarget || typeof replyTarget.postMessage !== 'function') {
        return;
      }
      const nonce = issueNonceInternal({
        boundOrigin: event.origin,
        boundSource: replyTarget,
      });
      replyTarget.postMessage(
        {
          type: HANDSHAKE_CHALLENGE_TYPE,
          requestId: data.requestId,
          nonce,
        },
        event.origin,
      );
      return;
    }

    // Step 2: verify nonce, origin, source binding, and transferred MessagePort
    if (data.type !== HANDSHAKE_PROTOCOL_TYPE) {
      return;
    }
    pruneExpiredNonces();
    if (typeof data.nonce !== 'string' || !pendingNonces.has(data.nonce)) {
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
    if (!port || typeof port.postMessage !== 'function') {
      return;
    }

    // Consume single-use nonce immediately to prevent replay.
    pendingNonces.delete(data.nonce);
    activePorts.add(port);

    if (typeof port.start === 'function') {
      port.start();
    }

    let closed = false;
    const closePort = () => {
      if (closed) {
        return;
      }
      closed = true;
      activePorts.delete(port);
      if (typeof port.close === 'function') {
        port.close();
      }
    };

    port.postMessage({ type: HANDSHAKE_ACK_TYPE, accepted: true });
    onPortConnected({
      port,
      origin: event.origin,
      pluginId: typeof data.pluginId === 'string' ? data.pluginId : null,
      close: closePort,
    });
  };

  win.addEventListener('message', onMessage);

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
      if (typeof win.removeEventListener === 'function') {
        win.removeEventListener('message', onMessage);
      }
      for (const port of [...activePorts]) {
        activePorts.delete(port);
        if (typeof port.close === 'function') {
          port.close();
        }
      }
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

/**
 * Full cross-context client helper: requests a single-use challenge nonce from
 * `targetWindow` (strictly validated against `allowedOrigins`), completes
 * MessageChannel transfer, and resolves with the ACKed `MessagePort`.
 */
export async function connectPluginHandshake({
  selfWindow,
  targetWindow,
  targetOrigin,
  allowedOrigins,
  pluginId,
  timeoutMs = 5000,
  MessageChannelCtor = globalThis.MessageChannel,
}) {
  assertOriginAllowed(targetOrigin, allowedOrigins, 'handshake targetOrigin');
  if (!selfWindow || typeof selfWindow.addEventListener !== 'function') {
    throw new SecurityPolicyError('ERR_INVALID_WINDOW', 'selfWindow with event listeners is required.');
  }
  const requestId = generateHandshakeNonce(12);

  return new Promise((resolve, reject) => {
    let settled = false;
    let clientPort = null;

    const cleanup = () => {
      clearTimeout(timer);
      if (typeof selfWindow.removeEventListener === 'function') {
        selfWindow.removeEventListener('message', onChallenge);
      }
    };

    const fail = (err) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (clientPort && typeof clientPort.close === 'function') {
        clientPort.close();
      }
      reject(err);
    };

    const timer = setTimeout(() => {
      fail(new SecurityPolicyError('ERR_HANDSHAKE_TIMEOUT', 'Plugin handshake timed out.'));
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
          MessageChannelCtor,
        });
      } catch (err) {
        fail(err);
        return;
      }

      const ackTimer = setTimeout(() => {
        fail(new SecurityPolicyError('ERR_HANDSHAKE_ACK_TIMEOUT', 'Plugin handshake ACK timed out.'));
      }, timeoutMs);

      const onAck = (ackEvent) => {
        const msg = ackEvent?.data;
        if (!msg || msg.type !== HANDSHAKE_ACK_TYPE || msg.accepted !== true) {
          return;
        }
        clearTimeout(ackTimer);
        if (typeof clientPort.removeEventListener === 'function') {
          clientPort.removeEventListener('message', onAck);
        }
        if (!settled) {
          settled = true;
          resolve(clientPort);
        }
      };

      if (typeof clientPort.addEventListener === 'function') {
        clientPort.addEventListener('message', onAck);
      } else {
        clientPort.onmessage = onAck;
      }
    };

    selfWindow.addEventListener('message', onChallenge);
    targetWindow.postMessage(
      {
        type: HANDSHAKE_REQUEST_TYPE,
        requestId,
      },
      targetOrigin,
    );
  });
}
