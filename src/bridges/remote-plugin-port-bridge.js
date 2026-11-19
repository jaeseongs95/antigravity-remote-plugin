import { REMOTE_PLUGIN_CONTRACT_VERSION } from '../core/remote-plugin-contract.js';
import { SecurityPolicyError } from '../security/origin-policy.js';
import { redactSecrets } from '../security/redactor.js';

export const PORT_MSG = Object.freeze({
  REGISTER: 'remote-plugin-v1:register',
  REGISTER_RESULT: 'remote-plugin-v1:register-result',
  UNREGISTER: 'remote-plugin-v1:unregister',
  DISCONNECT: 'remote-plugin-v1:disconnect',
  DIRTY: 'remote-plugin-v1:dirty',
  LIST: 'remote-plugin-v1:list',
  LIST_RESULT: 'remote-plugin-v1:list-result',
  SNAPSHOT_REQ: 'remote-plugin-v1:snapshot-req',
  SNAPSHOT_RES: 'remote-plugin-v1:snapshot-res',
  INVOKE_REQ: 'remote-plugin-v1:invoke-req',
  INVOKE_RES: 'remote-plugin-v1:invoke-res',
});

const DEFAULT_RPC_TIMEOUT_MS = 5000;

/**
 * Host-side MessagePort RPC bridge for cross-context RemotePlugin.v1 peers.
 * Supports register, snapshot, invoke, dirty notifications, list, unregister,
 * and deterministic disconnect/port release without leaking host internals.
 */
export function attachRemotePluginPortBridge({
  port,
  registry,
  diagnostics = null,
  onClose = null,
  rpcTimeoutMs = DEFAULT_RPC_TIMEOUT_MS,
}) {
  if (!port || typeof port.postMessage !== 'function') {
    throw new TypeError('attachRemotePluginPortBridge requires a MessagePort.');
  }
  if (!registry || typeof registry.register !== 'function') {
    throw new TypeError('attachRemotePluginPortBridge requires a RemotePluginRegistry.');
  }

  let closed = false;
  let reqCounter = 0;
  let registeredPluginId = null;
  let unregisterFn = null;
  let dirtyCallback = null;
  const pendingRpc = new Map();

  function rejectAllPending(reason) {
    for (const [id, entry] of pendingRpc.entries()) {
      clearTimeout(entry.timer);
      pendingRpc.delete(id);
      entry.reject(new Error(reason));
    }
  }

  function sendRpc(reqType, payload) {
    if (closed) {
      return Promise.reject(new SecurityPolicyError('ERR_PORT_CLOSED', 'Remote plugin port is closed.'));
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
    if (typeof unregisterFn === 'function') {
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
    rejectAllPending('Remote plugin port disconnected.');
    teardownLocalPlugin();
    if (typeof port.removeEventListener === 'function') {
      port.removeEventListener('message', onMessage);
    } else if (port.onmessage === onMessage) {
      port.onmessage = null;
    }
    if (typeof onClose === 'function') {
      onClose();
    } else if (typeof port.close === 'function') {
      port.close();
    }
  }

  function onMessage(event) {
    if (closed) {
      return;
    }
    const msg = event?.data;
    if (!msg || typeof msg !== 'object') {
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
        entry.reject(new Error(typeof msg.error === 'string' ? msg.error : 'Remote RPC error'));
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
          capabilities: p.capabilities,
        })),
      });
      return;
    }

    if (msg.type === PORT_MSG.REGISTER) {
      const desc = msg.descriptor;
      if (!desc || typeof desc !== 'object' || Array.isArray(desc)) {
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: false,
          error: 'Invalid plugin descriptor.',
        });
        return;
      }
      if (registeredPluginId) {
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: false,
          error: 'Port already registered a plugin.',
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
        ...(caps.includes('actions')
          ? {
              invoke(actionId, invocation, ctx) {
                return sendRpc(PORT_MSG.INVOKE_REQ, { actionId, invocation, ctx });
              },
            }
          : {}),
        ...(caps.includes('subscribe')
          ? {
              subscribe(onDirty) {
                dirtyCallback = onDirty;
                return () => {
                  if (dirtyCallback === onDirty) {
                    dirtyCallback = null;
                  }
                };
              },
            }
          : {}),
        dispose() {
          if (!closed) {
            try {
              port.postMessage({ type: PORT_MSG.DISCONNECT });
            } catch (err) {
              if (diagnostics) {
                diagnostics.emit({
                  level: 'warn',
                  code: 'PORT_DISCONNECT_SEND_FAILED',
                  source: 'bridge.remote-plugin-port',
                  message: 'Failed sending disconnect over port',
                  detail: err,
                });
              }
            }
          }
          closeBridge();
        },
      };

      try {
        unregisterFn = registry.register(proxy);
        registeredPluginId = desc.id;
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: true,
          pluginId: desc.id,
        });
      } catch (err) {
        const redacted = redactSecrets(err);
        port.postMessage({
          type: PORT_MSG.REGISTER_RESULT,
          requestId: msg.requestId ?? null,
          ok: false,
          error: redacted?.message || 'Registration failed.',
          code: err?.code || 'ERR_REGISTER_FAILED',
        });
      }
      return;
    }

    if (msg.type === PORT_MSG.DIRTY) {
      if (typeof dirtyCallback === 'function') {
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

  if (typeof port.addEventListener === 'function') {
    port.addEventListener('message', onMessage);
    if (typeof port.start === 'function') {
      port.start();
    }
  } else {
    port.onmessage = onMessage;
  }

  return Object.freeze({
    getRegisteredPluginId() {
      return registeredPluginId;
    },
    close: closeBridge,
  });
}

/**
 * Client-side helper for cross-context plugins connecting over a handshaked MessagePort.
 */
export function serveRemotePluginOverPort({ port, plugin, timeoutMs = DEFAULT_RPC_TIMEOUT_MS }) {
  if (!port || typeof port.postMessage !== 'function') {
    throw new TypeError('serveRemotePluginOverPort requires a MessagePort.');
  }
  if (!plugin || typeof plugin !== 'object') {
    throw new TypeError('serveRemotePluginOverPort requires a RemotePlugin.v1 object.');
  }

  let unsubDirty = null;
  let closed = false;

  const onMessage = async (event) => {
    if (closed) {
      return;
    }
    const msg = event?.data;
    if (!msg || typeof msg !== 'object') {
      return;
    }
    if (msg.type === PORT_MSG.SNAPSHOT_REQ) {
      try {
        const result = await plugin.getSnapshot(msg.ctx || { locale: 'ko' });
        port.postMessage({ type: PORT_MSG.SNAPSHOT_RES, requestId: msg.requestId, ok: true, result });
      } catch (err) {
        const redacted = redactSecrets(err);
        port.postMessage({
          type: PORT_MSG.SNAPSHOT_RES,
          requestId: msg.requestId,
          ok: false,
          error: redacted?.message || 'Snapshot failed',
        });
      }
      return;
    }
    if (msg.type === PORT_MSG.INVOKE_REQ) {
      try {
        if (typeof plugin.invoke !== 'function') {
          throw new Error('Plugin does not implement invoke().');
        }
        const result = await plugin.invoke(msg.actionId, msg.invocation || {}, msg.ctx || { locale: 'ko' });
        port.postMessage({ type: PORT_MSG.INVOKE_RES, requestId: msg.requestId, ok: true, result });
      } catch (err) {
        const redacted = redactSecrets(err);
        port.postMessage({
          type: PORT_MSG.INVOKE_RES,
          requestId: msg.requestId,
          ok: false,
          error: redacted?.message || 'Invoke failed',
        });
      }
      return;
    }
    if (msg.type === PORT_MSG.DISCONNECT) {
      disconnect();
    }
  };

  if (typeof port.addEventListener === 'function') {
    port.addEventListener('message', onMessage);
    if (typeof port.start === 'function') {
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
    if (typeof unsubDirty === 'function') {
      unsubDirty();
      unsubDirty = null;
    }
    try {
      port.postMessage({ type: PORT_MSG.DISCONNECT });
    } catch (_err) {
      closed = true;
    }
    if (typeof port.removeEventListener === 'function') {
      port.removeEventListener('message', onMessage);
    } else if (port.onmessage === onMessage) {
      port.onmessage = null;
    }
    if (typeof port.close === 'function') {
      port.close();
    }
  }

  const registerPromise = new Promise((resolve, reject) => {
    const requestId = 'reg-1';
    const timer = setTimeout(() => {
      reject(new Error('Remote plugin registration over MessagePort timed out.'));
    }, timeoutMs);

    const onRegResult = (event) => {
      const msg = event?.data;
      if (!msg || msg.type !== PORT_MSG.REGISTER_RESULT || msg.requestId !== requestId) {
        return;
      }
      clearTimeout(timer);
      if (typeof port.removeEventListener === 'function') {
        port.removeEventListener('message', onRegResult);
      }
      if (msg.ok) {
        if (typeof plugin.subscribe === 'function') {
          const maybeUnsub = plugin.subscribe(
            () => {
              if (!closed) {
                port.postMessage({ type: PORT_MSG.DIRTY });
              }
            },
            { locale: 'ko' },
          );
          if (typeof maybeUnsub === 'function') {
            unsubDirty = maybeUnsub;
          }
        }
        resolve(msg);
      } else {
        const err = new Error(msg.error || 'Registration rejected');
        err.code = msg.code || 'ERR_REGISTER_FAILED';
        reject(err);
      }
    };

    if (typeof port.addEventListener === 'function') {
      port.addEventListener('message', onRegResult);
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
        loadOrder: plugin.loadOrder,
      },
    });
  });

  return Object.freeze({
    ready: registerPromise,
    notifyDirty() {
      if (!closed) {
        port.postMessage({ type: PORT_MSG.DIRTY });
      }
    },
    disconnect,
  });
}
