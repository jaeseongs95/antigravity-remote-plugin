import { DiagnosticsBus } from './diagnostics.js';
import { AsyncMutex, DisposableStore, SingleFlight } from './lifecycle.js';
import {
  validateBridgeDescriptor,
  validateDiscoveryPort,
  validateFramePromotionPort,
} from './ports.js';

function computeSidecarFingerprint(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') {
    return null;
  }
  return `${sidecar.sidecarId || ''}|${sidecar.host || '127.0.0.1'}|${sidecar.port || ''}|${sidecar.token || ''}`;
}

function buildDiscoveryFlightKey(context) {
  if (!context || typeof context !== 'object' || !Array.isArray(context.workspaceUris)) {
    return 'discovery:';
  }
  const normalized = context.workspaceUris
    .filter((uri) => typeof uri === 'string' && uri.trim().length > 0)
    .map((uri) => uri.trim())
    .sort();
  return `discovery:${normalized.join('\0')}`;
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
    const flightKey = buildDiscoveryFlightKey(context);
    return this.#singleFlight.run(flightKey, async () => {
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
