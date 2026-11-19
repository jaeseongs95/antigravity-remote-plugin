import { DiagnosticsBus } from './diagnostics.js';
import { DisposableStore, SingleFlight } from './lifecycle.js';
import {
  validateBridgeDescriptor,
  validateDiscoveryPort,
  validateFramePromotionPort,
} from './ports.js';

export class RemoteOrchestrator {
  #discoveryPort;
  #framePort;
  #diagnostics;
  #bridges = new Map();
  #mounted = new Map();
  #singleFlight = new SingleFlight();
  #store;
  #started = false;
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
    return this.#singleFlight.run('discovery', async () => {
      const [plugins, sidecars] = await Promise.all([
        this.#discoveryPort.listPlugins(context),
        this.#discoveryPort.listSidecars(context),
      ]);
      const normalizedPlugins = Array.isArray(plugins) ? plugins : [];
      const normalizedSidecars = Array.isArray(sidecars) ? sidecars : [];

      const activePlugins = new Map();
      for (const plugin of normalizedPlugins) {
        if (!plugin || typeof plugin.name !== 'string') {
          continue;
        }
        const isEnabled = plugin.disabled !== true && plugin.enabled !== false;
        if (isEnabled) {
          activePlugins.set(plugin.name, plugin);
        }
      }

      const activeSidecars = new Map();
      for (const sidecar of normalizedSidecars) {
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
    if (this.#started) {
      return this.reconcile(context);
    }
    this.#started = true;
    this.#activeFrame = await this.#framePort.acquireActiveFrame();

    const unsubFrame = this.#framePort.onFrameChange(async (nextFrame) => {
      this.#activeFrame = nextFrame;
      this.#unmountAll();
      if (nextFrame) {
        await this.reconcile(context);
      }
    });
    if (typeof unsubFrame === 'function') {
      this.#store.add(unsubFrame);
    }

    return this.reconcile(context);
  }

  async reconcile(context = {}) {
    if (this.#store.isDisposed) {
      return { mountedIds: [], skippedIds: [] };
    }
    const { activePlugins, activeSidecars } = await this.discoverAuthoritativeState(context);
    const mountedIds = [];
    const skippedIds = [];

    for (const [bridgeId, bridge] of this.#bridges.entries()) {
      const pluginRecord = activePlugins.get(bridge.pluginName);
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

      if (this.#mounted.has(bridgeId)) {
        mountedIds.push(bridgeId);
        continue;
      }

      try {
        await bridge.mount({
          frame: this.#activeFrame,
          plugin: pluginRecord,
          sidecar: sidecarRecord,
          diagnostics: this.#diagnostics,
        });
        this.#mounted.set(bridgeId, bridge);
        mountedIds.push(bridgeId);
      } catch (err) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'BRIDGE_MOUNT_FAILED',
          source: 'core.orchestrator',
          message: `Failed to mount bridge "${bridgeId}"`,
          detail: err,
        });
      }
    }

    return { mountedIds, skippedIds };
  }

  getMountedBridgeIds() {
    return [...this.#mounted.keys()];
  }

  #unmountBridge(bridgeId) {
    const bridge = this.#mounted.get(bridgeId);
    if (!bridge) {
      return;
    }
    this.#mounted.delete(bridgeId);
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

  #unmountAll() {
    for (const bridgeId of [...this.#mounted.keys()].reverse()) {
      this.#unmountBridge(bridgeId);
    }
  }

  dispose() {
    this.#unmountAll();
    this.#store.dispose();
    this.#started = false;
    this.#activeFrame = null;
  }
}
