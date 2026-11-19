import { SecurityPolicyError } from '../security/origin-policy.js';
import { redactSecrets } from '../security/redactor.js';
import { DiagnosticsBus } from './diagnostics.js';
import {
  validateActionInvocation,
  validateActionResult,
  validatePluginSnapshot,
  validateRemotePlugin,
} from './remote-plugin-contract.js';

const hasOwn = Object.hasOwn
  ? Object.hasOwn
  : (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

export class RemotePluginRegistry {
  #plugins = Object.create(null);
  #exclusiveSlotOwners = Object.create(null);
  #slotIds = Object.create(null);
  #unsubscribers = Object.create(null);
  #listeners = new Set();
  #diagnostics;
  #disposed = false;

  constructor({ diagnostics = new DiagnosticsBus() } = {}) {
    this.#diagnostics = diagnostics;
  }

  get diagnostics() {
    return this.#diagnostics;
  }

  register(rawPlugin, { locale = 'ko' } = {}) {
    if (this.#disposed) {
      throw new SecurityPolicyError('ERR_REGISTRY_DISPOSED', 'Cannot register plugin on a disposed registry.');
    }
    const plugin = validateRemotePlugin(rawPlugin);

    if (hasOwn(this.#plugins, plugin.id)) {
      throw new SecurityPolicyError(
        'ERR_DUPLICATE_PLUGIN_ID',
        `Remote plugin "${plugin.id}" is already registered.`,
      );
    }
    if (hasOwn(this.#slotIds, plugin.uiSlot.slotId)) {
      throw new SecurityPolicyError(
        'ERR_DUPLICATE_SLOT_ID',
        `UI slotId "${plugin.uiSlot.slotId}" is already claimed by "${this.#slotIds[plugin.uiSlot.slotId]}".`,
      );
    }
    if (plugin.uiSlot.exclusive && hasOwn(this.#exclusiveSlotOwners, plugin.uiSlot.slot)) {
      throw new SecurityPolicyError(
        'ERR_EXCLUSIVE_SLOT_CONFLICT',
        `Exclusive slot "${plugin.uiSlot.slot}" is already owned by "${this.#exclusiveSlotOwners[plugin.uiSlot.slot]}".`,
      );
    }
    if (!plugin.uiSlot.exclusive && hasOwn(this.#exclusiveSlotOwners, plugin.uiSlot.slot)) {
      throw new SecurityPolicyError(
        'ERR_EXCLUSIVE_SLOT_CONFLICT',
        `Slot "${plugin.uiSlot.slot}" is exclusively owned by "${this.#exclusiveSlotOwners[plugin.uiSlot.slot]}".`,
      );
    }
    if (plugin.uiSlot.exclusive) {
      for (const existingId of Object.keys(this.#plugins)) {
        if (this.#plugins[existingId].uiSlot.slot === plugin.uiSlot.slot) {
          throw new SecurityPolicyError(
            'ERR_EXCLUSIVE_SLOT_CONFLICT',
            `Cannot claim exclusive slot "${plugin.uiSlot.slot}" while "${existingId}" is registered in it.`,
          );
        }
      }
    }

    this.#plugins[plugin.id] = plugin;
    this.#slotIds[plugin.uiSlot.slotId] = plugin.id;
    if (plugin.uiSlot.exclusive) {
      this.#exclusiveSlotOwners[plugin.uiSlot.slot] = plugin.id;
    }

    if (plugin.capabilities.includes('subscribe') && typeof plugin.subscribe === 'function') {
      try {
        const unsub = plugin.subscribe(
          () => {
            if (!this.#disposed && hasOwn(this.#plugins, plugin.id)) {
              this.#emitChange({ type: 'dirty', pluginId: plugin.id });
            }
          },
          { locale },
        );
        if (typeof unsub === 'function') {
          this.#unsubscribers[plugin.id] = unsub;
        }
      } catch (err) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'PLUGIN_SUBSCRIBE_FAILED',
          source: 'core.remote-plugin-registry',
          message: `Plugin "${plugin.id}" subscribe() threw`,
          detail: err,
        });
      }
    }

    this.#emitChange({ type: 'registered', pluginId: plugin.id });

    let active = true;
    return () => {
      if (!active) {
        return;
      }
      active = false;
      this.unregister(plugin.id);
    };
  }

  unregister(pluginId) {
    if (typeof pluginId !== 'string' || !hasOwn(this.#plugins, pluginId)) {
      return false;
    }
    const plugin = this.#plugins[pluginId];
    delete this.#plugins[pluginId];
    if (hasOwn(this.#slotIds, plugin.uiSlot.slotId) && this.#slotIds[plugin.uiSlot.slotId] === pluginId) {
      delete this.#slotIds[plugin.uiSlot.slotId];
    }
    if (
      hasOwn(this.#exclusiveSlotOwners, plugin.uiSlot.slot) &&
      this.#exclusiveSlotOwners[plugin.uiSlot.slot] === pluginId
    ) {
      delete this.#exclusiveSlotOwners[plugin.uiSlot.slot];
    }

    if (hasOwn(this.#unsubscribers, pluginId)) {
      const unsub = this.#unsubscribers[pluginId];
      delete this.#unsubscribers[pluginId];
      try {
        unsub();
      } catch (err) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'PLUGIN_UNSUBSCRIBE_FAILED',
          source: 'core.remote-plugin-registry',
          message: `Plugin "${pluginId}" unsubscribe failed`,
          detail: err,
        });
      }
    }

    if (typeof plugin.dispose === 'function') {
      try {
        plugin.dispose();
      } catch (err) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'PLUGIN_DISPOSE_FAILED',
          source: 'core.remote-plugin-registry',
          message: `Plugin "${pluginId}" dispose() threw`,
          detail: err,
        });
      }
    }

    this.#emitChange({ type: 'unregistered', pluginId });
    return true;
  }

  get(pluginId) {
    if (typeof pluginId !== 'string' || !hasOwn(this.#plugins, pluginId)) {
      return null;
    }
    return this.#plugins[pluginId];
  }

  list() {
    return Object.keys(this.#plugins)
      .map((id) => this.#plugins[id])
      .sort((a, b) => {
        if (a.loadOrder !== b.loadOrder) {
          return a.loadOrder - b.loadOrder;
        }
        return a.id.localeCompare(b.id);
      });
  }

  listBySlot(slot) {
    return this.list().filter((plugin) => plugin.uiSlot.slot === slot);
  }

  async readSnapshot(pluginId, ctx = { locale: 'ko' }) {
    const plugin = this.get(pluginId);
    if (!plugin) {
      return Object.freeze({ ok: false, error: 'Plugin not registered.' });
    }
    try {
      const raw = await plugin.getSnapshot({ locale: ctx?.locale === 'en' ? 'en' : 'ko' });
      const snapshot = validatePluginSnapshot(raw);
      return Object.freeze({ ok: true, snapshot });
    } catch (err) {
      const redacted = redactSecrets(err);
      this.#diagnostics.emit({
        level: 'error',
        code: 'PLUGIN_SNAPSHOT_FAILED',
        source: 'core.remote-plugin-registry',
        message: `Plugin "${pluginId}" snapshot failed`,
        detail: err,
      });
      return Object.freeze({
        ok: false,
        error: typeof redacted?.message === 'string' && redacted.message ? redacted.message : 'Snapshot failed.',
      });
    }
  }

  async invokeAction(pluginId, actionId, invocation = {}, ctx = { locale: 'ko' }) {
    const plugin = this.get(pluginId);
    if (!plugin) {
      return validateActionResult({
        status: 'error',
        message: { ko: '등록되지 않은 플러그인입니다.', en: 'Plugin is not registered.' },
      });
    }
    if (!plugin.capabilities.includes('actions') || typeof plugin.invoke !== 'function') {
      return validateActionResult({
        status: 'error',
        message: { ko: '액션을 지원하지 않는 플러그인입니다.', en: 'Plugin does not support actions.' },
      });
    }

    let safeInvocation;
    try {
      safeInvocation = validateActionInvocation(actionId, invocation);
    } catch (err) {
      const redacted = redactSecrets(err);
      return validateActionResult({
        status: 'error',
        message: redacted?.message || 'Invalid action invocation.',
      });
    }

    try {
      const rawResult = await plugin.invoke(actionId, safeInvocation, {
        locale: ctx?.locale === 'en' ? 'en' : 'ko',
      });
      return validateActionResult(rawResult);
    } catch (err) {
      const redacted = redactSecrets(err);
      this.#diagnostics.emit({
        level: 'error',
        code: 'PLUGIN_INVOKE_FAILED',
        source: 'core.remote-plugin-registry',
        message: `Plugin "${pluginId}" invoke("${actionId}") failed`,
        detail: err,
      });
      return validateActionResult({
        status: 'error',
        message: redacted?.message || 'Plugin action failed.',
      });
    }
  }

  onChange(listener) {
    if (typeof listener !== 'function') {
      throw new TypeError('Registry onChange listener must be a function.');
    }
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  #emitChange(event) {
    for (const listener of [...this.#listeners]) {
      try {
        listener(event);
      } catch (err) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'REGISTRY_LISTENER_FAILED',
          source: 'core.remote-plugin-registry',
          message: 'Registry change listener threw',
          detail: err,
        });
      }
    }
  }

  dispose() {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    for (const id of Object.keys(this.#plugins).reverse()) {
      this.unregister(id);
    }
    this.#listeners.clear();
  }
}
