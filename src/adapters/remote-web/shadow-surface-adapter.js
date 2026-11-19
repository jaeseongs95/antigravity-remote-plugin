import { createSafeElement } from '../../security/dom-guard.js';
import { SecurityPolicyError } from '../../security/origin-policy.js';

const hasOwn = Object.hasOwn
  ? Object.hasOwn
  : (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/**
 * Remote web HostSurfacePort implementation backed by a Closed Shadow DOM root.
 * Provides full CSS isolation and zero page DOM pollution while sharing the exact
 * HostSurfacePort contract used by the Desktop AddonManifest.v1 adapter (LSP).
 */
export function createShadowSurfaceAdapter({
  doc,
  ownerId = 'antigravity-remote-plugin',
  mountTarget = null,
  diagnostics = null,
} = {}) {
  if (!doc || typeof doc.createElement !== 'function') {
    throw new SecurityPolicyError('ERR_INVALID_DOCUMENT', 'ShadowSurfaceAdapter requires a DOM document.');
  }

  const hostEl = createSafeElement(doc, 'div', {
    attrs: {
      translate: 'no',
      'data-addon-host-owner': ownerId,
      'data-remote-host-surface': 'closed-shadow',
    },
  });

  const shadowRoot =
    typeof hostEl.attachShadow === 'function' ? hostEl.attachShadow({ mode: 'closed' }) : hostEl;

  const parent = mountTarget || doc.body || doc.documentElement;
  if (parent && typeof parent.appendChild === 'function') {
    parent.appendChild(hostEl);
  }

  const slots = Object.create(null);
  const styles = Object.create(null);
  const disposers = [];
  let disposed = false;

  return Object.freeze({
    ownerId,
    hostElement: hostEl,

    mountSlot(slotId) {
      if (disposed) {
        throw new SecurityPolicyError('ERR_SURFACE_DISPOSED', 'HostSurfacePort is already disposed.');
      }
      if (typeof slotId !== 'string' || !slotId.trim()) {
        throw new SecurityPolicyError('ERR_INVALID_SLOT_ID', 'slotId must be a non-empty string.');
      }
      if (hasOwn(slots, slotId)) {
        return slots[slotId];
      }
      const el = createSafeElement(doc, 'div', {
        attrs: {
          translate: 'no',
          'data-addon-host-owner': ownerId,
          'data-addon-host-slot': slotId,
        },
      });
      slots[slotId] = el;
      shadowRoot.appendChild(el);
      return el;
    },

    unmountSlot(slotId) {
      if (!hasOwn(slots, slotId)) {
        return false;
      }
      const el = slots[slotId];
      delete slots[slotId];
      if (el && el.parentNode && typeof el.parentNode.removeChild === 'function') {
        el.parentNode.removeChild(el);
      }
      return true;
    },

    injectStyle(styleId, cssText) {
      if (disposed) {
        throw new SecurityPolicyError('ERR_SURFACE_DISPOSED', 'HostSurfacePort is already disposed.');
      }
      if (typeof styleId !== 'string' || !styleId.trim()) {
        throw new SecurityPolicyError('ERR_INVALID_STYLE_ID', 'styleId must be a non-empty string.');
      }
      let styleEl = hasOwn(styles, styleId) ? styles[styleId] : null;
      if (!styleEl) {
        styleEl = createSafeElement(doc, 'style', {
          attrs: {
            'data-addon-host-owner': ownerId,
            'data-addon-host-style': `${ownerId}:${styleId}`,
          },
        });
        styles[styleId] = styleEl;
        shadowRoot.appendChild(styleEl);
      }
      styleEl.textContent = String(cssText || '');
      return styleEl;
    },

    removeStyle(styleId) {
      if (!hasOwn(styles, styleId)) {
        return false;
      }
      const el = styles[styleId];
      delete styles[styleId];
      if (el && el.parentNode && typeof el.parentNode.removeChild === 'function') {
        el.parentNode.removeChild(el);
      }
      return true;
    },

    listOwnedSlots() {
      return Object.keys(slots);
    },

    onDispose(fn) {
      if (disposed || typeof fn !== 'function') {
        return;
      }
      disposers.push(fn);
    },

    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      for (const fn of disposers.splice(0, disposers.length).reverse()) {
        try {
          fn();
        } catch (err) {
          if (diagnostics && typeof diagnostics.emit === 'function') {
            diagnostics.emit({
              level: 'error',
              code: 'SURFACE_DISPOSER_FAILED',
              source: 'adapter.shadow-surface',
              message: 'Surface disposer threw during teardown',
              detail: err,
            });
          }
        }
      }
      for (const key of Object.keys(slots)) {
        const el = slots[key];
        delete slots[key];
        if (el && el.parentNode && typeof el.parentNode.removeChild === 'function') {
          el.parentNode.removeChild(el);
        }
      }
      for (const key of Object.keys(styles)) {
        const el = styles[key];
        delete styles[key];
        if (el && el.parentNode && typeof el.parentNode.removeChild === 'function') {
          el.parentNode.removeChild(el);
        }
      }
      if (hostEl.parentNode && typeof hostEl.parentNode.removeChild === 'function') {
        hostEl.parentNode.removeChild(hostEl);
      }
    },
  });
}
