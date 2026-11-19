import { deepFreeze, redactSecrets } from '../security/redactor.js';

const DEFAULT_MAX_EVENTS = 200;

export class DiagnosticsBus {
  #events = [];
  #listeners = new Set();
  #maxEvents;

  constructor({ maxEvents = DEFAULT_MAX_EVENTS } = {}) {
    this.#maxEvents = Math.max(1, Number(maxEvents) || DEFAULT_MAX_EVENTS);
  }

  emit({ level = 'info', code, source, message, detail = null }) {
    const entry = deepFreeze({
      timestamp: new Date().toISOString(),
      level,
      code: String(code || 'UNKNOWN'),
      source: String(source || 'core'),
      message: String(redactSecrets(message || '')),
      detail: detail === null || detail === undefined ? null : redactSecrets(detail),
    });

    this.#events.push(entry);
    if (this.#events.length > this.#maxEvents) {
      this.#events.splice(0, this.#events.length - this.#maxEvents);
    }

    for (const listener of [...this.#listeners]) {
      try {
        listener(entry);
      } catch (_listenerErr) {
        // Isolated listener failure: never break other observers or caller flow.
      }
    }
    return entry;
  }

  subscribe(listener) {
    if (typeof listener !== 'function') {
      throw new TypeError('Diagnostics listener must be a function.');
    }
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  snapshot() {
    return [...this.#events];
  }

  clear() {
    this.#events.length = 0;
  }
}
