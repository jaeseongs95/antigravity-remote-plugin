export class DisposableStore {
  #disposers = [];
  #disposed = false;
  #diagnostics;

  constructor({ diagnostics = null } = {}) {
    this.#diagnostics = diagnostics;
  }

  get isDisposed() {
    return this.#disposed;
  }

  get size() {
    return this.#disposers.length;
  }

  add(disposable) {
    const fn =
      typeof disposable === 'function'
        ? disposable
        : disposable && typeof disposable.dispose === 'function'
          ? () => disposable.dispose()
          : null;

    if (!fn) {
      throw new TypeError('Disposable must be a function or an object with dispose().');
    }

    if (this.#disposed) {
      this.#invokeSafe(fn, 'late-add');
      return () => {};
    }

    let active = true;
    const entry = () => {
      if (!active) {
        return;
      }
      active = false;
      fn();
    };
    this.#disposers.push(entry);

    return () => {
      if (!active) {
        return;
      }
      active = false;
      const idx = this.#disposers.indexOf(entry);
      if (idx !== -1) {
        this.#disposers.splice(idx, 1);
      }
      this.#invokeSafe(fn, 'manual-remove');
    };
  }

  dispose() {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    const toRun = this.#disposers.splice(0, this.#disposers.length).reverse();
    for (const fn of toRun) {
      this.#invokeSafe(fn, 'store-dispose');
    }
  }

  #invokeSafe(fn, phase) {
    try {
      fn();
    } catch (err) {
      if (this.#diagnostics) {
        this.#diagnostics.emit({
          level: 'error',
          code: 'DISPOSE_FAILED',
          source: 'core.lifecycle',
          message: `Disposer failed during ${phase}`,
          detail: err,
        });
      }
    }
  }
}

/**
 * Composable, arbitrary-order safe hook chain that preserves host guard semantics.
 * Removing any handler never breaks remaining handlers or the underlying host callback.
 */
export class EventChain {
  #handlers = new Map();
  #nextId = 1;
  #hostGuard;
  #diagnostics;

  constructor({ hostGuard = null, diagnostics = null } = {}) {
    this.#hostGuard = typeof hostGuard === 'function' ? hostGuard : null;
    this.#diagnostics = diagnostics;
  }

  get size() {
    return this.#handlers.size;
  }

  register(handler, { label = 'anonymous' } = {}) {
    if (typeof handler !== 'function') {
      throw new TypeError('EventChain handler must be a function.');
    }
    const id = this.#nextId++;
    this.#handlers.set(id, { handler, label });
    return () => {
      this.#handlers.delete(id);
    };
  }

  dispatch(...args) {
    let guardResult = true;
    if (this.#hostGuard) {
      guardResult = this.#hostGuard(...args);
      if (guardResult === false) {
        return { allowed: false, invoked: 0 };
      }
    }

    let invoked = 0;
    for (const { handler, label } of [...this.#handlers.values()]) {
      try {
        handler(...args);
        invoked += 1;
      } catch (err) {
        if (this.#diagnostics) {
          this.#diagnostics.emit({
            level: 'error',
            code: 'EVENT_CHAIN_HANDLER_FAILED',
            source: 'core.lifecycle',
            message: `Handler "${label}" threw during dispatch`,
            detail: err,
          });
        }
      }
    }
    return { allowed: guardResult, invoked };
  }

  clear() {
    this.#handlers.clear();
  }
}

/**
 * Coalesces concurrent async operations by key to prevent duplicate discovery RPCs.
 */
export class SingleFlight {
  #inflight = new Map();

  async run(key, taskFn) {
    if (typeof taskFn !== 'function') {
      throw new TypeError('SingleFlight taskFn must be a function.');
    }
    const existing = this.#inflight.get(key);
    if (existing) {
      return existing;
    }
    const promise = Promise.resolve()
      .then(() => taskFn())
      .finally(() => {
        if (this.#inflight.get(key) === promise) {
          this.#inflight.delete(key);
        }
      });
    this.#inflight.set(key, promise);
    return promise;
  }

  get activeCount() {
    return this.#inflight.size;
  }
}
