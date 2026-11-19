import test from 'node:test';
import assert from 'node:assert/strict';
import { DiagnosticsBus } from '../src/core/diagnostics.js';
import { DisposableStore, EventChain, SingleFlight } from '../src/core/lifecycle.js';
import { RemoteOrchestrator } from '../src/core/orchestrator.js';

test('ARP-TC-009: DisposableStore is idempotent, runs in reverse order, and reports disposer errors', () => {
  const diagnostics = new DiagnosticsBus();
  const store = new DisposableStore({ diagnostics });
  const order = [];

  store.add(() => order.push('first'));
  store.add(() => {
    order.push('failing');
    throw new Error('cleanup boom');
  });
  store.add(() => order.push('last'));

  store.dispose();
  store.dispose(); // idempotent

  assert.deepEqual(order, ['last', 'failing', 'first']);
  const errors = diagnostics.snapshot().filter((e) => e.code === 'DISPOSE_FAILED');
  assert.equal(errors.length, 1);
});

test('ARP-TC-010: EventChain supports arbitrary-order removal and preserves host guard', () => {
  let allow = true;
  const chain = new EventChain({ hostGuard: () => allow });
  const seen = [];

  const offA = chain.register((v) => seen.push(`A:${v}`));
  const offB = chain.register((v) => seen.push(`B:${v}`));
  const offC = chain.register((v) => seen.push(`C:${v}`));

  offB();
  const r1 = chain.dispatch(1);
  assert.deepEqual(r1, { allowed: true, invoked: 2 });
  assert.deepEqual(seen, ['A:1', 'C:1']);

  allow = false;
  const r2 = chain.dispatch(2);
  assert.deepEqual(r2, { allowed: false, invoked: 0 });

  allow = true;
  offA();
  offC();
  assert.equal(chain.size, 0);
});

test('ARP-TC-011: SingleFlight deduplicates concurrent calls and runs fresh after settlement', async () => {
  const sf = new SingleFlight();
  let calls = 0;

  const fetchOnce = async () => {
    calls += 1;
    await new Promise((r) => setTimeout(r, 15));
    return `result-${calls}`;
  };

  const [a, b, c] = await Promise.all([
    sf.run('k', fetchOnce),
    sf.run('k', fetchOnce),
    sf.run('k', fetchOnce),
  ]);
  assert.equal(calls, 1);
  assert.deepEqual([a, b, c], ['result-1', 'result-1', 'result-1']);

  const d = await sf.run('k', fetchOnce);
  assert.equal(calls, 2);
  assert.equal(d, 'result-2');
});

test('ARP-TC-012: RemoteOrchestrator mounts only active plugins and disposes cleanly', async () => {
  const mounted = [];
  const disposed = [];

  const discoveryPort = {
    async listPlugins() {
      return [
        { name: 'active-overlay', disabled: false },
        { name: 'disabled-overlay', disabled: true },
      ];
    },
    async listSidecars() {
      return [];
    },
  };
  const framePort = {
    async acquireActiveFrame() {
      return { win: {}, doc: {} };
    },
    onFrameChange() {
      return () => {};
    },
  };

  const orchestrator = new RemoteOrchestrator({ discoveryPort, framePort });
  orchestrator.registerBridge({
    id: 'b-active',
    pluginName: 'active-overlay',
    async mount() { mounted.push('b-active'); },
    dispose() { disposed.push('b-active'); },
  });
  orchestrator.registerBridge({
    id: 'b-disabled',
    pluginName: 'disabled-overlay',
    async mount() { mounted.push('b-disabled'); },
    dispose() { disposed.push('b-disabled'); },
  });
  orchestrator.registerBridge({
    id: 'b-missing',
    pluginName: 'uninstalled-plugin',
    async mount() { mounted.push('b-missing'); },
    dispose() { disposed.push('b-missing'); },
  });

  const result = await orchestrator.start();
  assert.deepEqual(result.mountedIds, ['b-active']);
  assert.deepEqual(result.skippedIds, ['b-disabled', 'b-missing']);
  assert.deepEqual(mounted, ['b-active']);

  orchestrator.dispose();
  assert.deepEqual(disposed, ['b-active']);
});
