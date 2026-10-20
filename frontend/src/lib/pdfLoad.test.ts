import { expect, test } from 'bun:test';
import { PdfLoad } from './pdfLoad';
import { PdfCanvasBudget } from './pdfCanvas';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, failed) => { resolve = done; reject = failed; });
  return { promise, resolve, reject };
}
const flush = () => new Promise(resolve => setTimeout(resolve, 0));

test('owns a pending parser before document resolution and joins destruction exactly once', async () => {
  const document = deferred<{ numPages: number }>(), retirement = deferred<void>();
  let destroys = 0;
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; return retirement.promise; } });
  expect(load.promise).toBe(document.promise);
  const closing = load.destroy();
  expect(destroys).toBe(1);
  expect(load.destroy()).toBe(closing);
  let joined = false;
  void closing.then(() => { joined = true; });
  await flush(); expect(joined).toBe(false);
  retirement.resolve(); await closing;
  expect(joined).toBe(true); expect(destroys).toBe(1);
  expect(load.destroy()).toBe(closing);
  document.resolve({ numPages: 1 }); expect(await load.promise).toEqual({ numPages: 1 });
});

test('retains destruction rejection and blocks a fresh task behind it', async () => {
  const document = deferred<unknown>(), retirement = deferred<void>();
  const failure = new Error('synthetic retirement refusal');
  let destroys = 0, replacements = 0;
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; return retirement.promise; } });
  const closing = load.destroy();
  const replace = (async () => { await load.destroy(); replacements++; })();
  const outcomes = Promise.allSettled([closing, replace]);
  retirement.reject(failure);
  const settled = await outcomes;
  expect(settled).toHaveLength(2);
  for (const result of settled) {
    expect(result.status).toBe('rejected');
    if (result.status === 'rejected') expect(result.reason).toBe(failure);
  }
  expect(load.destroy()).toBe(closing); expect(destroys).toBe(1); expect(replacements).toBe(0);
  document.resolve(undefined); await document.promise;
});

test('synchronous destroy refusal is the same retained rejected retirement', async () => {
  const failure = new Error('synthetic synchronous refusal');
  let destroys = 0;
  const document = deferred<unknown>();
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; throw failure; } });
  const closing = load.destroy();
  await expect(closing).rejects.toBe(failure);
  expect(load.destroy()).toBe(closing); expect(destroys).toBe(1);
  document.resolve(undefined); await document.promise;
});

test('a sibling initialization failure retires a parser whose document has not resolved', async () => {
  const document = deferred<unknown>(), retirement = deferred<void>();
  let destroys = 0, joined = false;
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; return retirement.promise; } });
  const failure = new Error('synthetic fields refusal');
  const initialize = Promise.all([load.promise, Promise.reject(failure)]).catch(async error => {
    await load.destroy(); joined = true; throw error;
  });
  await flush(); expect(destroys).toBe(1); expect(joined).toBe(false);
  document.resolve(undefined); await document.promise;
  retirement.resolve(); await expect(initialize).rejects.toBe(failure);
  expect(joined).toBe(true);
});

test('throwing closing/retired bookkeeping cannot suppress native destruction or strand its stable fulfilled retirement', async () => {
  for (const phase of ['closing', 'retired'] as const) {
    const budget = new PdfCanvasBudget(16), generation = budget.generation(), store = { width: 0, height: 0 };
    const lease = await budget.acquire(generation, store, 4, 4); store.width = store.height = 4;
    const painted = Promise.resolve(); lease.observe(painted); await painted; lease.finish();
    const original = Promise.resolve({ numPages: 1 }), native = deferred<void>(); let destroys = 0;
    const task = { promise: original, destroy() { expect(this).toBe(task); destroys++; return native.promise; } };
    const load = new PdfLoad(task, {
      closing: () => { if (phase === 'closing') throw new Error('bookkeeping'); budget.closing(generation); },
      retired: () => { if (phase === 'retired') throw new Error('bookkeeping'); budget.retired(generation); },
      failed: () => budget.retirementFailed(generation),
    });
    expect(load.promise).toBe(original);
    const closing = load.destroy(); expect(destroys).toBe(1); expect(load.destroy()).toBe(closing);
    let joined = false; void closing.then(() => { joined = true; }); await flush(); expect(joined).toBe(false);
    expect(budget.snapshot().pixels).toBe(16); // no unconfirmed native retirement is credited
    native.resolve(); await closing;
    expect(joined).toBe(true); expect(destroys).toBe(1); expect(load.destroy()).toBe(closing);
    expect(budget.snapshot().blocked).toBe(true); expect(() => budget.generation()).toThrow('Close another');
    if (phase === 'retired') expect(budget.snapshot().pixels).toBe(16); // cleanup threw, charge remains
  }
});

test('throwing bookkeeping never replaces the original asynchronous or synchronous native destroy failure', async () => {
  for (const kind of ['asynchronous', 'synchronous'] as const) {
    const budget = new PdfCanvasBudget(16), generation = budget.generation(), native = deferred<void>();
    const originalFailure = new Error('original native destroy failure'); let destroys = 0;
    const task = { promise: Promise.resolve({ numPages: 1 }), destroy(): Promise<void> {
      expect(this).toBe(task); destroys++;
      if (kind === 'synchronous') throw originalFailure;
      return native.promise;
    } };
    const load = new PdfLoad(task, {
      closing: () => { throw new Error('bookkeeping closing'); },
      retired: () => { throw new Error('must not retire a native failure'); },
      failed: () => { budget.retirementFailed(generation); throw new Error('bookkeeping failure observer'); },
    });
    const closing = load.destroy();
    if (kind === 'asynchronous') native.reject(originalFailure);
    await expect(closing).rejects.toBe(originalFailure);
    expect(load.destroy()).toBe(closing); expect(destroys).toBe(1); expect(budget.snapshot().blocked).toBe(true);
    expect(load.promise).toBe(task.promise);
  }
});
