import { expect, test } from 'bun:test';
import { PdfCanvasBudget, PDF_CANVAS_PIXELS, PDF_CANVAS_LOGICAL_BYTES } from './pdfCanvas';
import { PdfLoad } from './pdfLoad';

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, failed) => { resolve = done; reject = failed; });
  return { promise, resolve, reject };
}
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
const canvas = () => ({ width: 0, height: 0 });
async function painted(budget: PdfCanvasBudget, owner: ReturnType<PdfCanvasBudget['generation']>, store: ReturnType<typeof canvas>, size = 4, evictable = false) {
  const lease = await budget.acquire(owner, store, size, size, { evictable: () => evictable });
  store.width = size; store.height = size;
  const original = Promise.resolve(); lease.observe(original); await original; lease.finish();
}

test('tab policy is logical RGBA only and four independent owners share one synchronous paint reservation', async () => {
  expect(PDF_CANVAS_PIXELS).toBe(32 * 1024 * 1024); expect(PDF_CANVAS_LOGICAL_BYTES).toBe(128 * 1024 * 1024);
  const budget = new PdfCanvasBudget(64), owners = Array.from({ length: 4 }, () => budget.generation());
  const stores = owners.map(canvas), promises = owners.map((owner, i) => budget.acquire(owner, stores[i], 4, 4));
  const first = await promises[0]; expect(budget.snapshot()).toMatchObject({ pixels: 16, waiting: 3, painting: true });
  const original = deferred<void>(); first.observe(original.promise); first.finish();
  await flush(); expect(budget.snapshot().waiting).toBe(3);
  original.resolve(); await original.promise; await flush();
  const second = await promises[1]; expect(budget.snapshot()).toMatchObject({ pixels: 32, waiting: 2, painting: true });
  second.finish(); const third = await promises[2]; third.finish(); const fourth = await promises[3]; fourth.finish();
  expect(budget.snapshot().pixels).toBe(64);
  for (const owner of owners) { budget.closing(owner); budget.retired(owner); }
  expect(budget.snapshot()).toMatchObject({ pixels: 0, stores: 0, owners: 0 });
});

test('allocation cannot double-grant the final capacity across callers and releases zero before waking a waiter', async () => {
  const budget = new PdfCanvasBudget(32), a = budget.generation(), b = budget.generation(), c = budget.generation();
  const one = canvas(), two = canvas(), three = canvas();
  await painted(budget, a, one); await painted(budget, b, two);
  let granted = false; const pending = budget.acquire(c, three, 4, 4).then(lease => { granted = true; return lease; });
  await flush(); expect(granted).toBe(false); expect(budget.snapshot().pixels).toBe(32);
  expect(budget.recycle(a, one)).toBe(true); expect([one.width, one.height]).toEqual([0, 0]);
  const lease = await pending; expect(granted).toBe(true); expect(budget.snapshot().pixels).toBe(32); lease.finish();
  for (const owner of [a, b, c]) budget.retired(owner);
});

test('native destruction alone cannot free an unsettled original render or let another generation reuse its canvas', async () => {
  const budget = new PdfCanvasBudget(32), old = budget.generation(), fresh = budget.generation(), store = canvas();
  const lease = await budget.acquire(old, store, 4, 4); store.width = store.height = 4;
  const native = deferred<void>(); lease.observe(native.promise); lease.finish();
  budget.closing(old); budget.retired(old);
  let granted = false; const pending = budget.acquire(fresh, store, 4, 4).then(value => { granted = true; return value; });
  await flush(); expect(granted).toBe(false); expect(store.width).toBe(4); expect(budget.snapshot().pixels).toBe(16);
  native.resolve(); await native.promise;
  const next = await pending; expect([store.width, store.height]).toEqual([0, 0]);
  store.width = store.height = 4; next.finish(); budget.retired(old);
  expect(store.width).toBe(4); expect(budget.snapshot().pixels).toBe(16); budget.retired(fresh);
});

test('a pending original render rejection preserves its object and keeps the charge until settlement', async () => {
  const budget = new PdfCanvasBudget(16), owner = budget.generation(), store = canvas();
  const lease = await budget.acquire(owner, store, 4, 4), native = deferred<void>(), failure = new Error('render cancelled');
  lease.observe(native.promise); lease.finish();
  expect(budget.recycle(owner, store)).toBe(false); expect(budget.snapshot().painting).toBe(true);
  native.reject(failure); await expect(native.promise).rejects.toBe(failure); await flush();
  expect(budget.snapshot().painting).toBe(false); expect(budget.recycle(owner, store)).toBe(true); budget.retired(owner);
});

test('failed native retirement preserves the public rejection, freezes unresolved stores and refuses all new admission', async () => {
  const budget = new PdfCanvasBudget(32), owner = budget.generation(), store = canvas(), native = deferred<void>();
  const original = Promise.resolve({ numPages: 1 }); let destroys = 0;
  const load = new PdfLoad({ promise: original, destroy() { destroys++; return native.promise; } }, {
    closing: () => budget.closing(owner), retired: () => budget.retired(owner), failed: () => budget.retirementFailed(owner),
  });
  expect(load.promise).toBe(original); await painted(budget, owner, store);
  const close = load.destroy(), failure = new Error('destroy failed'); native.reject(failure);
  await expect(close).rejects.toBe(failure); expect(load.destroy()).toBe(close); expect(destroys).toBe(1);
  expect(budget.snapshot()).toMatchObject({ pixels: 16, blocked: true }); expect(store.width).toBe(4);
  expect(budget.recycle(owner, store)).toBe(false); expect(() => budget.generation()).toThrow('Close another');
});

test('a granted owner retired before continuation cannot allocate or invoke a native renderer', async () => {
  const budget = new PdfCanvasBudget(32), owner = budget.generation(), store = canvas();
  const pending = budget.acquire(owner, store, 4, 4); budget.closing(owner); budget.retired(owner);
  const lease = await pending; expect(() => lease.assertCurrent()).toThrow('closed');
  expect(store.width).toBe(0); lease.finish(); expect(budget.snapshot().pixels).toBe(0);
});

test('queues are one per owner, cancelable, and have a finite admission deadline', async () => {
  const budget = new PdfCanvasBudget(16, 5), a = budget.generation(), b = budget.generation();
  await painted(budget, a, canvas());
  const abort = new AbortController(), pending = budget.acquire(b, canvas(), 4, 4, { signal: abort.signal });
  await expect(budget.acquire(b, canvas(), 4, 4)).rejects.toThrow('busy');
  abort.abort(); await expect(pending).rejects.toMatchObject({ name: 'AbortError' }); expect(budget.snapshot().waiting).toBe(0);
  await expect(budget.acquire(b, canvas(), 4, 4)).rejects.toThrow('Close another');
  expect(budget.snapshot().waiting).toBe(0); budget.retired(a); budget.retired(b);
});

test('visible requests have priority but a waiting background owner cannot starve behind five visible paints', async () => {
  const budget = new PdfCanvasBudget(128), first = budget.generation(), hold = await budget.acquire(first, canvas(), 1, 1);
  const background = budget.generation(), order: string[] = [];
  const bg = budget.acquire(background, canvas(), 1, 1, { priority: 'background' }).then(lease => { order.push('background'); lease.finish(); });
  const visible = Array.from({ length: 5 }, (_, i) => budget.acquire(budget.generation(), canvas(), 1, 1).then(lease => { order.push(String(i)); lease.finish(); }));
  hold.finish(); await Promise.all([bg, ...visible]);
  expect(order.slice(0, 3)).toEqual(['0', '1', '2']); expect(order.indexOf('background')).toBeLessThan(5);
});

test('only settled explicitly evictable stores can yield capacity and a failed zero never returns charge', async () => {
  const budget = new PdfCanvasBudget(16), a = budget.generation(), b = budget.generation(), store = canvas();
  await painted(budget, a, store, 4, true); const next = await budget.acquire(b, canvas(), 4, 4); expect(store.width).toBe(0); next.finish();
  budget.retired(a); budget.retired(b);
  const failing = new PdfCanvasBudget(16), owner = failing.generation(); let width = 4;
  const bad = { get width() { return width; }, set width(value) { if (!value) throw new Error('zero failed'); width = value; }, height: 4 };
  const lease = await failing.acquire(owner, bad, 4, 4); lease.finish();
  expect(failing.recycle(owner, bad)).toBe(false); expect(failing.snapshot()).toMatchObject({ pixels: 16, blocked: true });
});

test('metadata admission caps owners at32 and settled stores at3 per owner even for one-pixel pages', async () => {
  const budget = new PdfCanvasBudget(128), owners = Array.from({ length: 32 }, () => budget.generation());
  expect(() => budget.generation()).toThrow('Close another');
  for (const owner of owners) for (let i = 0; i < 3; i++) await painted(budget, owner, canvas(), 1);
  expect(budget.snapshot()).toMatchObject({ stores: 96, owners: 32, pixels: 96 });
  const abort = new AbortController();
  const blocked = budget.acquire(owners[0], canvas(), 1, 1, { signal: abort.signal });
  await flush(); expect(budget.snapshot()).toMatchObject({ stores: 96, waiting: 1 });
  abort.abort(); await expect(blocked).rejects.toMatchObject({ name: 'AbortError' });
  for (const owner of owners) budget.retired(owner);
  expect(budget.snapshot()).toMatchObject({ stores: 0, owners: 0, pixels: 0 });
});
