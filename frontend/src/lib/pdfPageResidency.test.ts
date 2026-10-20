import { afterEach, expect, test } from 'bun:test';
import { PdfCanvasBudget, PDF_CANVAS_WAIT_MS } from './pdfCanvas';
import { ContinuousPDFPages, type PDFPageGeometry } from './pdfPageResidency';

const priorWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
const priorObserver = Object.getOwnPropertyDescriptor(globalThis, 'IntersectionObserver');
afterEach(() => {
  if (priorWindow) Object.defineProperty(globalThis, 'window', priorWindow); else delete (globalThis as any).window;
  if (priorObserver) Object.defineProperty(globalThis, 'IntersectionObserver', priorObserver); else delete (globalThis as any).IntersectionObserver;
});
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
class PageElement extends EventTarget {
  constructor(readonly page: number) { super(); }
  getBoundingClientRect() { return { top: this.page * 1000, bottom: this.page * 1000 + 800 }; }
  contains(node: unknown) { return node === this; }
}
function environment() {
  const win = Object.assign(new EventTarget(), { innerHeight: 1200 });
  const observers: Observer[] = [];
  class Observer {
    elements: PageElement[] = [];
    constructor(private callback: (entries: any[]) => void) { observers.push(this); }
    observe(element: PageElement) { this.elements.push(element); this.callback([{ target: element, isIntersecting: element.page <= 2 }]); }
    disconnect() { this.elements = []; }
    show(pages: number[]) { this.callback(this.elements.map(target => ({ target, isIntersecting: pages.includes(target.page) }))); }
  }
  Object.defineProperty(globalThis, 'window', { configurable: true, value: win });
  Object.defineProperty(globalThis, 'IntersectionObserver', { configurable: true, value: Observer });
  return { win, observers };
}
function fixture(count = 50, budget = new PdfCanvasBudget(128), heldPage = 0) {
  const dom = environment(), generation = budget.generation(), held = deferred<void>();
  const canvases = new Map<number, HTMLCanvasElement>(), mounted: PDFPageGeometry[][] = [], successes: number[] = [], failures: unknown[] = [];
  let maxStores = 0, alive = true, rejectPage = 0;
  const ready = new Map<number, boolean>();
  const doc = { numPages: count };
  const owner = new ContinuousPDFPages(doc, {
    current: () => { if (!alive) throw new DOMException('stale source', 'AbortError'); },
    geometry: async (_doc, num) => ({ num, w: 4, h: num % 2 ? 4 : 5, scale: 1 }),
    mount: async pages => {
      mounted.push(pages.map(page => ({ ...page })));
      for (const page of pages) canvases.set(page.num, { width: 0, height: 0, parentElement: new PageElement(page.num) } as any);
    },
    canvas: num => canvases.get(num),
    paint: async (_doc, page, canvas, _scale, options) => {
      const geometry = mounted[0][page - 1], lease = await budget.acquire(generation, canvas, geometry.w, geometry.h, options);
      try {
        lease.assertCurrent(); canvas.width = geometry.w; canvas.height = geometry.h;
        const original = page === heldPage ? held.promise : page === rejectPage ? Promise.reject(new Error('paint refused')) : Promise.resolve();
        lease.observe(original); maxStores = Math.max(maxStores, budget.snapshot().stores);
        await original; successes.push(page); return { width: geometry.w, height: geometry.h };
      } finally { lease.finish(); }
    },
    recycle: (_doc, canvas) => budget.recycle(generation, canvas),
    isResident: (_doc, canvas) => budget.resident(generation, canvas),
    resident: (page, value) => { ready.set(page, value); },
    failed: reason => { failures.push(reason); },
  });
  return { owner, dom, budget, generation, held, mounted, canvases, ready, successes, failures,
    maxStores: () => maxStores, stale() { alive = false; }, reject(page: number) { rejectPage = page; },
    close() { owner.stop(); budget.closing(generation); budget.retired(generation); } };
}

test('an eighty-page mixed-size document genuinely paints every page while retaining at most three stores', async () => {
  const f = fixture(80); const pages = await f.owner.start();
  expect(f.successes).toEqual(Array.from({ length: 80 }, (_, i) => i + 1));
  expect(f.owner.allPagesRendered()).toBe(true); expect(f.maxStores()).toBeLessThanOrEqual(3);
  expect(f.budget.snapshot().stores).toBeLessThanOrEqual(3); expect(pages).toEqual(f.mounted[0]);
  const geometry = pages.map(page => [page.w, page.h]);
  expect(f.canvases.get(79)!.width).toBe(0); expect(geometry[78]).toEqual([4, 4]);
  expect(f.owner.pageReady(79)).toBe(false); expect(f.owner.pageReady(1)).toBe(true);
  f.close(); expect(f.budget.snapshot().pixels).toBe(0);
});

test('visibility and complete geometry cannot substitute for a pending page’s original render promise', async () => {
  const f = fixture(5, new PdfCanvasBudget(128), 2); let complete = false;
  const pending = f.owner.start().then(value => { complete = true; return value; }); await flush();
  expect(f.successes).toEqual([1]); expect(f.mounted[0]).toHaveLength(5);
  expect(f.owner.allPagesRendered()).toBe(false); expect(f.owner.pageReady(2)).toBe(false); expect(complete).toBe(false);
  f.held.resolve(); await pending; expect(f.owner.allPagesRendered()).toBe(true); f.close();
});

test('scroll recycling retains geometry and a focus/active-pointer page while requesting only the new viewport paints', async () => {
  const f = fixture(12); const pages = await f.owner.start(), before = JSON.stringify(pages);
  f.canvases.get(1)!.parentElement!.dispatchEvent(new Event('focusin'));
  const pointer = new Event('pointerdown'); Object.defineProperty(pointer, 'pointerId', { value: 7 });
  f.canvases.get(2)!.parentElement!.dispatchEvent(pointer);
  f.dom.observers[0].show([10, 11]); await flush();
  expect(f.owner.pageReady(1)).toBe(true); expect(f.owner.pageReady(2)).toBe(true);
  expect(f.budget.snapshot().stores).toBeLessThanOrEqual(3); expect(JSON.stringify(pages)).toBe(before);
  f.canvases.get(1)!.parentElement!.dispatchEvent(new Event('focusout'));
  const up = new Event('pointerup'); Object.defineProperty(up, 'pointerId', { value: 7 }); f.dom.win.dispatchEvent(up); await flush();
  expect(f.owner.pageReady(10)).toBe(true); expect(f.owner.pageReady(11)).toBe(true);
  expect(f.owner.allPagesRendered()).toBe(true); expect(JSON.stringify(pages)).toBe(before); f.close();
});

test('a later viewport repaint error revokes the same generation’s proof instead of silently keeping historical readiness', async () => {
  const f = fixture(8); await f.owner.start(); expect(f.owner.allPagesRendered()).toBe(true);
  f.reject(7); f.dom.observers[0].show([7]); await flush();
  expect(f.failures).toHaveLength(1); expect(f.owner.allPagesRendered()).toBe(false); expect(f.owner.pageReady(7)).toBe(false); f.close();
});

test('stopping a queued/active document disconnects observers but does not manufacture native render cancellation or release', async () => {
  const f = fixture(6, new PdfCanvasBudget(128), 2), pending = f.owner.start(); await flush();
  f.owner.stop(); await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  expect(f.budget.snapshot().painting).toBe(true); expect(f.dom.observers[0].elements).toEqual([]);
  f.budget.closing(f.generation); f.budget.retired(f.generation);
  expect(f.budget.snapshot().pixels).toBeGreaterThan(0);
  f.held.resolve(); await flush(); expect(f.budget.snapshot().pixels).toBe(0); expect(f.owner.allPagesRendered()).toBe(false);
});

test('source replacement before a real paint completes cannot publish positive resident or all-page proof', async () => {
  const f = fixture(4, new PdfCanvasBudget(128), 2), pending = f.owner.start(); await flush();
  f.stale(); f.held.resolve(); await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  expect(f.owner.allPagesRendered()).toBe(false); expect(f.owner.pageReady(2)).toBe(false); f.close();
});

test('window pointerup capture keeps the exact page pinned through its drop handler and releases only that pointer afterward', async () => {
  const f = fixture(9); await f.owner.start();
  const element = f.canvases.get(1)!.parentElement!;
  const event = (name: string) => { const event = new Event(name); Object.defineProperty(event, 'pointerId', { value: 9 }); return event; };
  element.dispatchEvent(event('pointerdown'));
  f.dom.observers[0].show([7, 8]); await flush(); expect(f.owner.pageReady(1)).toBe(true);
  f.dom.win.dispatchEvent(event('pointerup'));
  // The application's real target handler runs after window capture in this
  // same dispatch turn. Its field geometry is still backed by the prior paint.
  expect(f.owner.pageReady(1)).toBe(true);
  await flush(); expect(f.owner.pageReady(1)).toBe(false);
  expect(f.owner.pageReady(7)).toBe(true); expect(f.owner.pageReady(8)).toBe(true); f.close();
});

test('relieving three pinned stores cancels the finite pause timer so completed rendering cannot fail later', async () => {
  const nativeSet = globalThis.setTimeout, nativeClear = globalThis.clearTimeout;
  const timers = new Map<object, { callback: () => void; active: boolean }>();
  globalThis.setTimeout = ((callback: () => void, delay?: number, ...args: unknown[]) => {
    if (delay !== PDF_CANVAS_WAIT_MS) return (nativeSet as any)(callback, delay, ...args);
    const token = {}; timers.set(token, { callback, active: true }); return token;
  }) as typeof setTimeout;
  globalThis.clearTimeout = ((token: any) => {
    const timer = timers.get(token); if (timer) timer.active = false; else nativeClear(token);
  }) as typeof clearTimeout;
  let f: ReturnType<typeof fixture> | undefined;
  try {
    f = fixture(9, new PdfCanvasBudget(128), 3); const pending = f.owner.start(); await flush();
    for (let page = 1; page <= 3; page++) {
      const event = new Event('pointerdown'); Object.defineProperty(event, 'pointerId', { value: page });
      f.canvases.get(page)!.parentElement!.dispatchEvent(event);
    }
    f.held.resolve(); await flush();
    expect([...timers.values()].filter(timer => timer.active)).toHaveLength(1);
    expect(f.owner.allPagesRendered()).toBe(false);
    for (let page = 1; page <= 3; page++) {
      const event = new Event('pointerup'); Object.defineProperty(event, 'pointerId', { value: page }); f.dom.win.dispatchEvent(event);
    }
    await pending; expect(f.owner.allPagesRendered()).toBe(true);
    expect([...timers.values()].filter(timer => timer.active)).toHaveLength(0);
    // Advance the controlled clock: only live timers may fire, as in the host.
    for (const timer of timers.values()) if (timer.active) timer.callback();
    expect(f.failures).toEqual([]); expect(f.owner.allPagesRendered()).toBe(true);
  } finally { f?.close(); globalThis.setTimeout = nativeSet; globalThis.clearTimeout = nativeClear; }
});
