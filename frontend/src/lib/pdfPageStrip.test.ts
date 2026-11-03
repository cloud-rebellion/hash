import { expect, test } from 'bun:test';
import { PDFPaintLane, PDFThumbnailWindow, pdfThumbnailPages } from './pdfPageStrip';
import { PdfCanvasBudget } from './pdfCanvas';
import { PdfLoad } from './pdfLoad';
import { checkedCanvasSize } from './pdfViewport';
import { readFileSync } from 'node:fs';

function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
test('five reusable thumbnail positions cover exact first, middle and last pages, with closed page bounds', () => {
  expect(pdfThumbnailPages(1, 500)).toEqual([1, 2, 3, 4, 5]);
  expect(pdfThumbnailPages(250, 500)).toEqual([248, 249, 250, 251, 252]);
  expect(pdfThumbnailPages(500, 500)).toEqual([496, 497, 498, 499, 500]);
  expect(pdfThumbnailPages(2, 2)).toEqual([1, 2]);
  for (const [page, total] of [[0, 500], [501, 500], [1, 501], [1.1, 2], [1, 0]]) expect(() => pdfThumbnailPages(page, total)).toThrow();
});

test('page and thumbnail share the actual native one-waiter generation without parallel allocation', async () => {
  const budget = new PdfCanvasBudget(100), generation = budget.generation(), lane = new PDFPaintLane(() => {});
  const hold = deferred<void>(), started = deferred<void>(), order: string[] = [];
  async function paint(name: string, wait = Promise.resolve()) {
    const canvas = { width: 0, height: 0 };
    const lease = await budget.acquire(generation, canvas, 2, 2); lease.assertCurrent(); order.push(name); started.resolve();
    lease.observe(wait); try { await wait; canvas.width = canvas.height = 2; } finally { lease.finish(); }
  }
  const first = lane.paint('page', () => paint('page', hold.promise)); await started.promise;
  const thumbnail = lane.paint('thumbnail', () => paint('thumbnail'));
  await expect(lane.paint('page', () => paint('duplicate'))).rejects.toThrow('already pending');
  await flush(); expect(order).toEqual(['page']); expect(lane.snapshot()).toMatchObject({ active: true, queued: 1, clients: 2 });
  expect(budget.snapshot().waiting).toBe(0); hold.resolve(); await Promise.all([first, thumbnail]);
  expect(order).toEqual(['page', 'thumbnail']); expect(lane.snapshot()).toMatchObject({ active: false, queued: 0, clients: 0 });
  budget.retired(generation);
});

test('queued abort and lane close refuse unstarted work but never fake completion of an active original paint', async () => {
  const hold = deferred<void>(), entered = deferred<void>(), abort = new AbortController(); let activeFinished = false, queued = 0;
  const lane = new PDFPaintLane(() => {});
  const active = lane.paint('page', async () => { entered.resolve(); await hold.promise; }).then(() => { activeFinished = true; }); await entered.promise;
  const canceled = lane.paint('thumbnail', async () => { queued++; }, abort.signal); abort.abort(); await expect(canceled).rejects.toMatchObject({ name: 'AbortError' });
  const refused = lane.paint('thumbnail', async () => { queued++; }); lane.close(); await expect(refused).rejects.toMatchObject({ name: 'AbortError' });
  await flush(); expect(activeFinished).toBe(false); expect(queued).toBe(0);
  hold.resolve(); await active; expect(activeFinished).toBe(true);
  await expect(lane.paint('page', async () => {})).rejects.toMatchObject({ name: 'AbortError' });
});

test('source invalidation is checked when queued work starts, before invoking native rendering', async () => {
  let current = true, calls = 0; const hold = deferred<void>(), entered = deferred<void>();
  const lane = new PDFPaintLane(() => { if (!current) throw new Error('source changed'); });
  const page = lane.paint('page', async () => { entered.resolve(); await hold.promise; }); await entered.promise;
  const thumb = lane.paint('thumbnail', async () => { calls++; }); current = false; hold.resolve(); await page;
  await expect(thumb).rejects.toThrow('source changed'); expect(calls).toBe(0);
});

function thumbnailFixture(total = 500, pixels = 100_000) {
  const budget = new PdfCanvasBudget(pixels), generation = budget.generation(), lane = new PDFPaintLane(() => {}), doc = { numPages: total };
  const canvases = Array.from({ length: Math.min(total, 5) }, () => ({ width: 0, height: 0 }));
  const states: { slot: number; page: number; state: string }[] = [], paints: number[] = [], failures: unknown[] = [];
  let paintBarrier: ReturnType<typeof deferred<void>> | null = null;
  const window = new PDFThumbnailWindow(doc, {
    current() {}, geometry: async (_doc, page) => ({ num: page, w: 760, h: 1075, scale: 1 }),
    canvas: slot => canvases[slot] as HTMLCanvasElement,
    paint: (_doc, page, canvas, _scale, options) => lane.paint('thumbnail', async () => {
      const lease = await budget.acquire(generation, canvas, 112, 158, options); lease.assertCurrent();
      paints.push(page); const original = paintBarrier?.promise ?? Promise.resolve(); lease.observe(original);
      try { await original; canvas.width = 112; canvas.height = 158; return { width: 112, height: 158 }; } finally { lease.finish(); }
    }, options.signal),
    recycle: (_doc, canvas) => budget.recycle(generation, canvas), resident: (_doc, canvas) => budget.resident(generation, canvas),
    state: (slot, page, state) => states.push({ slot, page, state }), failed: failure => failures.push(failure),
  });
  return { budget, generation, window, states, paints, failures, canvases, barrier: (value: ReturnType<typeof deferred<void>> | null) => { paintBarrier = value; } };
}
async function idle(f: ReturnType<typeof thumbnailFixture>, count: number) { for (let i = 0; i < 100 && f.paints.length < count; i++) await flush(); await flush(); }

test('500-page selection uses only five real native stores and recycles them for the selected window', async () => {
  const f = thumbnailFixture(); f.window.select(250); await idle(f, 5);
  expect(f.paints).toEqual([248, 249, 250, 251, 252]); expect(f.budget.snapshot().stores).toBe(5);
  f.window.select(500); await idle(f, 10);
  expect(f.paints.slice(5)).toEqual([496, 497, 498, 499, 500]); expect(f.budget.snapshot().stores).toBe(5);
  expect(f.canvases.filter(canvas => canvas.width > 0)).toHaveLength(5); expect(f.failures).toEqual([]);
  await f.window.stop(); f.budget.retired(f.generation); expect(f.budget.snapshot().pixels).toBe(0);
});

test('actual native geometry and renderer round fractional portrait and landscape viewports within thumbnail bounds', async () => {
  const source = readFileSync(new URL('./pdf.ts', import.meta.url), 'utf8');
  const geometry = source.slice(source.indexOf('export async function pageGeometry('), source.indexOf('// renderPage paints'));
  const paint = source.slice(source.indexOf('export async function renderPage('), source.indexOf('// unscaledWidth returns'));
  const budget = new PdfCanvasBudget(), generation = budget.generation();
  const env = { checkedCanvasSize, pdfCanvasBudget: budget, canvasOwner: () => generation };
  const native = new Function('env', `with(env) { ${new Bun.Transpiler({ loader: 'ts' }).transformSync(geometry + paint).replaceAll('export ', '')}; return { pageGeometry, renderPage }; }`)(env);
  const shapes = [[595.28, 841.89], [841.89, 595.28], [112.001, 160.001], [760.499, 1075.499]];
  for (const [width, height] of shapes) {
    const doc = { numPages: 1, getPage: async () => ({ getViewport: ({ scale }: { scale: number }) => ({ width: width * scale, height: height * scale }), render: () => ({ promise: Promise.resolve() }) }) };
    const canvas = { width: 0, height: 0, getContext: () => ({}) } as unknown as HTMLCanvasElement, states: string[] = [];
    const thumbnails = new PDFThumbnailWindow(doc, { current() {}, geometry: native.pageGeometry, paint: native.renderPage,
      canvas: () => canvas, recycle: (_doc, value) => budget.recycle(generation, value), resident: (_doc, value) => budget.resident(generation, value),
      state: (_slot, _page, state) => states.push(state), failed: reason => { throw reason; } });
    thumbnails.select(1); for (let i = 0; i < 100 && !states.includes('ready'); i++) await flush();
    expect(states).toContain('ready'); expect(canvas.width).toBeLessThanOrEqual(112); expect(canvas.height).toBeLessThanOrEqual(160);
    await thumbnails.stop(); expect(budget.recycle(generation, canvas)).toBe(true);
  }
  budget.retired(generation);
});

test('rapid selections coalesce while a real paint settles, and never publish its stale page as ready', async () => {
  const f = thumbnailFixture(), hold = deferred<void>(); f.barrier(hold); f.window.select(1); await idle(f, 1);
  f.window.select(100); f.window.select(500); f.barrier(null); hold.resolve(); await idle(f, 6);
  expect(f.paints).toEqual([1, 496, 497, 498, 499, 500]);
  expect(f.states.filter(row => row.page === 1 && row.state === 'ready')).toEqual([]);
  await f.window.stop(); f.budget.retired(f.generation);
});

test('eviction fits the real native budget without an endless repaint loop or fake thumbnail readiness', async () => {
  const f = thumbnailFixture(500, 112 * 158 * 2); f.window.select(250); await idle(f, 5);
  expect(f.paints).toHaveLength(5); expect(f.budget.snapshot().stores).toBeLessThanOrEqual(2);
  await flush(); await flush(); expect(f.paints).toHaveLength(5); expect(f.states.some(row => row.state === 'released')).toBe(true);
  await f.window.stop(); f.budget.retired(f.generation);
});

test('thumbnail cancellation preserves its original rejection and native ownership until stable PdfLoad retirement', async () => {
  const f = thumbnailFixture(1), hold = deferred<void>(), retirement = deferred<void>(); f.barrier(hold);
  const load = new PdfLoad({ promise: Promise.resolve({ numPages: 1 }), destroy: () => retirement.promise }, {
    closing: () => f.budget.closing(f.generation), retired: () => f.budget.retired(f.generation), failed: () => f.budget.retirementFailed(f.generation),
  });
  f.window.select(1); await idle(f, 1); let stopped = false;
  const stopping = f.window.stop().then(() => { stopped = true; }, reason => { stopped = true; throw reason; });
  const closing = load.destroy(); expect(load.destroy()).toBe(closing); await flush(); expect(stopped).toBe(false);
  expect(f.budget.snapshot().pixels).toBe(112 * 158);
  const failure = new Error('original paint refusal'); hold.reject(failure); await expect(stopping).rejects.toBe(failure);
  expect(f.budget.snapshot().pixels).toBe(112 * 158); retirement.reject(new Error('native retirement refused'));
  await expect(closing).rejects.toThrow('native retirement refused'); expect(f.budget.snapshot()).toMatchObject({ blocked: true, pixels: 112 * 158 });
});
