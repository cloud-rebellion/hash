import { expect, test } from 'bun:test';
import { PdfCanvasBudget } from './pdfCanvas';
import { PdfLoad } from './pdfLoad';
import { checkedCanvasSize } from './pdfViewport';

const source = await Bun.file(new URL('./pdf.ts', import.meta.url)).text();
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (error: unknown) => void; const promise = new Promise<T>((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
function actualPath(task: any) {
  const budget = new PdfCanvasBudget(), args: unknown[] = [];
  const start = source.indexOf('const canvasOwners ='), end = source.indexOf('// unscaledWidth', start);
  if (start < 0 || end <= start) throw new Error('Actual shared PDF ownership/render path moved');
  const code = transpiler.transformSync(source.slice(start, end).replaceAll('export ', ''));
  const path = new Function('pdfjsLib', 'PdfLoad', 'pdfCanvasBudget', 'checkedCanvasSize', `${code}; return {startPdfData, startPdf, renderPage, pageGeometry, recyclePage, pageIsResident};`)(
    { getDocument(value: unknown) { args.push(value); return task; } }, PdfLoad, budget, checkedCanvasSize,
  );
  return { budget, args, ...path };
}
const flush = () => new Promise(resolve => setTimeout(resolve, 0));

test('actual loading wrapper retains the native promise/data and native destroy receiver exactly once', async () => {
  const parsed = deferred<any>(), retired = deferred<void>(); let destroys = 0;
  const native = { promise: parsed.promise, destroy() { expect(this).toBe(native); destroys++; return retired.promise; } };
  const actual = actualPath(native), data = new Uint8Array([1, 2, 3]);
  const load = actual.startPdfData(data); expect(load.promise).toBe(parsed.promise); expect(actual.args).toEqual([{ data }]);
  const closing = load.destroy(); expect(load.destroy()).toBe(closing); expect(destroys).toBe(1);
  parsed.resolve({}); retired.resolve(); await closing; expect(actual.budget.snapshot().owners).toBe(0);
  expect(Array.from(data)).toEqual([1, 2, 3]);
});

test('actual render path forwards native render receiver/arguments, leaves task/continuation/promise intact and joins settlement before reuse', async () => {
  const parsed = deferred<any>(), retired = deferred<void>(), first = deferred<void>(), second = deferred<void>();
  const nativeLoad = { promise: parsed.promise, destroy: () => retired.promise }, actual = actualPath(nativeLoad);
  const continuation = () => {}, nativeTasks = [{ promise: first.promise, onContinue: continuation }, { promise: second.promise, onContinue: continuation }];
  const calls: any[] = [], sizes: number[] = []; let width = 0, height = 0;
  const context = {}, canvas = {
    getContext: () => context,
    get width() { return width; }, set width(value: number) { sizes.push(value); width = value; },
    get height() { return height; }, set height(value: number) { sizes.push(value); height = value; },
  };
  const pages = [1, 2].map((number, i) => ({
    getViewport: () => ({ width: 760, height: number === 1 ? 1000 : 1100 }),
    render(options: any) { expect(this).toBe(pages[i]); calls.push(options); return nativeTasks[i]; },
  }));
  const doc = { getPage: async (number: number) => pages[number - 1] };
  const load = actual.startPdfData(new Uint8Array([1])); parsed.resolve(doc); await load.promise;
  const one = actual.renderPage(doc, 1, canvas, 1); await flush();
  const two = actual.renderPage(doc, 2, canvas, 1); await flush(); expect(calls).toHaveLength(1);
  expect(nativeTasks[0].promise).toBe(first.promise); expect(nativeTasks[0].onContinue).toBe(continuation);
  expect(calls[0]).toEqual({ canvas, canvasContext: context, viewport: { width: 760, height: 1000 } });
  first.resolve(); expect(await one).toEqual({ width: 760, height: 1000 }); await flush();
  expect(calls).toHaveLength(2); expect(sizes).toEqual([760, 1000, 0, 0, 760, 1100]);
  expect(actual.budget.snapshot().stores).toBe(1); second.resolve(); await two;
  const closing = load.destroy(); retired.resolve(); await closing;
  expect([width, height]).toEqual([0, 0]); expect(actual.budget.snapshot().pixels).toBe(0);
});

test('actual render path preserves the original rejection and does not touch unsafe geometry or an unowned document', async () => {
  const parsed = deferred<any>(), actual = actualPath({ promise: parsed.promise, destroy: async () => {} });
  let touched = 0; const canvas = { getContext() { touched++; return {}; }, set width(_: number) { touched++; }, set height(_: number) { touched++; } };
  const doc = { getPage: async () => ({ getViewport: () => ({ width: 5000, height: 5000 }), render() { touched++; return { promise: Promise.resolve() }; } }) };
  await expect(actual.renderPage(doc, 1, canvas, 1)).rejects.toThrow('safe preview dimensions'); expect(touched).toBe(0);
  const safeUnowned = { getPage: async () => ({ getViewport: () => ({ width: 760, height: 1000 }) }) };
  await expect(actual.renderPage(safeUnowned, 1, canvas, 1)).rejects.toThrow('no preview owner'); expect(touched).toBe(0);
  const native = deferred<void>(), failure = new Error('original rendering cancelled');
  const owned = { getPage: async () => ({ getViewport: () => ({ width: 760, height: 1000 }), render: () => ({ promise: native.promise }) }) };
  const load = actual.startPdfData(new Uint8Array([1])); parsed.resolve(owned); await load.promise;
  const painting = actual.renderPage(owned, 1, { width: 0, height: 0, getContext: () => ({}) }, 1); await flush();
  native.reject(failure); await expect(painting).rejects.toBe(failure); await load.destroy();
});
