import { expect, test } from 'bun:test';
import { PdfLoad } from '../pdfLoad';
import { PdfCanvasBudget, type CanvasGeneration, type PaintOptions } from '../pdfCanvas';
import { ContinuousPDFPages } from '../pdfPageResidency';
import { captureFlarePDFViewError } from '../flare-client';
import { SignerPDFSession, readSignerFieldResponse, renderSignerPDFPages, signerPDFScopeKey, validateSignerPDFFields, validateSignerPDFObservation, type SignerPDFScope } from '../signerPDF';

const source = await Bun.file(new URL('./PdfSignerView.svelte', import.meta.url)).text();
const transpiler = new Bun.Transpiler({ loader: 'ts' });
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
function fixture(failure?: 'fields' | 'count' | 'json' | 'utf8', pendingPDF = false, pendingRetirement = false) {
  const scope: SignerPDFScope = { token: 'original-token', noticeDigest: 'c'.repeat(64), observation: {
    document_id: '10000000-0000-4000-8000-000000000001', recipient_id: '20000000-0000-4000-8000-000000000001', pdf_sha256: 'a'.repeat(64), page_count: 2,
    html_source_commitment: 'b'.repeat(64), materialization_revision: 1
  } };
  let live = signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation);
  const ready: boolean[] = [], renders: { page: number; resolve: (size: { width: number; height: number }) => void; reject: (error: Error) => void }[] = [];
  const headers = { 'Content-Type': 'application/json', 'X-Hash-Document-Id': scope.observation.document_id,
    'X-Hash-Recipient-Id': scope.observation.recipient_id, 'X-Hash-PDF-SHA256': scope.observation.pdf_sha256, 'X-Hash-PDF-Pages': '2',
    'X-Hash-HTML-Source-Commitment': scope.observation.html_source_commitment!, 'X-Hash-Materialization-Revision': '1' };
  let destroyed = 0;
  const reported: unknown[][] = [];
  let resolveDocument!: (document: { numPages: number }) => void;
  let resolveRetirement!: () => void;
  let rejectRetirement!: (reason: unknown) => void;
  const ownedCanvases = new Set<HTMLCanvasElement>();
  const budget = new PdfCanvasBudget(); let generation!: CanvasGeneration;
  // This callback suite controls visibility directly, without installing fake
  // browser globals. The actual residency runner and ledger still execute.
  class VisiblePages extends ContinuousPDFPages<{ numPages: number }> {
    constructor(...args: ConstructorParameters<typeof ContinuousPDFPages<{ numPages: number }>>) {
      super(...args);
      (this as any).observe = () => { (this as any).visible.add(1); (this as any).visible.add(2); };
    }
  }
  const document = pendingPDF ? new Promise<{ numPages: number }>(resolve => { resolveDocument = resolve; }) : Promise.resolve({ numPages: 2 });
  const retirement = pendingRetirement ? new Promise<void>((resolve, reject) => { resolveRetirement = resolve; rejectRetirement = reject; }) : Promise.resolve();
  const env: any = {
    ContinuousPDFPages: VisiblePages, pageOwners: new WeakMap(), observedPDFRetirements: new WeakSet(), residentPages: [],
    pages: [], fields: [], fieldsLoaded: false, documentReady: false, loading: true, error: null,
    buf: {}, persisted: {}, canvasEls: { 1: { width: 760, height: 1000 }, 2: { width: 760, height: 1000 } },
    validateSignerPDFObservation, validateSignerPDFFields, readSignerFieldResponse, renderSignerPDFPages,
    captureFlarePDFViewError: (...args: unknown[]) => { reported.push(args); captureFlarePDFViewError(); },
    fetchSignerPDF: async () => new Uint8Array([1, 2, 3]),
    fetch: async () => new Response(failure === 'json' ? '{"synthetic_private_excerpt":' : failure === 'utf8' ? new Uint8Array([0xff]) : JSON.stringify({ fields: [], count: failure === 'count' ? 1 : 0 }), { headers, status: failure === 'fields' ? 503 : 200 }),
    pdfModule: async () => ({ startPdfData: () => {
      generation = budget.generation();
      return new PdfLoad({ promise: document, destroy() { destroyed++; return retirement; } }, {
        closing: () => budget.closing(generation), retired: () => budget.retired(generation), failed: () => budget.retirementFailed(generation),
      });
    }, pageGeometry: async (_doc: unknown, num: number) => ({ num, w: 760, h: 1000, scale: 1 }),
      recyclePage: (_doc: unknown, canvas: HTMLCanvasElement) => budget.recycle(generation, canvas),
      pageIsResident: (_doc: unknown, canvas: HTMLCanvasElement) => budget.resident(generation, canvas),
      renderPage: async (_doc: unknown, page: number, canvas: HTMLCanvasElement, _scale: number, options: PaintOptions) => {
        const lease = await budget.acquire(generation, canvas, 760, 1000, options);
        try {
          lease.assertCurrent(); canvas.width = 760; canvas.height = 1000;
          const original = new Promise<{ width: number; height: number }>((resolve, reject) => renders.push({ page, resolve, reject }));
          lease.observe(original); return await original;
        } finally { lease.finish(); }
      } }),
    tick: async () => {}, emptyValue: () => '', errorMessage: (error: Error) => error.message,
    onFilledChange() {}, onReadyChange: (value: boolean) => ready.push(value)
  };
  const start = source.indexOf('  async function loadDocument('), end = source.indexOf('  function errorMessage(', start);
  const callback = source.slice(start, end);
  if (start < 0 || end <= start || callback.split("await import('$lib/pdf')").length !== 2) throw new Error('actual signer load callback missing');
  const actual = callback.replace("await import('$lib/pdf')", 'await pdfModule()');
  const callbacks = new Function('env', `with(env) { ${transpiler.transformSync(actual)}; return { loadDocument, retireDocument }; }`)(env);
  const session = new SignerPDFSession(scope, () => live);
  return { env, ready, renders, session, reported, load: () => callbacks.loadDocument(session, ownedCanvases), retire: () => callbacks.retireDocument(session, ownedCanvases), navigate() { live = 'different'; }, resolveDocument: () => resolveDocument({ numPages: 2 }), resolveRetirement: () => resolveRetirement(), rejectRetirement: (reason: unknown) => rejectRetirement(reason), get destroyed() { return destroyed; } };
}

test('actual load callback publishes rendered readiness only after the final page and verified fields', async () => {
  const f = fixture(); const pending = f.load(); await flush();
  expect(f.renders.map(item => item.page)).toEqual([1]); expect(f.ready).toEqual([]);
  f.renders[0].resolve({ width: 760, height: 1000 }); await flush();
  expect(f.renders.map(item => item.page)).toEqual([1, 2]); expect(f.ready).toEqual([]); expect(f.env.documentReady).toBe(false);
  f.renders[1].resolve({ width: 760, height: 1000 }); await pending;
  expect(f.ready).toEqual([true]); expect(f.env.fieldsLoaded).toBe(true); expect(f.env.loading).toBe(false);
  expect(f.reported).toEqual([]);
  expect(f.env.pages).toHaveLength(2);
  await f.session.destroy(); expect(f.destroyed).toBe(1);
});

for (const failure of ['fields', 'count', 'json', 'utf8', 'render', 'navigation', 'dispose'] as const) {
  test(`actual ${failure} failure cannot publish positive document readiness`, async () => {
    const f = fixture(['fields', 'count', 'json', 'utf8'].includes(failure) ? failure as 'fields' | 'count' | 'json' | 'utf8' : undefined);
    const pending = f.load(); await flush();
    if (failure === 'render' || failure === 'navigation' || failure === 'dispose') expect(f.renders).toHaveLength(1);
    if (f.renders.length) {
      if (failure === 'navigation') f.navigate();
      if (failure === 'dispose') f.session.destroy();
      if (failure === 'render') f.renders[0].reject(new Error('render failed'));
      else f.renders[0].resolve({ width: 760, height: 1000 });
    }
    await pending;
    expect(f.ready).not.toContain(true); expect(f.env.documentReady).toBe(false); expect(f.session.current()).toBe(false);
    if (failure !== 'navigation' && failure !== 'dispose') expect(f.ready).toEqual([false]);
    expect(f.reported).toEqual(failure === 'navigation' || failure === 'dispose' ? [] : [[]]);
    if (failure === 'render') expect(f.env.error).toContain('render failed');
    if (failure === 'count') expect(f.env.error).toContain('field list is incomplete');
    if (failure === 'json' || failure === 'utf8') expect(f.env.error).toBe('Unable to load document: The document fields could not be verified. Please reopen your signing link.');
  });
}

for (const reason of ['dispose', 'navigation'] as const) {
  test(`actual ${reason} cancels pending PDF.js loading before document resolution and joins its retirement`, async () => {
    const f = fixture(undefined, true, true);
    const pending = f.load(); await flush();
    expect(f.renders).toHaveLength(0); expect(f.destroyed).toBe(0);
    if (reason === 'navigation') f.navigate();
    const closing = f.session.destroy();
    expect(f.destroyed).toBe(1); expect(f.session.controller.signal.aborted).toBe(true);
    let retired = false; void closing.then(() => { retired = true; });
    await flush(); expect(retired).toBe(false);
    f.resolveDocument(); await pending;
    expect(f.renders).toHaveLength(0); expect(f.ready).not.toContain(true); expect(f.env.documentReady).toBe(false);
    expect(retired).toBe(false);
    f.resolveRetirement(); await closing;
    expect(retired).toBe(true); expect(f.destroyed).toBe(1);
    expect(f.reported).toEqual([]);
  });
}

test('a later page failure removes partial pages and releases their captured canvases only after retirement', async () => {
  const f = fixture(undefined, false, true);
  const pending = f.load(); await flush();
  const firstCanvas = f.env.canvasEls[1], secondCanvas = f.env.canvasEls[2];
  f.renders[0].resolve({ width: 760, height: 1000 }); await flush();
  expect(f.renders.map(item => item.page)).toEqual([1, 2]);
  expect(f.env.pages).toHaveLength(2);
  f.renders[1].reject(new Error('second page failed')); await pending;
  expect(f.env.pages).toEqual([]); expect(f.env.fields).toEqual([]);
  expect(f.env.error).toBe('Unable to load document: second page failed');
  expect(f.env.documentReady).toBe(false); expect(f.env.fieldsLoaded).toBe(false);
  expect(f.ready).toEqual([false]); expect(f.destroyed).toBe(1);
  expect([firstCanvas.width, firstCanvas.height, secondCanvas.width, secondCanvas.height]).toEqual([760, 1000, 760, 1000]);
  const closing = f.retire();
  expect(closing).toBe(f.session.destroy()); expect(f.destroyed).toBe(1);
  f.resolveRetirement(); await closing; await flush();
  expect([firstCanvas.width, firstCanvas.height, secondCanvas.width, secondCanvas.height]).toEqual([0, 0, 0, 0]);
});

test('a stale render failure and late retirement preserve the replacement viewer and its canvases', async () => {
  const f = fixture(undefined, false, true);
  const pending = f.load(); await flush();
  const oldCanvas = f.env.canvasEls[1];
  f.navigate();
  const freshCanvas = { width: 800, height: 1200 };
  const freshPages = [{ num: 1, w: 800, h: 1200 }], freshFields = [{ id: 'fresh-field' }];
  f.env.canvasEls[1] = freshCanvas; f.env.pages = freshPages; f.env.fields = freshFields;
  f.env.documentReady = true; f.env.fieldsLoaded = true; f.env.error = null; f.env.loading = false;
  f.renders[0].reject(new Error('old render failed')); await pending;
  expect(f.env.pages).toBe(freshPages); expect(f.env.fields).toBe(freshFields);
  expect(f.env.documentReady).toBe(true); expect(f.env.error).toBe(null);
  expect(f.ready).toEqual([]); expect(f.destroyed).toBe(1);
  expect([oldCanvas.width, oldCanvas.height]).toEqual([760, 1000]);
  const closing = f.retire(); f.resolveRetirement(); await closing; await flush();
  expect([oldCanvas.width, oldCanvas.height]).toEqual([0, 0]);
  expect([freshCanvas.width, freshCanvas.height]).toEqual([800, 1200]);
  expect(f.env.pages).toBe(freshPages); expect(f.env.fields).toBe(freshFields);
});

test('failed retirement preserves the original rejection and does not clear a possibly active canvas', async () => {
  const f = fixture(undefined, false, true);
  const pending = f.load(); await flush();
  const canvas = f.env.canvasEls[1];
  f.renders[0].reject(new Error('render failed')); await pending;
  const closing = f.retire(), failure = new Error('retirement failed');
  f.rejectRetirement(failure);
  await expect(closing).rejects.toBe(failure); await flush();
  expect(f.retire()).toBe(closing); expect(f.destroyed).toBe(1);
  expect([canvas.width, canvas.height]).toEqual([760, 1000]);
  expect(f.env.pages).toEqual([]); expect(f.env.fields).toEqual([]);
  expect(f.env.documentReady).toBe(false); expect(f.ready).toEqual([false]);
});


test('actual current pre-request PDF validation failure emits only a no-argument signal and keeps failure/retirement semantics', async () => {
  const f = fixture(); const privateFailure = new Error('PRIVATE contract token /sign/secret-value');
  let requests = 0;
  f.env.validateSignerPDFObservation = () => { throw privateFailure; };
  f.env.fetchSignerPDF = async () => { requests++; return new Uint8Array([1]); };
  f.env.fetch = async () => { requests++; throw new Error('unexpected fields request'); };
  await f.load();
  expect(f.reported).toEqual([[]]); expect(requests).toBe(0);
  expect(f.env.error).toBe('Unable to load document: ' + privateFailure.message);
  expect(f.env.documentReady).toBe(false); expect(f.env.fieldsLoaded).toBe(false);
  expect(f.env.loading).toBe(false); expect(f.env.pages).toEqual([]); expect(f.env.fields).toEqual([]);
  expect(f.ready).toEqual([false]); expect(f.session.controller.signal.aborted).toBe(true);
  expect(f.reported[0]).not.toContain(privateFailure);
});


test('actual startup waits for PDF completion before requesting fields and preserves handed-off bytes', async () => {
  const f = fixture(); const bytes = new Uint8Array([1, 2, 3]); let resolvePDF!: (value: Uint8Array) => void;
  let fieldRequests = 0; const fetchFields = f.env.fetch;
  f.env.fetchSignerPDF = () => new Promise<Uint8Array>(resolve => { resolvePDF = resolve; });
  f.env.fetch = (...args: unknown[]) => { fieldRequests++; return fetchFields(...args); };
  const pending = f.load(); await flush(); expect(fieldRequests).toBe(0); expect(f.renders).toHaveLength(0);
  resolvePDF(bytes); await flush(); expect(fieldRequests).toBe(1); expect(f.renders).toHaveLength(1);
  f.renders[0].resolve({ width: 760, height: 1000 }); await flush();
  f.renders[1].resolve({ width: 760, height: 1000 }); await pending;
  expect(f.ready).toEqual([true]); expect(Array.from(bytes)).toEqual([1, 2, 3]);
  await f.session.destroy();
});

test('actual stale or aborted PDF completion cannot start fields and clears pre-transfer bytes', async () => {
  for (const reason of ['navigate', 'abort'] as const) {
    const f = fixture(); const bytes = new Uint8Array([1, 2, 3]); let resolvePDF!: (value: Uint8Array) => void; let fieldRequests = 0;
    f.env.fetchSignerPDF = () => new Promise<Uint8Array>(resolve => { resolvePDF = resolve; });
    f.env.fetch = async () => { fieldRequests++; throw new Error('unexpected stale field request'); };
    const pending = f.load(); await flush();
    if (reason === 'navigate') f.navigate(); else await f.session.destroy();
    resolvePDF(bytes); await pending;
    expect(fieldRequests).toBe(0); expect(f.ready).not.toContain(true); expect(f.reported).toEqual([]);
    expect(Array.from(bytes)).toEqual([0, 0, 0]); expect(f.destroyed).toBe(0);
  }
});

test('actual field refusal clears the fetched PDF before any PDF.js ownership', async () => {
  const f = fixture('fields'); const bytes = new Uint8Array([1, 2, 3]);
  f.env.fetchSignerPDF = async () => bytes;
  await f.load(); expect(Array.from(bytes)).toEqual([0, 0, 0]); expect(f.renders).toHaveLength(0);
  expect(f.destroyed).toBe(0); expect(f.ready).toEqual([false]); expect(f.session.current()).toBe(false);
});

test('actual field cancellation releases pre-transfer PDF bytes without publishing stale readiness', async () => {
  const f = fixture(); const bytes = new Uint8Array([1, 2, 3]); let fieldRequests = 0;
  f.env.fetchSignerPDF = async () => bytes;
  f.env.fetch = (_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
    fieldRequests++; init.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
  });
  const pending = f.load(); await flush(); expect(fieldRequests).toBe(1); expect(Array.from(bytes)).toEqual([1, 2, 3]);
  await f.session.destroy(); await pending;
  expect(Array.from(bytes)).toEqual([0, 0, 0]); expect(f.ready).not.toContain(true); expect(f.renders).toHaveLength(0); expect(f.reported).toEqual([]);
});


test('actual signer callback refuses positive readiness if the completed residency owner stopped before publication', async () => {
  const f = fixture(), ActualOwner = f.env.ContinuousPDFPages;
  f.env.ContinuousPDFPages = class extends ActualOwner {
    async start() { const pages = await super.start(); this.stop(); return pages; }
  };
  const pending = f.load(); await flush();
  f.renders[0].resolve({ width: 760, height: 1000 }); await flush();
  f.renders[1].resolve({ width: 760, height: 1000 }); await pending;
  expect(f.ready).not.toContain(true); expect(f.env.documentReady).toBe(false);
  expect(f.env.error).toContain('stopped before review completed'); expect(f.destroyed).toBe(1);
});


test('actual signer retirement reports a native rejection once after disposal and retains the exact original outcome', async () => {
  const f = fixture(undefined, true, true), pending = f.load(); await flush();
  const original = f.retire(); expect(f.retire()).toBe(original); expect(f.session.destroy()).toBe(original);
  f.navigate(); const failure = new Error('PRIVATE native cleanup error /sign/private-token');
  f.rejectRetirement(failure); await expect(original).rejects.toBe(failure);
  f.resolveDocument(); await pending;
  expect(f.retire()).toBe(original); expect(f.destroyed).toBe(1); expect(f.reported).toEqual([[]]);
  expect(f.ready).not.toContain(true); expect(f.env.documentReady).toBe(false);
});

test('actual signer fulfilled retirement remains silent and preserves its stable original promise after repeated disposal', async () => {
  const f = fixture(undefined, true, true), pending = f.load(); await flush();
  const original = f.retire(); expect(f.retire()).toBe(original); f.navigate(); f.resolveRetirement(); await original;
  f.resolveDocument(); await pending;
  expect(f.retire()).toBe(original); expect(f.session.destroy()).toBe(original);
  expect(f.destroyed).toBe(1); expect(f.reported).toEqual([]); expect(f.ready).not.toContain(true);
});
