import { expect, test } from 'bun:test';
import { PdfLoad } from '../pdfLoad';

const transpiler = new Bun.Transpiler({ loader: 'ts' });
function replacePDFImport(code: string): string {
  const needle = "await import('$lib/pdf')";
  if (code.split(needle).length !== 2) throw new Error('expected one actual PDF import');
  return code.replace(needle, 'await pdfModule()');
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, failed) => { resolve = done; reject = failed; });
  return { promise, resolve, reject };
}
function task() {
  const document = deferred<{ numPages: number }>(), retirement = deferred<void>();
  const started = deferred<void>(), destroying = deferred<void>();
  let destroys = 0;
  return { document, retirement, started, destroying,
    start() { started.resolve(); return new PdfLoad({ promise: document.promise, destroy() { destroys++; destroying.resolve(); return retirement.promise; } }); },
    get destroys() { return destroys; } };
}
const reviewSource = await Bun.file(new URL('./HtmlPDFReview.svelte', import.meta.url)).text();
const reviewStart = reviewSource.indexOf('  async function loadPreview()');
const reviewEnd = reviewSource.indexOf('  async function approve()', reviewStart);
if (reviewStart < 0 || reviewEnd <= reviewStart) throw new Error('actual review callback missing');
const reviewRetirement = reviewSource.slice(reviewSource.indexOf('  // Observe each original retirement'), reviewStart);
const reviewCode = replacePDFImport(reviewRetirement + reviewSource.slice(reviewStart, reviewEnd));
function reviewFixture() {
  const tasks = [task(), task()]; let starts = 0, fetches = 0, alive = true;
  const reported: unknown[][] = [];
  const env: any = { current: () => alive, busy: false, activePDF: null, pdfLoad: null, loadInFlight: false,
    loading: true, error: null, sourceID: 'synthetic-document', sourceSHA: 'a'.repeat(64), abort: new AbortController(), pageCount: 0,
    fetchVerifiedDocumentPDF: async () => { fetches++; return new Uint8Array([1, 2, 3]); },
    pdfModule: async () => ({ startPdfData() { const next = tasks[starts++]; if (!next) throw new Error('unexpected replacement'); return next.start(); } }),
    renderPage: async () => {}, captureFlarePDFViewError: (...args: unknown[]) => reported.push(args) };
  const load = new Function('env', 'with(env) { ' + transpiler.transformSync(reviewCode) + '; return loadPreview; }')(env);
  return { env, tasks, load, reported, navigate() { alive = false; }, get starts() { return starts; }, get fetches() { return fetches; } };
}

test('actual review retry waits for pending parser retirement before creating another task', async () => {
  const f = reviewFixture(); let finished = false;
  const first = f.load().then(() => { finished = true; }); await f.tasks[0].started.promise;
  f.tasks[0].document.reject(new Error('synthetic parser failure')); await f.tasks[0].destroying.promise;
  expect(f.env.loadInFlight).toBe(true); expect(finished).toBe(false);
  const oldOwner = f.env.pdfLoad;
  await f.load(); expect(f.starts).toBe(1); expect(f.fetches).toBe(1); expect(f.env.pdfLoad).toBe(oldOwner);
  f.tasks[0].retirement.resolve(); await first;
  const second = f.load(); await f.tasks[1].started.promise;
  expect(f.starts).toBe(2); expect(f.fetches).toBe(2); expect(f.env.pdfLoad).not.toBe(oldOwner);
  f.tasks[1].document.resolve({ numPages: 2 }); await second;
  expect(f.env.activePDF.numPages).toBe(2); expect(f.env.loading).toBe(false); expect(f.env.error).toBe(null);
  const closing = f.env.pdfLoad.destroy(); f.tasks[1].retirement.resolve(); await closing;
  expect(f.tasks.map(value => value.destroys)).toEqual([1, 1]);
});

test('actual review retains failed retirement and refuses a same-component replacement', async () => {
  const f = reviewFixture(); const first = f.load(); await f.tasks[0].started.promise;
  f.tasks[0].document.reject(new Error('synthetic parser failure')); await f.tasks[0].destroying.promise;
  const oldOwner = f.env.pdfLoad;
  f.tasks[0].retirement.reject(new Error('synthetic cleanup refusal')); await first;
  expect(f.env.error).toBe('The PDF preview could not be closed. Refresh this page before trying again.');
  await f.load(); expect(f.starts).toBe(1); expect(f.fetches).toBe(1); expect(f.env.pdfLoad).toBe(oldOwner);
  expect(f.tasks[0].destroys).toBe(1); expect(f.env.activePDF).toBe(null);
  expect(f.reported).toEqual([[], []]); // parser failure + once-only native retirement failure, even across retry
});

test('actual review navigation during retirement cannot start a replacement', async () => {
  const f = reviewFixture(); const first = f.load(); await f.tasks[0].started.promise;
  f.tasks[0].document.reject(new Error('synthetic parser failure')); await f.tasks[0].destroying.promise;
  f.navigate(); f.tasks[0].retirement.resolve(); await first; await f.load();
  expect(f.starts).toBe(1); expect(f.fetches).toBe(1); expect(f.env.activePDF).toBe(null);
});

const designerSource = await Bun.file(new URL('./PdfFieldDesigner.svelte', import.meta.url)).text();
const designerStart = designerSource.indexOf('  onMount(async () => {');
const designerEnd = designerSource.indexOf('\n  onDestroy(() => {', designerStart);
if (designerStart < 0 || designerEnd <= designerStart) throw new Error('actual designer mount missing');
const designerRetirement = designerSource.slice(designerSource.indexOf('  // Observe each original retirement'), designerStart);
const designerCode = replacePDFImport(designerRetirement + designerSource.slice(designerStart, designerEnd));
function designerFixture(verified: boolean) {
  const pdfTask = task(), recipients = deferred<any[]>(), fields = deferred<any[]>();
  const proofs: boolean[] = [], reported: unknown[][] = []; let mount!: () => Promise<void>;
  const module = { startPdf: () => pdfTask.start(), startPdfData: () => pdfTask.start(), unscaledWidth() { throw new Error('stale parser reached rendering'); } };
  const env: any = { documentID: 'synthetic-document', sourceHTML: verified, sourceSHA: 'a'.repeat(64), sourceCommitment: 'b'.repeat(64),
    retainedSource: null, readonly: true, current: () => true, emitProof: (value: boolean) => proofs.push(value), htmlPlacementPins() {},
    pdfModule: async () => module, listRecipients: () => recipients.promise, listFields: () => fields.promise,
    documentPdfURL: () => '/synthetic.pdf', fetchVerifiedDocumentPDF: async () => new Uint8Array([1, 2, 3]),
    recipients: [], fields: [], pages: [], residentPages: [], recipientID: '', tick: async () => {}, emitSignatureFields() {},
    abort: new AbortController(), pdfLoad: null, pageResidency: undefined, rendered: false, error: null, loading: true,
    captureFlarePDFViewError: (...args: unknown[]) => reported.push(args),
    onMount(callback: () => Promise<void>) { mount = callback; } };
  new Function('env', 'with(env) { ' + transpiler.transformSync(designerCode) + ' }')(env);
  return { env, pdfTask, recipients, fields, proofs, reported, mount: () => mount() };
}
for (const verified of [false, true]) for (const sibling of ['recipients', 'fields'] as const) {
  test('actual designer ' + (verified ? 'verified bytes' : 'URL') + ' retires pending PDF when ' + sibling + ' fail', async () => {
    const f = designerFixture(verified); let finished = false;
    const pending = f.mount().then(() => { finished = true; }); await f.pdfTask.started.promise;
    f[sibling].reject(new Error('synthetic sibling refusal')); await f.pdfTask.destroying.promise;
    expect(f.env.abort.signal.aborted).toBe(true); expect(f.pdfTask.destroys).toBe(1); expect(finished).toBe(false);
    expect(f.proofs).not.toContain(true); expect(f.env.pdfLoad).not.toBe(null);
    f[sibling === 'fields' ? 'recipients' : 'fields'].resolve([]);
    f.pdfTask.document.resolve({ numPages: 2 }); await f.pdfTask.document.promise;
    expect(finished).toBe(false); expect(f.proofs).not.toContain(true);
    f.pdfTask.retirement.resolve(); await pending;
    expect(f.env.rendered).toBe(false); expect(f.env.loading).toBe(false); expect(f.proofs).not.toContain(true);
    expect(f.env.error).toBe('synthetic sibling refusal'); expect(f.pdfTask.destroys).toBe(1);
  });
}

test('actual designer retains a failed retirement instead of granting placement readiness', async () => {
  const f = designerFixture(false); const pending = f.mount(); await f.pdfTask.started.promise;
  f.fields.reject(new Error('synthetic sibling refusal')); await f.pdfTask.destroying.promise;
  const owner = f.env.pdfLoad;
  f.recipients.resolve([]); f.pdfTask.document.resolve({ numPages: 2 });
  f.pdfTask.retirement.reject(new Error('synthetic cleanup refusal')); await pending;
  expect(f.env.error).toBe('The PDF preview could not be closed. Refresh this page before trying again.');
  expect(f.env.pdfLoad).toBe(owner); expect(f.proofs).not.toContain(true); expect(f.env.rendered).toBe(false);
});


test('current review PDF.js failures emit no-argument signals, while stale and expected cancellation outcomes stay silent', async () => {
  for (const mode of ['current', 'stale', 'abort', 'render-cancel'] as const) {
    const f = reviewFixture(), pending = f.load(); await f.tasks[0].started.promise;
    const failure = new Error('PRIVATE parser text /sign/private-token');
    if (mode === 'abort') failure.name = 'AbortError';
    if (mode === 'render-cancel') failure.name = 'RenderingCancelledException';
    if (mode === 'stale') f.navigate();
    f.tasks[0].document.reject(failure); await f.tasks[0].destroying.promise;
    f.tasks[0].retirement.resolve(); await pending;
    expect(f.reported).toEqual(mode === 'current' ? [[]] : []);
    expect(f.tasks[0].destroys).toBe(1);
  }
});

test('review page-limit refusal and pre-PDF verified-fetch refusal do not become PDF.js error telemetry', async () => {
  const limited = reviewFixture(), pending = limited.load(); await limited.tasks[0].started.promise;
  limited.tasks[0].document.resolve({ numPages: 501 }); await limited.tasks[0].destroying.promise;
  limited.tasks[0].retirement.resolve(); await pending;
  expect(limited.reported).toEqual([]); expect(limited.env.activePDF).toBeNull();
  const refused = reviewFixture(); refused.env.fetchVerifiedDocumentPDF = async () => { throw new Error('ordinary verified-source refusal'); };
  await refused.load(); expect(refused.reported).toEqual([]); expect(refused.starts).toBe(0);
});

test('actual review paint catch reports only the current render revision and preserves its existing error state', async () => {
  const start = reviewSource.indexOf('  async function renderPage('), end = reviewSource.indexOf('  // Observe each original retirement', start);
  if (start < 0 || end <= start) throw new Error('actual review paint callback missing');
  const code = replacePDFImport(reviewSource.slice(start, end));
  for (const mode of ['current', 'stale', 'revision', 'abort', 'render-cancel'] as const) {
    const paint = deferred<void>(), started = deferred<void>(), reported: unknown[][] = []; let alive = true;
    const failure = new Error('PRIVATE render text /documents/private-id');
    if (mode === 'abort') failure.name = 'AbortError'; if (mode === 'render-cancel') failure.name = 'RenderingCancelledException';
    const env: any = { current: () => alive, activePDF: {}, busy: false, rendering: false, error: null, revision: 0,
      canvas: {}, pageNumber: 1, seenPages: [], captureFlarePDFViewError: (...args: unknown[]) => reported.push(args),
      pdfModule: async () => ({ unscaledWidth: async () => 100, renderPage() { started.resolve(); return paint.promise; } }) };
    const render = new Function('env', 'with(env) { ' + transpiler.transformSync(code) + '; return renderPage; }')(env);
    const rendering = render(1); await started.promise;
    if (mode === 'stale') alive = false; if (mode === 'revision') env.revision++;
    paint.reject(failure); await rendering;
    expect(reported).toEqual(mode === 'current' ? [[]] : []);
    if (mode === 'current') expect(env.error).toBe(failure.message);
  }
});

test('designer outer Promise.all attributes only its exact PDF rejection, including concurrent and undefined sibling failures', async () => {
  for (const mode of ['pdf', 'pdf-undefined', 'sibling', 'sibling-undefined', 'validation', 'page-limit'] as const) {
    const f = designerFixture(false), privateFailure = new Error('PRIVATE document bytes /sign/private-token');
    if (mode === 'validation') f.env.htmlPlacementPins = () => { throw privateFailure; };
    const pending = f.mount();
    if (mode === 'validation') { await pending; expect(f.reported).toEqual([]); continue; }
    await f.pdfTask.started.promise;
    if (mode === 'pdf' || mode === 'pdf-undefined') { f.recipients.resolve([]); f.fields.resolve([]); f.pdfTask.document.reject(mode === 'pdf' ? privateFailure : undefined); }
    if (mode === 'sibling' || mode === 'sibling-undefined') {
      f.fields.reject(mode === 'sibling' ? new Error('field lookup failed') : undefined);
      f.recipients.resolve([]); f.pdfTask.document.reject(privateFailure);
    }
    if (mode === 'page-limit') {
      f.recipients.resolve([]); f.fields.resolve([]); f.pdfTask.document.resolve({ numPages: 501 });
    }
    await f.pdfTask.destroying.promise; f.pdfTask.retirement.resolve();
    // The existing UI reads Error.message; thrown undefined remains an original
    // callback rejection. It still must never borrow a PDF failure identity.
    if (mode === 'sibling-undefined' || mode === 'pdf-undefined') await expect(pending).rejects.toBeInstanceOf(TypeError);
    else await pending;
    expect(f.reported).toEqual(mode === 'pdf' || mode === 'pdf-undefined' ? [[]] : []);
  }
});

test('review native retirement failure remains the exact original rejection and reports once even after navigation and retry', async () => {
  const f = reviewFixture(), pending = f.load(); await f.tasks[0].started.promise;
  const cancelled = new Error('expected parse cancellation'); cancelled.name = 'AbortError';
  f.tasks[0].document.reject(cancelled); await f.tasks[0].destroying.promise; f.navigate();
  const original = f.env.pdfLoad.destroy(), failure = new Error('PRIVATE native retirement failure');
  f.tasks[0].retirement.reject(failure); await pending;
  await expect(original).rejects.toBe(failure); expect(f.env.pdfLoad.destroy()).toBe(original);
  await f.load(); expect(f.reported).toEqual([[]]); expect(f.tasks[0].destroys).toBe(1);
});


test('actual designer later paint failure captures only a current unexpected outcome and revokes placement proof', async () => {
  for (const mode of ['current', 'stale', 'abort', 'render-cancel'] as const) {
    const f = designerFixture(false); let options: any;
    f.env.ContinuousPDFPages = class {
      constructor(_doc: unknown, provided: any) { options = provided; }
      start() { return Promise.resolve([{ num: 1, w: 760, h: 1075, scale: 1 }]); }
      allPagesRendered() { return true; } stop() {}
    };
    f.env.verifyAssignments = () => {};
    const pending = f.mount(); await f.pdfTask.started.promise;
    f.recipients.resolve([]); f.fields.resolve([]); f.pdfTask.document.resolve({ numPages: 1 }); await pending;
    expect(f.proofs.at(-1)).toBe(true);
    const failure = new Error('PRIVATE current paint failure');
    if (mode === 'stale') f.env.current = () => false;
    if (mode === 'abort') failure.name = 'AbortError';
    if (mode === 'render-cancel') failure.name = 'RenderingCancelledException';
    options.failed(failure);
    expect(f.reported).toEqual(mode === 'current' ? [[]] : []);
    if (mode === 'current') { expect(f.env.rendered).toBe(false); expect(f.proofs.at(-1)).toBe(false); }
    const retirement = f.env.pdfLoad.destroy(); f.pdfTask.retirement.resolve(); await retirement;
  }
});


test('actual designer verified-fetch refusal remains outside PDF.js capture and cannot borrow a later parser error', async () => {
  const f = designerFixture(true); f.env.fetchVerifiedDocumentPDF = async () => { throw new Error('ordinary source/HTTP refusal'); };
  const pending = f.mount(); f.recipients.resolve([]); f.fields.resolve([]); await pending;
  expect(f.reported).toEqual([]); expect(f.pdfTask.destroys).toBe(0); expect(f.env.pdfLoad).toBeNull();
  expect(f.proofs).not.toContain(true); expect(f.env.error).toBe('ordinary source/HTTP refusal');
});
