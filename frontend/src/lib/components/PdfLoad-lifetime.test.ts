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
const reviewCode = replacePDFImport(reviewSource.slice(reviewStart, reviewEnd));
function reviewFixture() {
  const tasks = [task(), task()]; let starts = 0, fetches = 0, alive = true;
  const env: any = { current: () => alive, busy: false, activePDF: null, pdfLoad: null, loadInFlight: false,
    loading: true, error: null, sourceID: 'synthetic-document', sourceSHA: 'a'.repeat(64), abort: new AbortController(), pageCount: 0,
    fetchVerifiedDocumentPDF: async () => { fetches++; return new Uint8Array([1, 2, 3]); },
    pdfModule: async () => ({ startPdfData() { const next = tasks[starts++]; if (!next) throw new Error('unexpected replacement'); return next.start(); } }),
    renderPage: async () => {} };
  const load = new Function('env', 'with(env) { ' + transpiler.transformSync(reviewCode) + '; return loadPreview; }')(env);
  return { env, tasks, load, navigate() { alive = false; }, get starts() { return starts; }, get fetches() { return fetches; } };
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
const designerCode = replacePDFImport(designerSource.slice(designerStart, designerEnd));
function designerFixture(verified: boolean) {
  const pdfTask = task(), recipients = deferred<any[]>(), fields = deferred<any[]>();
  const proofs: boolean[] = []; let mount!: () => Promise<void>;
  const module = { startPdf: () => pdfTask.start(), startPdfData: () => pdfTask.start(), unscaledWidth() { throw new Error('stale parser reached rendering'); } };
  const env: any = { documentID: 'synthetic-document', sourceHTML: verified, sourceSHA: 'a'.repeat(64), sourceCommitment: 'b'.repeat(64),
    retainedSource: null, readonly: true, current: () => true, emitProof: (value: boolean) => proofs.push(value), htmlPlacementPins() {},
    pdfModule: async () => module, listRecipients: () => recipients.promise, listFields: () => fields.promise,
    documentPdfURL: () => '/synthetic.pdf', fetchVerifiedDocumentPDF: async () => new Uint8Array([1, 2, 3]),
    abort: new AbortController(), pdfLoad: null, rendered: false, error: null, loading: true,
    onMount(callback: () => Promise<void>) { mount = callback; } };
  new Function('env', 'with(env) { ' + transpiler.transformSync(designerCode) + ' }')(env);
  return { env, pdfTask, recipients, fields, proofs, mount: () => mount() };
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
