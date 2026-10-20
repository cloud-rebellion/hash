import { expect, test } from 'bun:test';
import { PdfLoad } from '../pdfLoad';

const transpiler = new Bun.Transpiler({ loader: 'ts' });
const signer = await Bun.file(new URL('./PdfSignerView.svelte', import.meta.url)).text();
const designer = await Bun.file(new URL('./PdfFieldDesigner.svelte', import.meta.url)).text();
function bind(source: string, from: string, to: string, names: string[], env: any) {
  const start = source.indexOf(from), end = source.indexOf(to, start);
  if (start < 0 || end <= start) throw new Error('Actual field callback boundary moved');
  return new Function('env', `with(env) { ${transpiler.transformSync(source.slice(start, end))}; return {${names.join(',')}}; }`)(env);
}

test('actual signer save and signing gate preserve confirmed values and actionable autosave errors through bitmap residency changes', async () => {
  const field = { id: 'field-1', document_id: 'document', type: 'text', required: true, value: 'confirmed', page: 1 };
  const env: any = {
    session: { current: () => true, assertCurrent() {}, scope: { token: 'fixture-only', noticeDigest: 'a'.repeat(64), observation: {} }, controller: new AbortController() },
    signed: false, readOnly: false, documentReady: true, loading: false, fieldsLoaded: true, error: null,
    fields: [field], pages: [{ num: 1, w: 760, h: 1075 }], residentPages: [1],
    buf: { 'field-1': 'draft' }, persisted: { 'field-1': 'confirmed' }, saving: {}, saveErrors: {},
    emptyValue: () => '', isFilled: (_field: unknown, value: string) => !!value.trim(),
    signerNoticeHeaders: () => ({}), fetch: async () => { throw new Error('save unavailable'); },
    readSignerFieldResponse: async () => { throw new Error('must not parse a failed request'); },
    validateSignerPDFFields: () => [], confirmSignerPDFField() {}, errorMessage: (error: Error) => error.message,
  };
  const { saveField } = bind(signer, '  async function saveField(', '  function fieldsOnPage(', ['saveField'], env);
  const { recomputeFilled } = bind(signer, '  function recomputeFilled()', '  $effect(() => {', ['recomputeFilled'], env);
  const maps = [env.buf, env.persisted, env.saving, env.saveErrors];
  env.residentPages = []; // the field/overlay DOM and autosave state stay owned
  await saveField(field);
  expect(env.buf['field-1']).toBe('confirmed'); expect(env.persisted['field-1']).toBe('confirmed');
  expect(env.saveErrors['field-1']).toBe('save unavailable'); expect(env.saving['field-1']).toBe(false);
  expect(recomputeFilled()).toBe(false); env.residentPages = [1]; expect(recomputeFilled()).toBe(false);
  [env.buf, env.persisted, env.saving, env.saveErrors].forEach((map, i) => expect(map).toBe(maps[i]));
});

test('actual designer rejects placement on recycled pages and preserves page-relative saved geometry once a current paint is ready', async () => {
  let ready = false; const writes: any[] = [], failures: unknown[] = [];
  const env: any = {
    dragStart: null, draft: null, readonly: false, generated: false, placementUnavailable: false,
    current: () => true, documentID: 'document', sourceHTML: true, sourceSHA: 'a'.repeat(64), sourceCommitment: 'b'.repeat(64),
    pageResidency: { pageReady: () => ready }, pages: [{ num: 2, w: 760, h: 1075 }], tool: 'text', recipientID: 'party', required: true,
    error: null, saving: false, fields: [], TOOLS: [{ type: 'text', label: 'Text' }],
    round: (n: number) => Math.round(n * 1000) / 1000,
    htmlPlacementPins: () => ({ expected_pdf_sha256: 'a'.repeat(64), expected_html_source_commitment: 'b'.repeat(64) }),
    addField: async (document: string, input: any) => { writes.push({ document, input }); return { ...input, document_id: document, id: 'created' }; },
    emitSignatureFields: () => {},
  };
  const callbacks = bind(designer, '  function pctFromEvent(', '  function round(', ['onPointerDown', 'onPointerMove', 'onPointerUp', 'cancelPlacement'], env);
  const layer = { getBoundingClientRect: () => ({ left: 100, top: 200, width: 760, height: 1075 }), setPointerCapture() {} };
  const down = { isPrimary: true, button: 0, pointerId: 3, clientX: 176, clientY: 415 };
  callbacks.onPointerDown(down, 2, layer); expect(env.dragStart).toBe(null); expect(writes).toEqual([]);
  ready = true; callbacks.onPointerDown(down, 2, layer);
  callbacks.onPointerMove({ ...down, clientX: 328, clientY: 522.5 }, layer); await callbacks.onPointerUp(down);
  expect(writes).toHaveLength(1);
  expect(writes[0]).toEqual({ document: 'document', input: {
    type: 'text', page: 2, x_pct: 10, y_pct: 20, w_pct: 20, h_pct: 10, required: true, recipient_id: 'party', label: 'Text',
    expected_pdf_sha256: 'a'.repeat(64), expected_html_source_commitment: 'b'.repeat(64),
  } });
  expect(env.saving).toBe(false); expect(env.error).toBe(null); expect(failures).toEqual([]);
  callbacks.onPointerDown(down, 2, layer); ready = false; await callbacks.onPointerUp(down);
  expect(writes).toHaveLength(1); // historical all-page readiness never authorizes a blank current page
});

test('actual designer cannot publish completed placement proof from an owner stopped after its ready promise fulfilled', async () => {
  let mount!: () => Promise<void>, destroys = 0; const proofs: boolean[] = [];
  const env: any = {
    documentID: 'document', sourceHTML: false, sourceSHA: undefined, sourceCommitment: undefined,
    retainedSource: null, readonly: true, current: () => true, emitProof: (value: boolean) => proofs.push(value), htmlPlacementPins() {},
    listRecipients: async () => [], listFields: async () => [], documentPdfURL: () => '/fixture.pdf',
    fetchVerifiedDocumentPDF: async () => new Uint8Array([1]), verifyAssignments() {},
    pdfModule: async () => ({ startPdf: () => new PdfLoad({ promise: Promise.resolve({ numPages: 1 }), destroy() { destroys++; return Promise.resolve(); } }) }),
    ContinuousPDFPages: class {
      start() { return Promise.resolve([{ num: 1, w: 760, h: 1075, scale: 1 }]); }
      allPagesRendered() { return false; } stop() {}
    },
    recipients: [], fields: [], recipientID: '', pages: [], residentPages: [],
    abort: new AbortController(), pdfLoad: null, pageResidency: undefined, rendered: false, error: null, loading: true,
    captureFlarePDFViewError() {}, emitSignatureFields() {}, tick: async () => {}, onMount(callback: () => Promise<void>) { mount = callback; },
  };
  const start = designer.indexOf('  onMount(async () => {'), end = designer.indexOf('\n  onDestroy(() => {', start);
  if (start < 0 || end <= start) throw new Error('Actual designer initialization callback moved');
  const retirement = designer.slice(designer.indexOf('  // Observe each original retirement'), start);
  const code = (retirement + designer.slice(start, end)).replace("await import('$lib/pdf')", 'await pdfModule()');
  new Function('env', `with(env) { ${transpiler.transformSync(code)} }`)(env);
  await mount();
  expect(proofs).not.toContain(true); expect(env.rendered).toBe(false);
  expect(env.error).toContain('stopped before review completed'); expect(destroys).toBe(1);
});
