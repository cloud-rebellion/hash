import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../api/client';
import { advanceCleanHTMLObservation, currentHTMLSource, htmlRevisionInput, htmlUUID, revisionDraft, validateHTMLHistory, validateHTMLSource, verifiedHTMLGeneratedFields, verifiedHTMLRevision, htmlPlacementPins } from '../htmlRevision';
import { generatedAssignmentFixture } from '../htmlRevision.test';

function bind(file: string, names: string[], env: any) {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8');
  const functions = names.map((name) => {
    let start = source.indexOf(`function ${name}(`);
    if (source.slice(start - 6, start) === 'async ') start -= 6;
    const opening = source.indexOf('{', start); let position = opening, depth = 1;
    while (depth && ++position < source.length) { if (source[position] === '{') depth++; if (source[position] === '}') depth--; }
    if (start < 0 || opening < 0 || depth) throw new Error(`Missing production callback ${name}`);
    return source.slice(start, position + 1);
  }).join('\n');
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions);
  return new Function('env', `with(env) { ${code}; return {${names.join(',')}}; }`)(env);
}
const ID = '10000000-0000-4000-8000-000000000001', ORG = '20000000-0000-4000-8000-000000000002', USER = '30000000-0000-4000-8000-000000000003', TEMPLATE = '40000000-0000-4000-8000-000000000004';
function source(sequence = 1) {
  return { document_id: ID, org_id: ORG, updated_at: `2026-10-10T06:0${sequence}:00.000000123Z`, html_source_commitment: (sequence === 1 ? 'a' : 'd').repeat(64),
    materialization_revision: sequence, pdf_sha256: 'b'.repeat(64), page_count: 2, template_id: TEMPLATE, template_version: 4, template_content_sha256: 'c'.repeat(64),
    values: [{ name: 'company', required: true, max_chars: 128, text: 'Printed company' }], sections: [{ name: 'scope', max_chars: 256, text: 'Approved wording', default_text: 'Approved wording' }], changed_sections: [], can_edit: true };
}
function document(sequence = 1) { const s = source(sequence); return { id: ID, org_id: ORG, sender_id: USER, template_id: TEMPLATE, status: 'draft', source_kind: 'pdf',
  has_html_source: true, html_review_required: true, updated_at: s.updated_at, html_source_commitment: s.html_source_commitment, pdf_sha256: s.pdf_sha256, html_materialization_revision: sequence }; }
function fixture() {
  const calls: any[] = [], revised: any[] = [];
  const env: any = { document: document(), retained: source(), sourceID: ID, sourceOrg: ORG, me: { user_id: USER, org_id: ORG, role: 'sender' }, disposed: false, operation: 0,
    values: { company: 'Negotiated <AB> & Co' }, sections: { scope: 'Human-proposed wording' }, summary: 'Negotiated scope', baseline: '', dirty: true, canSave: true,
    loading: false, busy: false, error: null, needsRefresh: false, uncertain: false, acknowledgedDocument: null, latestDocument: null, latestSource: null,
    APIError, htmlUUID, advanceCleanHTMLObservation, currentHTMLSource, htmlRevisionInput, revisionDraft, verifiedHTMLRevision,
    onRevised: (d: any) => revised.push(d), onSourceChange: undefined, window: { confirm: () => false } };
  env.current = () => !env.disposed && env.document.id === ID && env.document.org_id === ORG;
  env.fingerprint = () => JSON.stringify({ values: env.values, sections: env.sections, summary: env.summary });
  for (const [name, kind] of [['reviseHTMLDocument', 'write'], ['getHTMLDocumentSource', 'source'], ['getDocument', 'document'], ['getMe', 'identity']]) {
    env[name] = (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind, args, resolve, reject }));
  }
  const actions = bind('./HtmlDocumentRevision.svelte', ['reconcileObservation', 'reportRevisionState', 'identity', 'recordError', 'adopt', 'loadInitial', 'save', 'inspectLatest', 'adoptLatest', 'protectNavigation', 'protectUnload'], env);
  return { env, calls, revised, actions };
}
const event = { preventDefault() {} };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

test('clean same-source review and field metadata release the revision send guard without replacing local text', () => {
  for (const metadata of [{ html_review_required: false }, { name: 'Field placement metadata' }]) {
    const f = fixture(), states: boolean[] = [], retained = f.env.retained, inputs = f.env.fingerprint();
    f.env.dirty = false; f.env.baseline = inputs; f.env.untrack = (run: () => void) => run(); f.env.onStateChange = (blocked: boolean) => states.push(blocked);
    Object.defineProperty(f.env, 'observationCurrent', { get: () => f.env.retained.updated_at === f.env.document.updated_at });
    f.env.document = { ...f.env.document, ...metadata, updated_at: '2026-10-10T06:03:00.000000987Z' };
    f.actions.reconcileObservation(); f.actions.reportRevisionState();
    expect(f.env.retained.updated_at).toBe(f.env.document.updated_at); expect(f.env.needsRefresh).toBe(false); expect(states).toEqual([false]);
    expect(f.env.retained.values).toBe(retained.values); expect(f.env.retained.sections).toBe(retained.sections);
    expect(f.env.fingerprint()).toBe(inputs); expect(f.env.baseline).toBe(inputs); expect(f.calls).toHaveLength(0);
  }
});

test('parent receives only clean verified source and loses identity-edit authority during dirty or stale observations', () => {
  const f = fixture(), published: any[] = [];
  f.env.untrack = (run: () => void) => run(); f.env.onSourceChange = (source: any) => published.push(source); f.env.onStateChange = undefined;
  f.env.dirty = false; f.env.observationCurrent = true;
  f.actions.reportRevisionState(); expect(published).toEqual([f.env.retained]);
  for (const flags of [{ dirty: true }, { needsRefresh: true }, { busy: true }, { observationCurrent: false }]) {
    f.env.dirty = false; f.env.needsRefresh = false; f.env.busy = false; f.env.observationCurrent = true;
    Object.assign(f.env, flags); f.actions.reportRevisionState(); expect(published.at(-1)).toBeNull();
  }
});

test('dirty, pending, loading, uncertain, stale and unauthenticated inputs stay blocked across metadata changes', () => {
  for (const state of [{ dirty: true }, { busy: true }, { loading: true }, { uncertain: true }, { needsRefresh: true }, { me: null }]) {
    const f = fixture(), states: boolean[] = [], retained = f.env.retained, inputs = f.env.fingerprint();
    f.env.dirty = false; Object.assign(f.env, state); f.env.untrack = (run: () => void) => run(); f.env.onStateChange = (blocked: boolean) => states.push(blocked);
    Object.defineProperty(f.env, 'observationCurrent', { get: () => f.env.retained.updated_at === f.env.document.updated_at });
    f.env.document = { ...f.env.document, html_review_required: false, updated_at: '2026-10-10T06:03:00Z' };
    f.actions.reconcileObservation(); f.actions.reportRevisionState();
    expect(f.env.retained).toBe(retained); expect(f.env.fingerprint()).toBe(inputs); expect(f.env.needsRefresh).toBe(true); expect(states).toEqual([true]);
  }
  const f = fixture(); f.env.dirty = false; f.env.observationCurrent = false;
  f.env.document = { ...f.env.document, html_source_commitment: 'd'.repeat(64), html_materialization_revision: 2 };
  f.actions.reconcileObservation(); expect(f.env.retained.materialization_revision).toBe(1); expect(f.env.needsRefresh).toBe(true);
});

test('revision saves declared maps and exact observation once, then adopts only verified acknowledged source', async () => {
  const f = fixture(); const pending = f.actions.save(event); await f.actions.save(event);
  expect(f.calls).toHaveLength(1); expect(f.calls[0].args[1]).toEqual({ expected_updated_at: source().updated_at, expected_html_source_commitment: source().html_source_commitment,
    values: f.env.values, sections: f.env.sections, summary: 'Negotiated scope' });
  f.calls[0].resolve({ document: document(2), materialization_revision: 2, page_count: 2, review_required: true, placement_reset: true }); await tick();
  expect(f.calls[1].kind).toBe('source'); expect(f.env.acknowledgedDocument.html_materialization_revision).toBe(2);
  f.calls[1].resolve(source(2)); await pending;
  expect(f.revised).toEqual([document(2)]); expect(f.env.retained.materialization_revision).toBe(2); expect(f.env.summary).toBe(''); expect(f.env.busy).toBe(false);
});

test('confirmed write plus failed detail remains acknowledged, preserving text and preventing blind repeat', async () => {
  for (const failure of [new APIError(401, 'Expired'), new APIError(404, 'Unavailable'), new Error('Network failure')]) {
    const f = fixture(), before = f.env.fingerprint(); const pending = f.actions.save(event);
    f.calls[0].resolve({ document: document(2), materialization_revision: 2, page_count: 2, review_required: true, placement_reset: true }); await tick();
    f.calls[1].reject(failure); await pending;
    expect(f.env.uncertain).toBe(true); expect(f.env.acknowledgedDocument.id).toBe(ID); expect(f.env.fingerprint()).toBe(before); expect(f.revised).toEqual([]);
    f.env.canSave = false; await f.actions.save(event); expect(f.calls).toHaveLength(2);
    const inspecting = f.actions.inspectLatest(); f.calls[2].resolve({ user_id: USER, org_id: ORG, role: 'sender' }); await tick();
    f.calls[3].resolve(document(2)); await tick(); f.calls[4].resolve(source(2)); await inspecting;
    expect(f.env.values.company).toBe('Negotiated <AB> & Co'); expect(f.env.retained.materialization_revision).toBe(1);
    f.actions.adoptLatest(); expect(f.env.retained.materialization_revision).toBe(1);
    f.env.window.confirm = () => true; f.actions.adoptLatest(); expect(f.env.retained.materialization_revision).toBe(2); expect(f.env.uncertain).toBe(false);
  }
});

test('stale and unknown writes retain input; tenant/malformed identity clears authority without adoption', async () => {
  for (const failure of [new APIError(409, 'Changed'), new APIError(503, 'Try again'), new TypeError('Unknown request')]) {
    const f = fixture(), before = f.env.fingerprint(); const pending = f.actions.save(event); f.calls[0].reject(failure); await pending;
    expect(f.env.fingerprint()).toBe(before); expect(f.revised).toEqual([]);
    expect(failure instanceof APIError && failure.status === 409 ? f.env.needsRefresh : f.env.uncertain).toBe(true);
    if (!(failure instanceof APIError) || failure.status >= 500) expect(f.env.error).not.toContain('Try again');
  }
  for (const identity of [{ role: 'owner' }, { user_id: USER, org_id: TEMPLATE, role: 'owner' }]) {
    const f = fixture(), before = f.env.fingerprint(); const pending = f.actions.loadInitial();
    f.calls[0].resolve(identity); await pending;
    expect(f.env.me).toBeNull(); expect(f.env.fingerprint()).toBe(before); expect(f.calls).toHaveLength(1); expect(f.env.retained.materialization_revision).toBe(1);
  }
});

test('late revision receipt or readback cannot adopt after selection or local input change', async () => {
  for (const mode of ['route', 'disposed', 'inputs']) {
    const f = fixture(); const pending = f.actions.save(event);
    if (mode === 'route') f.env.document = { ...f.env.document, id: TEMPLATE };
    if (mode === 'disposed') f.env.disposed = true;
    if (mode === 'inputs') f.env.values.company = 'New local input';
    f.calls[0].resolve({ document: document(2), materialization_revision: 2, page_count: 2, review_required: true, placement_reset: true }); await pending;
    expect(f.revised).toEqual([]); expect(f.calls).toHaveLength(1); expect(f.env.retained.materialization_revision).toBe(1);
  }
});

test('a changed parent observation refuses adoption without discarding the acknowledged revision or local draft', async () => {
  const f = fixture(), before = f.env.fingerprint(); f.env.onRevised = () => false;
  const pending = f.actions.save(event);
  f.calls[0].resolve({ document: document(2), materialization_revision: 2, page_count: 2, review_required: true, placement_reset: true }); await tick();
  f.calls[1].resolve(source(2)); await pending;
  expect(f.env.retained.materialization_revision).toBe(1); expect(f.env.fingerprint()).toBe(before); expect(f.env.uncertain).toBe(true);
  expect(f.env.acknowledgedDocument.html_materialization_revision).toBe(2);
  f.env.latestDocument = document(2); f.env.latestSource = source(2); f.env.window.confirm = () => true; f.actions.adoptLatest();
  expect(f.env.fingerprint()).toBe(before); expect(f.env.error).toContain('displayed document changed');
});

test('pending/dirty revision protects both SPA navigation and native unload', () => {
  const f = fixture(); let canceled = 0, prevented = 0;
  const navigation = { willUnload: false, from: { url: new URL('https://hash.invalid/documents/a') }, to: { url: new URL('https://hash.invalid/documents') }, cancel: () => canceled++ };
  f.actions.protectNavigation(navigation); expect(canceled).toBe(1);
  f.env.window.confirm = () => true; f.actions.protectNavigation(navigation); expect(canceled).toBe(1);
  const unload = { preventDefault: () => prevented++, returnValue: undefined }; f.actions.protectUnload(unload); expect(prevented).toBe(1); expect(unload.returnValue).toBe('');
});

test('history rejects source rebinding and discards late reads before historical PDF dispatch', async () => {
  for (const mode of ['mismatch', 'late']) {
    const calls: any[] = [], row = { sequence: 1, source_commitment: source().html_source_commitment, pdf_sha256: source().pdf_sha256, page_count: 2 };
    const env: any = { rows: [row], document: document(), sourceID: ID, sourceOrg: ORG, disposed: false, selectionOperation: 0, abort: null, selected: null, bytes: null, opening: false, error: null,
      validateHTMLSource, current: () => !env.disposed && env.document.id === ID,
      getHTMLRevisionSource: (...args: any[]) => new Promise((resolve) => calls.push({ args, resolve })), fetchVerifiedHTMLRevisionPDF: () => { throw new Error('Unexpected PDF dispatch'); } };
    const actions = bind('./HtmlDocumentHistory.svelte', ['openRevision', 'closeRevision'], env); const pending = actions.openRevision(row);
    if (mode === 'late') actions.closeRevision();
    calls[0].resolve({ ...source(), can_edit: false, html_source_commitment: mode === 'mismatch' ? 'e'.repeat(64) : source().html_source_commitment }); await pending;
    expect(env.selected).toBeNull(); expect(env.bytes).toBeNull(); if (mode === 'mismatch') expect(env.error).toContain('immutable history');
  }
});

test('history opens only exact read-only source and verified bytes, keeping older history if refresh fails', async () => {
  const calls: any[] = [], row = { sequence: 1, id: TEMPLATE, source_commitment: source().html_source_commitment, pdf_sha256: source().pdf_sha256, page_count: 2,
    created_by: USER, created_at: source().updated_at, summary: '', current: true };
  const env: any = { rows: [row], document: document(), sourceID: ID, sourceOrg: ORG, disposed: false, listOperation: 0, selectionOperation: 0, abort: null,
    selected: null, bytes: null, loading: false, opening: false, error: null, validateHTMLSource, validateHTMLHistory, current: () => !env.disposed && env.document.id === ID };
  for (const name of ['getHTMLRevisionSource', 'fetchVerifiedHTMLRevisionPDF', 'getHTMLDocumentHistory']) env[name] = (...args: any[]) => new Promise((resolve, reject) => calls.push({ name, args, resolve, reject }));
  const actions = bind('./HtmlDocumentHistory.svelte', ['openRevision', 'refresh'], env);
  const pending = actions.openRevision(row); calls[0].resolve({ ...source(), can_edit: false }); await tick();
  expect(calls[1].args[1].html_source_commitment).toBe(row.source_commitment); const bytes = new Uint8Array([1, 2]); calls[1].resolve(bytes); await pending;
  expect(env.selected.can_edit).toBe(false); expect(env.bytes).toBe(bytes);
  const refresh = actions.refresh(); calls[2].reject(new Error('History unavailable')); await refresh;
  expect(env.rows).toEqual([row]); expect(env.error).toBe('History unavailable');
});

test('queued HTML field creation/deletion pins exact PDF and source, ignoring changed-source results', async () => {
  for (const action of ['onPointerUp', 'remove']) {
    const calls: any[] = [], changed: any[] = [];
    const env: any = { documentID: ID, sourceHTML: true, sourceSHA: 'b'.repeat(64), sourceCommitment: 'a'.repeat(64), htmlSourceCommitment: 'a'.repeat(64), disposed: false,
      draft: { page: 1, x: 10, y: 10, w: 20, h: 5 }, dragStart: {}, readonly: false, generated: false, placementUnavailable: false, tool: 'signature', recipientID: USER, required: true,
      TOOLS: [{ type: 'signature', label: 'Signature' }], fields: [{ id: 'field', document_id: ID }], saving: false, error: null, htmlPlacementPins,
      emitSignatureFields: () => changed.push(true), current: (target: string) => !env.disposed && target === ID && env.htmlSourceCommitment === env.sourceCommitment };
    for (const name of ['addField', 'deleteField']) env[name] = (...args: any[]) => new Promise((resolve) => calls.push({ name, args, resolve }));
    const actions = bind('./PdfFieldDesigner.svelte', ['onPointerUp', 'round', 'remove'], env);
    const pending = action === 'onPointerUp' ? actions.onPointerUp() : actions.remove(env.fields[0]);
    expect(calls[0].args[1]).toMatchObject({ expected_pdf_sha256: env.sourceSHA, expected_html_source_commitment: env.sourceCommitment });
    env.htmlSourceCommitment = 'd'.repeat(64); calls[0].resolve({ id: 'created', document_id: ID }); await pending;
    expect(changed).toEqual([]); expect(env.fields).toEqual([{ id: 'field', document_id: ID }]);
    await actions.onPointerUp(); await actions.remove(env.fields[0]); expect(calls).toHaveLength(1);
  }
});
test('automatic or readonly placement handlers cannot dispatch add/delete even if invoked directly', async () => {
  for (const mode of ['generated', 'readonly']) {
    const calls: unknown[] = [];
    const env: any = { documentID: ID, readonly: mode === 'readonly', generated: mode === 'generated',
      draft: { page: 2, x: 10, y: 42, w: 80, h: 7 }, dragStart: {}, placementUnavailable: false, current: () => true,
      addField: () => calls.push('add'), deleteField: () => calls.push('delete') };
    const actions = bind('./PdfFieldDesigner.svelte', ['onPointerUp', 'remove'], env);
    await actions.onPointerUp(); await actions.remove({ id: 'existing', document_id: ID });
    expect(calls).toEqual([]); expect(env.draft).toBeNull();
  }
});
test('generated field refresh invalidates readiness before read and only restores it after exact party and rectangle readback', async () => {
  for (const drift of [false, true]) {
    const fixture = generatedAssignmentFixture(), calls: any[] = [], proofs: boolean[] = [];
    const env: any = { documentID: ID, generated: true, retainedSource: fixture.source, recipientRevision: 1,
      rendered: true, loading: false, saving: false, refreshingRecipients: false, recipientRefreshError: null, appliedRecipientRevision: 0,
      dragStart: null, draft: null, recipients: fixture.recipients, fields: fixture.fields, recipientID: fixture.recipients[0].id,
      current: () => true, verifiedHTMLGeneratedFields, emitProof: (ready: boolean) => proofs.push(ready), emitSignatureFields: () => {} };
    env.listRecipients = () => new Promise(resolve => calls.push({ kind: 'recipients', resolve }));
    env.listFields = () => new Promise(resolve => calls.push({ kind: 'fields', resolve }));
    const actions = bind('./PdfFieldDesigner.svelte', ['verifyAssignments', 'refreshPlacementContext'], env);
    const pending = actions.refreshPlacementContext(1); expect(proofs).toEqual([false]);
    const fields = structuredClone(fixture.fields); if (drift) fields[0].y_pct = 43;
    calls.find(call => call.kind === 'recipients').resolve(fixture.recipients); calls.find(call => call.kind === 'fields').resolve(fields); await pending;
    expect(proofs).toEqual(drift ? [false] : [false, true]);
    expect(env.recipientRefreshError !== null).toBe(drift);
  }
});

test('review binds new materialization source and refuses an identical-PDF response from another source', async () => {
  const calls: any[] = [], reviewed: any[] = [];
  const env: any = { document: document(), sourceID: ID, sourceStamp: source().updated_at, sourceSHA: 'b'.repeat(64), sourceCommitment: 'a'.repeat(64),
    disposed: false, canReview: true, revisionBlocked: false, loading: false, rendering: false, busy: false, error: null, activePDF: {}, allPagesSeen: true, pageCountMatches: true, acknowledged: true,
    current: () => !env.disposed && env.document.html_source_commitment === env.sourceCommitment,
    reviewHTMLDocument: (...args: any[]) => new Promise((resolve) => calls.push({ args, resolve })), onReviewed: (d: any) => reviewed.push(d) };
  const actions = bind('./HtmlPDFReview.svelte', ['approve'], env); const pending = actions.approve();
  expect(calls[0].args).toEqual([ID, env.sourceStamp, env.sourceSHA, env.sourceCommitment]);
  calls[0].resolve({ ...document(), html_review_required: false, html_source_commitment: 'd'.repeat(64) }); await pending;
  expect(reviewed).toEqual([]); expect(env.acknowledged).toBe(false); expect(env.error).toContain('does not match');
});

test('dirty or unreconciled local wording blocks review of the previously rendered PDF at dispatch', async () => {
  const env: any = { document: document(), sourceID: ID, sourceStamp: source().updated_at, sourceSHA: 'b'.repeat(64), sourceCommitment: 'a'.repeat(64),
    canReview: true, revisionBlocked: true, loading: false, rendering: false, busy: false, error: null, activePDF: {}, allPagesSeen: true, acknowledged: true,
    current: () => true, reviewHTMLDocument: () => { throw new Error('Old PDF review must not dispatch'); } };
  await bind('./HtmlPDFReview.svelte', ['approve'], env).approve(); expect(env.busy).toBe(false);
});
test('unseen appended page or mismatched retained page count blocks the actual PDF approval callback', async () => {
  for (const mode of ['unseen_page', 'wrong_count']) {
    const env: any = { document: document(), sourceID: ID, sourceStamp: source().updated_at, sourceSHA: 'b'.repeat(64), sourceCommitment: 'a'.repeat(64),
      canReview: true, revisionBlocked: false, loading: false, rendering: false, busy: false, error: null, activePDF: {},
      allPagesSeen: mode !== 'unseen_page', pageCountMatches: mode !== 'wrong_count', acknowledged: true,
      current: () => true, reviewHTMLDocument: () => { throw new Error('Incomplete page review must not dispatch'); } };
    await bind('./HtmlPDFReview.svelte', ['approve'], env).approve(); expect(env.busy).toBe(false);
  }
});
