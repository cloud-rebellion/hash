import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { currentHTMLSource, htmlUUID } from '../htmlRevision';
import { documentFixture, signingPageSourceFixture } from '../htmlRevision.test';

const source = readFileSync(new URL('../../routes/documents/[id]/+page.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  type DocumentScope');
const end = source.indexOf('  $effect(() =>', start);
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with(env) { ${code}; return {
  loadDocument, loadComments, sendComment, loadChangeRequests, resolveCr, revise,
  toggleSignatureMode, receiveHTMLSource, receivePlacementProof, receiveEditorDocument, receiveCRMDocument, requestCRMReview, receiveStatus, changeDefaultLocale, resetRouteState
}; }`);
function document(id: string, status = 'changes_requested') {
  return { id, name: id, status, updated_at: `${id}-timestamp`, source_kind: 'blocks', requires_signature: true, blocks_json: { blocks: [{ text: `${id} content` }] } };
}
function fixture() {
  const calls: any[] = [];
  const pending = (kind: string) => (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind, args, resolve, reject }));
  const env: any = {
    doc: document('A'), $page: { params: { id: 'A' } }, routeRevision: 1, documentRevision: 1, disposed: false,
    userName: 'Owner', viewerRole: '', viewerUserID: '', loading: false, error: null, showPreview: true, savingTemplate: false, savedTemplateFlash: false,
    crmBusy: false, crmBlocked: true, crmReviewRequired: false, crmEditorClean: true, crmOtherBusy: false, htmlEditorClean: false, blocksEditorClean: false, senderMutationBusy: false, crmRefreshRevision: 0, crmReviewRevision: 0, crmEditorRevision: 0,
    showPDFSave: false, pdfSignatureFields: [], generatedPlacementReady: false, recipientRevision: 0, htmlRevisionBlocked: true, htmlSource: null,
    changeRequests: [{ id: 'request-A', status: 'open', message: 'Prior proposal' }], revising: false,
    approvalMode: 'accept', resolvingId: null, comments: [{ body: 'Prior conversation' }], commentBody: 'Unsent A draft',
    postingComment: false, commentLoadRevision: 0, commentRefreshError: null, savingMode: false,
    changeRequestRefreshError: null, refreshingChanges: false, savingApprovalMode: false, changeRequestLoadRevision: 0,
    templateFlashTimer: null, htmlUUID, currentHTMLSource, getMe: async () => ({ email: 'owner@example.test', change_approval_mode: 'accept' }),
    getDocument: pending('getDocument'), listComments: pending('listComments'), postComment: pending('postComment'),
    listChangeRequests: pending('listChangeRequests'), approveChangeRequest: pending('approve'), denyChangeRequest: pending('deny'),
    reviseDocument: pending('revise'), updateDocument: pending('update'), createBlocksTemplate: pending('template'),
    setChangeApprovalMode: pending('approvalMode'), setTimeout, clearTimeout
  };
  return { env, calls, actions: bind(env) };
}

test('unverified HTML source and declared contract signing intent block acknowledgement downgrade before dispatch', async () => {
  for (const mode of ['unverified', 'dirty', 'contract']) {
    const state = fixture(); state.env.doc = { ...document('A', 'draft'), has_html_source: true };
    state.env.htmlRevisionBlocked = mode === 'dirty';
    state.env.htmlSource = mode === 'unverified' ? null : { contract_profile: mode === 'contract' ? { id: 'profile' } : undefined };
    await state.actions.toggleSignatureMode(); expect(state.calls).toEqual([]);
  }
  const legacy = fixture(); legacy.env.doc = { ...document('A', 'draft'), has_html_source: true }; legacy.env.htmlRevisionBlocked = false;
  legacy.env.htmlSource = {}; const pending = legacy.actions.toggleSignatureMode();
  expect(legacy.calls[0].kind).toBe('update'); legacy.calls[0].resolve({ ...legacy.env.doc, requires_signature: false }); await pending;
});
test('actual parent gate accepts current generated PDF proof and refuses stale source or navigation callbacks', () => {
  const state = fixture(), source = signingPageSourceFixture();
  state.env.doc = documentFixture(source); state.env.$page.params.id = source.document_id;
  state.env.htmlSource = source; state.env.htmlRevisionBlocked = false;
  const scope = { id: source.document_id, routeRevision: state.env.routeRevision, documentRevision: state.env.documentRevision };
  const proof = { documentID: source.document_id, pdfSHA256: source.pdf_sha256, htmlSourceCommitment: source.html_source_commitment, ready: true };
  state.actions.receivePlacementProof(proof, scope); expect(state.env.generatedPlacementReady).toBe(true);
  state.env.generatedPlacementReady = false;
  for (const altered of [{ ...proof, documentID: 'other' }, { ...proof, pdfSHA256: '9'.repeat(64) }, { ...proof, htmlSourceCommitment: '8'.repeat(64) }]) {
    state.actions.receivePlacementProof(altered, scope); expect(state.env.generatedPlacementReady).toBe(false);
  }
  state.env.htmlRevisionBlocked = true; state.actions.receivePlacementProof(proof, scope); expect(state.env.generatedPlacementReady).toBe(false);
  state.env.htmlRevisionBlocked = false; state.env.routeRevision++; state.actions.receivePlacementProof(proof, scope); expect(state.env.generatedPlacementReady).toBe(false);
});
function move(state: ReturnType<typeof fixture>, id: string) {
  state.env.$page.params.id = id;
  state.env.routeRevision++;
  state.actions.resetRouteState();
  state.env.doc = document(id);
  state.env.loading = false;
}

test('late initial document success or failure cannot replace the next route or its loading/error state', async () => {
  for (const failed of [false, true]) {
    const state = fixture();
    state.env.loading = true;
    const old = state.actions.loadDocument('A', 1);
    move(state, 'B');
    state.env.error = 'Current B error';
    if (failed) state.calls[0].reject(new Error('Late A failure'));
    else state.calls[0].resolve(document('A'));
    await old;
    expect(state.env.doc.id).toBe('B');
    expect(state.env.error).toBe('Current B error');
    expect(state.env.loading).toBe(false);
    expect(state.calls).toHaveLength(1);
  }
});

test('new document load checks the returned identity and disposal before starting dependent reads', async () => {
  for (const disposed of [false, true]) {
    const state = fixture();
    const loading = state.actions.loadDocument('A', 1);
    state.env.disposed = disposed;
    state.calls[0].resolve(document('B'));
    await loading;
    expect(state.env.doc.id).toBe('A');
    expect(state.calls).toHaveLength(1);
    expect(state.env.error).toBe(disposed ? null : 'The server returned a different document.');
  }
});

test('failed proposal refresh retains loaded rows and retry clears its visible error', async () => {
  const state = fixture();
  const failed = state.actions.loadChangeRequests('A');
  state.calls[0].reject(new Error('Unavailable'));
  await failed;
  expect(state.env.changeRequests).toEqual([{ id: 'request-A', status: 'open', message: 'Prior proposal' }]);
  expect(state.env.changeRequestRefreshError).toContain('Change requests could not be refreshed');
  expect(state.env.refreshingChanges).toBe(false);
  const retry = state.actions.loadChangeRequests('A');
  state.calls[1].resolve({ change_requests: [{ id: 'fresh', status: 'open' }] });
  await retry;
  expect(state.env.changeRequests).toEqual([{ id: 'fresh', status: 'open' }]);
  expect(state.env.changeRequestRefreshError).toBeNull();
});

test('ordered proposal refreshes and returning to the same ID reject older route responses', async () => {
  const state = fixture();
  const older = state.actions.loadChangeRequests('A');
  const newer = state.actions.loadChangeRequests('A');
  state.calls[1].resolve({ change_requests: ['newer'] });
  await newer;
  state.calls[0].reject(new Error('Old refresh failure'));
  await older;
  expect(state.env.changeRequests).toEqual(['newer']);
  expect(state.env.changeRequestRefreshError).toBeNull();
  const previousVisit = state.actions.loadChangeRequests('A');
  move(state, 'B');
  move(state, 'A');
  state.env.changeRequests = ['current visit'];
  state.env.refreshingChanges = true;
  state.calls[2].resolve({ change_requests: ['previous visit'] });
  await previousVisit;
  expect(state.env.changeRequests).toEqual(['current visit']);
  expect(state.env.refreshingChanges).toBe(true);
});

test('late revise receipt and proposal action failure cannot mutate another document or its pending action', async () => {
  for (const action of ['revise', 'resolveCr'] as const) {
    const state = fixture();
    const pending = action === 'revise' ? state.actions.revise() : state.actions.resolveCr(state.env.changeRequests[0], true);
    move(state, 'B');
    state.env.changeRequests = ['B proposal'];
    state.env.error = 'B error';
    state.env.revising = true;
    state.env.resolvingId = 'B request';
    if (action === 'revise') state.calls[0].resolve(document('A', 'draft'));
    else state.calls[0].reject(new Error('Late A action failure'));
    await pending;
    expect(state.env.doc.id).toBe('B');
    expect(state.env.doc.status).toBe('changes_requested');
    expect(state.env.changeRequests).toEqual(['B proposal']);
    expect(state.env.error).toBe('B error');
    expect(state.env.revising).toBe(true);
    expect(state.env.resolvingId).toBe('B request');
    expect(state.calls).toHaveLength(1);
  }
});

test('late metadata receipt cannot overwrite a newer editor receipt in the same document', async () => {
  const state = fixture();
  state.env.doc.status = 'draft';
  const pending = state.actions.toggleSignatureMode();
  state.env.documentRevision++;
  state.env.doc = { ...document('A', 'draft'), blocks_json: { blocks: [{ text: 'Newly saved local edits' }] } };
  state.calls[0].resolve({ ...document('A', 'draft'), requires_signature: false });
  await pending;
  expect(state.env.doc.blocks_json.blocks[0].text).toBe('Newly saved local edits');
  expect(state.env.doc.requires_signature).toBe(true);
});

test('late comment failure preserves the next route draft, error and pending send', async () => {
  const state = fixture();
  const old = state.actions.sendComment();
  expect(state.calls[0].args).toEqual(['A', 'Unsent A draft']);
  move(state, 'B');
  state.env.commentBody = 'B draft';
  state.env.error = 'B error';
  state.env.postingComment = true;
  state.calls[0].reject(new Error('Late A send failure'));
  await old;
  expect(state.env.commentBody).toBe('B draft');
  expect(state.env.error).toBe('B error');
  expect(state.env.postingComment).toBe(true);
});

test('stale URL identity and foreign proposal IDs block dispatch before an action starts', async () => {
  const state = fixture();
  state.env.$page.params.id = 'B';
  await state.actions.sendComment();
  await state.actions.revise();
  await state.actions.toggleSignatureMode();
  await state.actions.resolveCr(state.env.changeRequests[0], true);
  await state.actions.loadChangeRequests('A');
  await state.actions.loadComments('A');
  expect(state.calls).toHaveLength(0);
  state.env.$page.params.id = 'A';
  await state.actions.resolveCr({ id: 'foreign', status: 'open' }, true);
  expect(state.calls).toHaveLength(0);
});

test('disposed or old child callbacks cannot replace content or status after navigation', () => {
  const state = fixture();
  const oldScope = { id: 'A', routeRevision: 1, documentRevision: 1 };
  move(state, 'B');
  state.actions.receiveEditorDocument(document('A', 'draft'), oldScope);
  state.actions.receiveStatus('sent', oldScope);
  expect(state.env.doc.id).toBe('B');
  expect(state.env.doc.status).toBe('changes_requested');
  state.env.disposed = true;
  state.actions.receiveEditorDocument(document('B', 'draft'), { ...oldScope, id: 'B', routeRevision: state.env.routeRevision });
  expect(state.env.doc.status).toBe('changes_requested');
});

test('CRM adoption requires original route revision and clean editor; accepted new source resets review and placement', () => {
  const state = fixture(), source = signingPageSourceFixture(); state.env.doc = documentFixture(source); state.env.$page.params.id = source.document_id;
  state.env.pdfSignatureFields = [{ role: 'provider', label: 'Old geometry' }]; state.env.generatedPlacementReady = true;
  const scope = { id: source.document_id, routeRevision: state.env.routeRevision, documentRevision: state.env.documentRevision };
  const updated = { ...state.env.doc, updated_at: '2026-10-10T12:03:00Z', html_source_commitment: '9'.repeat(64), pdf_sha256: '8'.repeat(64), html_materialization_revision: 2, html_review_required: true };
  state.env.crmEditorClean = false; expect(state.actions.receiveCRMDocument(updated, scope)).toBe(false); expect(state.env.doc.pdf_sha256).toBe(source.pdf_sha256);
  state.env.crmEditorClean = true; state.env.crmOtherBusy = true; expect(state.actions.receiveCRMDocument(updated, scope)).toBe(false);
  state.env.crmOtherBusy = false; expect(state.actions.receiveCRMDocument(updated, { ...scope, documentRevision: 0 })).toBe(false);
  state.env.crmReviewRequired = true; expect(state.actions.receiveCRMDocument(updated, scope)).toBe(true);
  expect(state.env.doc).toBe(updated); expect(state.env.crmReviewRequired).toBe(false); expect(state.env.crmEditorRevision).toBe(1);
  expect(state.env.pdfSignatureFields).toEqual([]); expect(state.env.generatedPlacementReady).toBe(false); expect(state.env.htmlRevisionBlocked).toBe(true);
});
test('CRM Apply lock cannot adopt a late block autosave or change document metadata', async () => {
  const state = fixture(); state.env.doc.status = 'draft'; state.env.crmBusy = true;
  const scope = { id: 'A', routeRevision: 1, documentRevision: 1 };
  state.actions.receiveEditorDocument({ ...state.env.doc, updated_at: 'late save' }, scope);
  await state.actions.toggleSignatureMode(); await state.actions.changeDefaultLocale('sv', scope);
  expect(state.env.doc.updated_at).toBe('A-timestamp'); expect(state.calls).toEqual([]);
});
test('the actual Send prop blocks dirty or unsynced editable blocks and retains clean manual sending', () => {
  const prop = source.slice(source.indexOf('<SenderPanel')).match(/revisionBlocked=\{([^\n]+)\}/)?.[1]; expect(prop).toBeDefined();
  const blocked = new Function('doc', 'htmlRevisionBlocked', 'crmEditable', 'blocksEditorClean', `return ${prop};`);
  const blocks = { source_kind: 'blocks', has_html_source: false };
  expect(blocked(blocks, false, true, false)).toBe(true);
  expect(blocked(blocks, false, true, true)).toBe(false);
  expect(blocked(blocks, false, false, false)).toBe(false);
  expect(blocked({ source_kind: 'pdf', has_html_source: true }, true, true, true)).toBe(true);
});
