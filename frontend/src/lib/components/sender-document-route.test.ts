import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../../routes/documents/[id]/+page.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  type DocumentScope');
const end = source.indexOf('  $effect(() =>', start);
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with(env) { ${code}; return {
  loadDocument, loadComments, sendComment, loadChangeRequests, resolveCr, revise,
  toggleSignatureMode, receiveEditorDocument, receiveStatus, changeDefaultLocale, resetRouteState
}; }`);
function document(id: string, status = 'changes_requested') {
  return { id, name: id, status, updated_at: `${id}-timestamp`, source_kind: 'blocks', requires_signature: true, blocks_json: { blocks: [{ text: `${id} content` }] } };
}
function fixture() {
  const calls: any[] = [];
  const pending = (kind: string) => (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind, args, resolve, reject }));
  const env: any = {
    doc: document('A'), $page: { params: { id: 'A' } }, routeRevision: 1, documentRevision: 1, disposed: false,
    userName: 'Owner', loading: false, error: null, showPreview: true, savingTemplate: false, savedTemplateFlash: false,
    changeRequests: [{ id: 'request-A', status: 'open', message: 'Prior proposal' }], revising: false,
    approvalMode: 'accept', resolvingId: null, comments: [{ body: 'Prior conversation' }], commentBody: 'Unsent A draft',
    postingComment: false, commentLoadRevision: 0, commentRefreshError: null, savingMode: false,
    changeRequestRefreshError: null, refreshingChanges: false, savingApprovalMode: false, changeRequestLoadRevision: 0,
    templateFlashTimer: null, getMe: async () => ({ email: 'owner@example.test', change_approval_mode: 'accept' }),
    getDocument: pending('getDocument'), listComments: pending('listComments'), postComment: pending('postComment'),
    listChangeRequests: pending('listChangeRequests'), approveChangeRequest: pending('approve'), denyChangeRequest: pending('deny'),
    reviseDocument: pending('revise'), updateDocument: pending('update'), createBlocksTemplate: pending('template'),
    setChangeApprovalMode: pending('approvalMode'), setTimeout, clearTimeout
  };
  return { env, calls, actions: bind(env) };
}
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
