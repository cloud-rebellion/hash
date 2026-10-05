import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../../api/client';

// Exercise the production async handlers so the tests cover disposal, review
// observations and local edit races without replacing them with test logic.
const source = readFileSync(new URL('./RecoveryPanel.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  function current(');
const end = source.indexOf('</script>', start);
if (start < 0 || end < 0) throw new Error('Recovery handlers missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with (env) { ${code}; return {
  loadReview, captureLocalDraft, resetSharedEditing, removeArchive,
  reloadSavedDocument, readyToReset, readyToReload, validState
}; }`);

function state(generation = '2') {
  return {
    document: { id: 'doc', org_id: 'org', source_kind: 'blocks', status: 'draft',
      name: 'Current contract', updated_at: '2026-10-05T12:00:00Z', blocks_json: { version: 1, blocks: [] } },
    generation,
    document_deleted: false,
    archives: [{ id: 'archive', origin: 'persisted', history_generation: null,
      observed_canonical_generation: '2', created_at: '2026-10-05T12:00:00Z',
      expires_at: '2027-01-03T12:00:00Z', size_bytes: 2 }]
  };
}

function fixture() {
  const requests: Array<{ method: string; args: unknown[]; resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
  const defer = (method: string, ...args: unknown[]) => new Promise((resolve, reject) => requests.push({ method, args, resolve, reject }));
  const env: any = {
    disposed: false, readVersion: 0, documentID: 'doc', orgID: 'org', editRevision: 1,
    archiveReviewOnly: false,
    loading: false, busy: false, owner: null, error: null, review: null,
    reviewedRevision: null, capturedRevision: null, acknowledged: false,
    successRevision: null, successGeneration: null, APIError,
    downloads: 0, recovered: [], reloaded: [], confirms: 0,
    downloadDraft: () => { env.downloads++; return true; },
    onRecovered: (id: string) => env.recovered.push(id),
    reloadDocument: (id: string, revision: number) => env.reloaded.push({ id, revision }),
    window: { confirm: () => { env.confirms++; return true; } },
    getMe: () => defer('me'),
    getCollaborationRecovery: (...args: unknown[]) => defer('get', ...args),
    recoverCollaboration: (...args: unknown[]) => defer('reset', ...args),
    deleteCollaborationArchive: (...args: unknown[]) => defer('delete', ...args)
  };
  return { env, requests, handlers: bind(env) };
}

async function settle() { for (let i = 0; i < 4; i++) await Promise.resolve(); }
function reviewed() {
  const fixtureValue = fixture();
  const { env } = fixtureValue;
  env.owner = true; env.review = state(); env.reviewedRevision = 1;
  env.capturedRevision = 1; env.acknowledged = true;
  return fixtureValue;
}

test('current role and tenant gate recovery reads before fetching the document history', async () => {
  for (const user of [{ org_id: 'org', role: 'sender' }, { org_id: 'other', role: 'owner' }]) {
    const { env, requests, handlers } = fixture();
    const pending = handlers.loadReview();
    requests[0].resolve(user); await pending;
    expect(requests.map((request) => request.method)).toEqual(['me']);
    expect(env.owner).toBe(false); expect(env.review).toBeNull();
  }
});

test('review response cannot enable reset after local edits or a changed document', async () => {
  const { env, requests, handlers } = fixture();
  const pending = handlers.loadReview();
  requests[0].resolve({ org_id: 'org', role: 'owner' }); await settle();
  env.editRevision++; requests[1].resolve(state()); await pending;
  handlers.captureLocalDraft(); env.acknowledged = true;
  expect(env.reviewedRevision).toBe(1); expect(env.capturedRevision).toBe(2);
  expect(handlers.readyToReset()).toBe(false);
  await handlers.resetSharedEditing(); expect(requests).toHaveLength(2);

  const other = fixture(); const late = other.handlers.loadReview();
  other.requests[0].resolve({ org_id: 'org', role: 'owner' }); await settle();
  other.env.documentID = 'next'; other.requests[1].resolve(state()); await late;
  expect(other.env.review).toBeNull();
});

test('disposed owner lookup does not fetch history or mutate the panel', async () => {
  const { env, requests, handlers } = fixture();
  const pending = handlers.loadReview(); env.disposed = true;
  requests[0].resolve({ org_id: 'org', role: 'owner' }); await pending;
  expect(requests).toHaveLength(1); expect(env.owner).toBeNull();
});

test('reset requires explicit acknowledgement and a draft captured at the reviewed revision', async () => {
  const { env, requests, handlers } = reviewed();
  env.acknowledged = false; await handlers.resetSharedEditing();
  env.acknowledged = true; env.capturedRevision = null; await handlers.resetSharedEditing();
  env.capturedRevision = 0; await handlers.resetSharedEditing();
  expect(requests).toHaveLength(0);
  handlers.captureLocalDraft();
  expect(handlers.readyToReset()).toBe(true);
  const pending = handlers.resetSharedEditing();
  await handlers.resetSharedEditing();
  expect(requests).toHaveLength(1);
  expect(requests[0].args).toEqual(['doc', { generation: '2', expected_updated_at: '2026-10-05T12:00:00Z', acknowledged: true }]);
  requests[0].resolve({ document: state('3').document, generation: '3' }); await settle();
  requests[1].resolve(state('3')); await pending;
  expect(env.recovered).toEqual(['doc']); expect(env.reloaded).toEqual([]);
  expect(env.successRevision).toBe(1);
  handlers.reloadSavedDocument(); expect(env.reloaded).toEqual([{ id: 'doc', revision: 1 }]);
});

test('edits made during reset remain local and prevent reload without undoing committed recovery', async () => {
  const { env, requests, handlers } = reviewed();
  const pending = handlers.resetSharedEditing(); env.editRevision++;
  requests[0].resolve({ document: state('3').document, generation: '3' }); await settle();
  requests[1].resolve(state('3')); await pending;
  expect(env.recovered).toEqual(['doc']); expect(env.successRevision).toBe(1);
  expect(handlers.readyToReload()).toBe(false); handlers.reloadSavedDocument();
  expect(env.reloaded).toEqual([]);
  handlers.captureLocalDraft(); handlers.reloadSavedDocument();
  expect(env.reloaded).toEqual([]);
});

test('observation conflict requires a new review and leaves the draft and connection untouched', async () => {
  const { env, requests, handlers } = reviewed();
  const pending = handlers.resetSharedEditing();
  requests[0].reject(new APIError(412, 'The saved document changed')); await pending;
  expect(env.error).toBe('The saved document changed'); expect(env.review).toBeNull();
  expect(env.capturedRevision).toBeNull(); expect(env.acknowledged).toBe(false);
  expect(env.recovered).toEqual([]); expect(env.reloaded).toEqual([]);
});

test('capacity and privacy review failures remain visible without accepting recovery', async () => {
  for (const status of [409, 507]) {
    const { env, requests, handlers } = reviewed();
    const pending = handlers.resetSharedEditing();
    requests[0].reject(new APIError(status, 'Recovery requires review')); await pending;
    expect(env.error).toBe('Recovery requires review'); expect(env.review.generation).toBe('2');
    expect(env.successGeneration).toBeNull(); expect(env.recovered).toEqual([]);
  }
});

test('post-commit archive refresh failure reports success and retains separate reload', async () => {
  const { env, requests, handlers } = reviewed();
  const pending = handlers.resetSharedEditing();
  requests[0].resolve({ document: state('3').document, generation: '3' }); await settle();
  requests[1].reject(new APIError(503, 'unavailable')); await pending;
  expect(env.successGeneration).toBe('3'); expect(env.recovered).toEqual(['doc']);
  expect(env.error).toContain('was reset'); expect(handlers.readyToReload()).toBe(true);
});

test('late reset receipt after disposal or navigation cannot call the editor', async () => {
  for (const stop of [(env: any) => { env.disposed = true; }, (env: any) => { env.documentID = 'other'; }]) {
    const { env, requests, handlers } = reviewed(); const pending = handlers.resetSharedEditing();
    stop(env); requests[0].resolve({ document: state('3').document, generation: '3' }); await pending;
    expect(env.recovered).toEqual([]); expect(env.successGeneration).toBeNull(); expect(requests).toHaveLength(1);
  }
});

test('archive deletion requires confirmation and preserves metadata on privacy deferral', async () => {
  const { env, requests, handlers } = reviewed();
  env.window.confirm = () => false; await handlers.removeArchive('archive'); expect(requests).toHaveLength(0);
  env.window.confirm = () => true;
  const pending = handlers.removeArchive('archive');
  requests[0].reject(new APIError(409, 'An access request requires review')); await pending;
  expect(env.error).toBe('An access request requires review'); expect(env.review.archives).toHaveLength(1);
  const retry = handlers.removeArchive('archive'); requests[1].resolve(undefined); await retry;
  expect(env.review.archives).toHaveLength(0);
});

test('foreign or malformed recovery receipt cannot enable a reset', async () => {
  const { handlers } = fixture();
  expect(handlers.validState({ ...state(), document: { ...state().document, org_id: 'other' } }, 'doc')).toBe(false);
  expect(handlers.validState({ ...state(), generation: '9223372036854775808' }, 'doc')).toBe(false);
  expect(handlers.validState({ ...state(), archives: [{ ...state().archives[0], size_bytes: 8 * 1024 * 1024 + 1 }] }, 'doc')).toBe(false);
});

test('archive-only review admits deleted metadata but never offers reset or editor reload', async () => {
  const { env, requests, handlers } = fixture(); env.archiveReviewOnly = true;
  const pending = handlers.loadReview();
  requests[0].resolve({ org_id: 'org', role: 'owner' }); await settle();
  requests[1].resolve({ ...state(), document_deleted: true }); await pending;
  expect(env.review.document_deleted).toBe(true); expect(env.review.archives).toHaveLength(1);
  env.reviewedRevision = 1; env.capturedRevision = 1; env.acknowledged = true;
  env.successRevision = 1; env.successGeneration = '3';
  expect(handlers.readyToReset()).toBe(false); expect(handlers.readyToReload()).toBe(false);
  await handlers.resetSharedEditing(); handlers.reloadSavedDocument();
  expect(requests.map((request) => request.method)).toEqual(['me', 'get']);
  expect(env.recovered).toEqual([]); expect(env.reloaded).toEqual([]);
});

test('deleted or noneditable metadata also blocks reset in an existing editor panel', async () => {
  for (const replacement of [
    { ...state(), document_deleted: true },
    { ...state(), document: { ...state().document, status: 'sent' } },
    { ...state(), document: { ...state().document, source_kind: 'pdf' } }
  ]) {
    const { env, requests, handlers } = reviewed(); env.review = replacement;
    expect(handlers.validState(replacement, 'doc')).toBe(true);
    expect(handlers.readyToReset()).toBe(false); await handlers.resetSharedEditing();
    expect(requests).toHaveLength(0); expect(env.recovered).toEqual([]);
  }
});

test('archive-only mode still checks owner access before reading deleted history', async () => {
  const { env, requests, handlers } = fixture(); env.archiveReviewOnly = true;
  const pending = handlers.loadReview(); requests[0].resolve({ org_id: 'org', role: 'sender' }); await pending;
  expect(env.owner).toBe(false); expect(env.review).toBeNull(); expect(requests).toHaveLength(1);
});

test('archive deletion remains available during deleted-document review and fences late receipts', async () => {
  const { env, requests, handlers } = reviewed();
  env.archiveReviewOnly = true; env.review.document_deleted = true;
  const pending = handlers.removeArchive('archive');
  expect(requests[0].method).toBe('delete'); expect(requests[0].args).toEqual(['doc', 'archive']);
  env.documentID = 'next'; requests[0].resolve(undefined); await pending;
  expect(env.review.archives).toHaveLength(1);
});
