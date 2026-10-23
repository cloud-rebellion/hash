import { expect, test } from 'bun:test';
import { PreSignController, checkedPreSignDocumentView, checkedPreSignEligibility, checkedPreSignIntent, checkedPreSignMarker, checkedPreSignView, preSignDocumentMatchesResult, preSignMarkerKey, readPreSignMarker, savePreSignMarker,
  type PreSignEligibility, type PreSignIntent, type PreSignMarker, type PreSignTransport, type PreSignView } from './presignExecution';
import { signingKey, signingNilUUID, type SigningContext, type SigningWorkflowDefinition } from './signingRegistry';

const org = '11111111-1111-4111-8111-111111111111', user = '22222222-2222-4222-8222-222222222222';
const documentID = '33333333-3333-4333-8333-333333333333', materializationID = '44444444-4444-4444-8444-444444444444', grantID = '55555555-5555-4555-8555-555555555555';
const policyID = '66666666-6666-4666-8666-666666666666', workflowID = '77777777-7777-4777-8777-777777777777', templateID = '88888888-8888-4888-8888-888888888888', executionID = '99999999-9999-4999-8999-999999999999';
const sha = 'a'.repeat(64), visibleSHA = 'b'.repeat(64), now = Date.parse('2026-10-23T12:00:00Z');
const source = { document_updated_at: '2026-10-23T11:00:00.123456Z', materialization_id: materializationID, materialization_revision: 2, source_commitment: sha };
const eligibility = (): PreSignEligibility => ({ schema_version: 1, org_id: org, user_id: user, document_id: documentID, eligible: true, source: { ...source } });
const context = (): SigningContext => ({ org_id: org, user_id: user, self: { id: user, name: 'Provider Example', email: 'provider@example.test', role: 'owner' }, execution_available: true,
  fonts: [{ font: 'Caveat', font_sha256: sha }], disclosure: { version: 1, sha256: sha, text: 'Named provider authority.' } });
function definition(): SigningWorkflowDefinition { return { version: 1, id: workflowID, policy_id: policyID, org_id: org, revision: 1, name: 'Exact agreement', kind: 'reviewed_document_send_v1',
  template: { id: templateID, version: 3, content_sha256: sha, approved_by: user, approved_at: '2026-10-22T12:00:00Z' }, executor: { kind: 'member', user_id: user, credential_id: signingNilUUID }, operation: 'pre_sign_and_send',
  input_rules: { version: 1, source_schema_version: 3, standalone: true, signature_fields_only: true, author_must_be_grantor: true }, data_rules: { version: 1, values: [], sections: [] },
  recipient_rules: { version: 1, provider: 'named_grantor_exact', customer: 'printed_profile_exact', mode: 'parallel', provider_company_name: 'Example AB', provider_company_id: '556000-0000', provider_authority_basis: 'Declared director' }, max_grant_duration_seconds: 86400, max_uses: 3 }; }
function workflow() { const d = definition(); return { org_id: org, user_id: user, definition: d, definition_sha256: sha,
  policy: { schema_version: 1, id: policyID, org_id: org, revision: 1, template: d.template, workflow: { id: d.id, revision: 1, content_sha256: sha, approved_by: user, approved_at: d.template.approved_at }, executor: d.executor, operation: d.operation,
    rules: { input_mode: 'reviewed_document', input_rules_sha256: sha, data_rules_sha256: sha, recipient_rules_sha256: sha }, max_grant_duration_seconds: 86400, max_uses: 3, approved_by: user, approved_at: d.template.approved_at },
  policy_reference: { id: policyID, revision: 1, sha256: sha }, current_revision: 1, archived: false, retired: false }; }
function grant() { return { org_id: org, user_id: user, grant: { schema_version: 1, id: grantID, org_id: org, revision: 1, policy: { id: policyID, revision: 1, sha256: sha },
  grantor: { user_id: user, name: 'Provider Example', email: 'provider@example.test', company_name: 'Example AB', company_id: '556000-0000', authority_basis: 'Declared director' }, signature: { font: 'Caveat', font_sha256: sha }, disclosure: { version: 1, sha256: sha },
  granted_at: '2026-10-23T10:00:00Z', not_before: '2026-10-23T10:00:00Z', expires_at: '2026-10-24T10:00:00Z', max_uses: 3 },
  reference: { id: grantID, revision: 1, sha256: sha }, current_revision: 1, revoked: false, expired: false, consumed_uses: 1, execution_available: true }; }
function result(intent: PreSignIntent, publication: 'sealing' | 'published' = 'sealing'): PreSignView { return { schema_version: 1, org_id: org, user_id: user, request_id: intent.request_id, state: 'committed', result: {
  command_sha256: sha, execution: { id: executionID, sha256: sha }, document_id: documentID, materialization_id: materializationID, materialization_revision: 2, source_commitment: sha, visible_pdf_sha256: visibleSHA, page_count: 2, use_number: 2, publication } }; }
function fixture() {
  let who = { org_id: org, user_id: user, role: 'owner' }, stored: PreSignMarker | null = null, prepared: PreSignIntent | null = null;
  const calls: string[] = [], current = context(), grantView = grant(), workflowView = workflow();
  const transport: PreSignTransport = {
    identity: async () => who, context: async () => current,
    grants: async () => ({ org_id: org, user_id: user, items: [grantView] }), workflows: async () => ({ org_id: org, user_id: user, items: [workflowView] }),
    eligibility: async () => eligibility(),
    preview: async intent => { prepared = intent; return { schema_version: 1, org_id: org, user_id: user, intent, receipt: 'original.session.receipt', expires_at: '2026-10-23T12:05:00Z', provider_name: 'Provider Example', provider_email: 'provider@example.test', customer_name: 'Customer Example', customer_email: 'customer@example.test', disclosure: 'Provider pre-signing.\nCustomer signs explicitly.', remaining_uses: 2 }; },
    execute: async input => { expect(stored?.request_id).toBe(input.intent.request_id); calls.push('execute'); return result(input.intent); },
    inspect: async () => { calls.push('inspect'); return result(prepared!); }, close: async marker => { calls.push('close'); return { schema_version: 1, org_id: org, user_id: user, request_id: marker.request_id, state: 'closed' }; },
  };
  const controller = new PreSignController(transport, () => {}, marker => { calls.push(marker ? 'persist' : 'clear'); stored = marker; }, () => now);
  return { controller, transport, calls, current, grantView, workflowView, stored: () => stored, intent: () => prepared!, actor: (value: typeof who) => { who = value; } };
}
async function prepare(f: ReturnType<typeof fixture>) {
  await f.controller.refresh(documentID); expect(f.controller.canPrepare).toBe(true);
  await f.controller.preview(signingKey(grant().reference), 'contract', sha); f.controller.confirm(true); expect(f.controller.canConfirm).toBe(true);
}

test('execution wire unions are closed and never interpret missing or malformed result as closed', () => {
  expect(checkedPreSignEligibility(eligibility()).eligible).toBe(true);
  expect(checkedPreSignEligibility({ schema_version: 1, org_id: org, user_id: user, document_id: documentID, eligible: false })).toEqual({ schema_version: 1, org_id: org, user_id: user, document_id: documentID, eligible: false });
  for (const changed of [{ ...eligibility(), eligible: false }, { ...eligibility(), source: null }, { ...eligibility(), eligible: 1 }, { ...eligibility(), storage_key: 'private' }]) expect(() => checkedPreSignEligibility(changed)).toThrow();
  const intent: PreSignIntent = { request_id: executionID, expected_org_id: org, expected_user_id: user, document_id: documentID, ...source, policy: grant().grant.policy, grant: grant().reference, lawful_basis: 'contract' };
  const committed = result(intent); expect(checkedPreSignView(committed)).toEqual(committed);
  for (const changed of [{ ...committed, result: undefined }, { ...committed, state: 'closed' }, { ...committed, state: 'missing' }, { ...committed, object_version: 'private' }]) expect(() => checkedPreSignView(changed)).toThrow();
  if (committed.state !== 'committed') throw new Error('fixture');
  for (const changed of [{ ...committed.result, publication: 'unknown' }, { ...committed.result, page_count: 501 }, { ...committed.result, visible_pdf_sha256: 'base' }, { ...committed.result, execution: { ...committed.result.execution, storage_key: 'secret' } }]) expect(() => checkedPreSignView({ ...committed, result: changed })).toThrow();
  const view = { schema_version: 1, execution: committed.result.execution, publication: 'published', visible_pdf_sha256: visibleSHA, page_count: 2 };
  expect(checkedPreSignDocumentView(view)).toEqual(view);
  expect(preSignDocumentMatchesResult(checkedPreSignDocumentView(view), committed.result)).toBe(true);
  expect(preSignDocumentMatchesResult(checkedPreSignDocumentView({ ...view, publication: 'sealing' }), { ...committed.result, publication: 'published' })).toBe(false);
  expect(preSignDocumentMatchesResult(checkedPreSignDocumentView({ ...view, publication: 'expired' }), { ...committed.result, publication: 'completed' })).toBe(false);
  expect(preSignDocumentMatchesResult(checkedPreSignDocumentView({ ...view, visible_pdf_sha256: sha }), committed.result)).toBe(false);
  for (const changed of [null, { ...view, page_count: 501 }, { ...view, storage_key: 'secret' }, { ...view, publication: 'pending' }]) expect(() => checkedPreSignDocumentView(changed)).toThrow();
  expect(() => checkedPreSignIntent({ ...intent, lawful_basis: 'other' })).toThrow();
});
test('availability is a real boolean but only exact current member grant, workflow and eligible source permit review', async () => {
  const cases: ((f: ReturnType<typeof fixture>) => void)[] = [f => { f.current.execution_available = false; }, f => { f.grantView.execution_available = false; }, f => { f.grantView.consumed_uses = 3; }, f => { f.grantView.revoked = true; }, f => { f.grantView.current_revision = 2; }, f => { f.workflowView.retired = true; }, f => { f.workflowView.definition.executor.user_id = grantID; f.workflowView.policy.executor.user_id = grantID; }];
  for (const mutate of cases) {
    const f = fixture(); mutate(f); await f.controller.refresh(documentID); expect(f.controller.canPrepare).toBe(false); expect(f.calls).toEqual([]);
  }
  const f = fixture(); f.transport.eligibility = async () => ({ schema_version: 1, org_id: org, user_id: user, document_id: documentID, eligible: false });
  await f.controller.refresh(documentID); expect(f.controller.canPrepare).toBe(false);
});
test('confirmed execution persists opaque original marker before POST and keeps committed sealing as committed', async () => {
  const f = fixture(); await prepare(f); await f.controller.execute();
  expect(f.calls.slice(0, 2)).toEqual(['persist', 'execute']); expect(f.controller.state.outcome?.state).toBe('committed');
  expect(f.stored()?.command_sha256).toBe(sha); expect(f.controller.canPrepare).toBe(false);
  const encoded = JSON.stringify(f.stored()); for (const privateValue of ['receipt', 'provider@example', 'Customer Example', 'disclosure', 'storage_key']) expect(encoded).not.toContain(privateValue);
  await f.controller.acknowledge(); expect(f.stored()).not.toBeNull();
  f.transport.inspect = async () => result(f.intent(), 'published'); await f.controller.inspect(); await f.controller.acknowledge(); expect(f.stored()).toBeNull();
});
test('lost response and scoped absence preserve original request and cannot create a second execution', async () => {
  for (const status of [401, 403, 404, 409, 503]) {
    const f = fixture(); await prepare(f); f.transport.execute = async () => { f.calls.push('execute'); throw { status, message: 'private raw failure' }; };
    await f.controller.execute(); const marker = f.stored(); expect(marker).not.toBeNull(); expect(f.controller.state.outcome).toBeNull(); expect(f.controller.canPrepare).toBe(false);
    f.transport.inspect = async () => { throw { status: 404 }; }; await f.controller.inspect(); expect(f.stored()).toEqual(marker); expect(f.controller.state.error).not.toContain('private raw');
    await f.controller.refresh(documentID); await f.controller.preview(signingKey(grant().reference), 'contract', sha); await f.controller.execute(); expect(f.calls.filter(v => v === 'execute')).toHaveLength(1);
    await f.controller.close(true); expect(f.controller.state.outcome?.state).toBe('closed'); await f.controller.acknowledge(); expect(f.stored()).toBeNull();
  }
});
test('original actor and source changes cancel stale pre-effect requests while marker survives post-effect invalidation', async () => {
  const f = fixture(); await prepare(f);
  let resolve!: (value: unknown) => void, reached!: () => void; const atEligibility = new Promise<void>(yes => { reached = yes; });
  f.transport.eligibility = () => new Promise(yes => { resolve = yes; reached(); });
  const pending = f.controller.execute(); await atEligibility; f.controller.invalidate(); resolve(eligibility()); await pending;
  expect(f.calls).toEqual([]); expect(f.stored()).toBeNull();
  const moved = fixture(); await prepare(moved); moved.actor({ org_id: org, user_id: grantID, role: 'owner' }); await moved.controller.execute(); expect(moved.calls).toEqual([]);
  const role = fixture(); await prepare(role); role.actor({ org_id: org, user_id: user, role: 'viewer' }); await role.controller.execute(); expect(role.calls).toEqual([]);
  const sourceChanged = fixture(); await prepare(sourceChanged); sourceChanged.transport.eligibility = async () => ({ ...eligibility(), source: { ...source, materialization_revision: 3 } }); await sourceChanged.controller.execute(); expect(sourceChanged.calls).toEqual([]);
  const lost = fixture(); await prepare(lost); lost.transport.execute = async () => { throw { status: 503 }; }; await lost.controller.execute(); const marker = lost.stored(); lost.controller.invalidate(); expect(lost.stored()).toEqual(marker);
});
test('foreign recovered results and raced closure never clear or relabel the original committed request', async () => {
  const f = fixture(); await prepare(f); f.transport.execute = async () => { throw { status: 503 }; }; await f.controller.execute();
  f.transport.inspect = async () => { const view = result(f.intent()); if (view.state === 'committed') view.result.source_commitment = visibleSHA; return view; };
  await f.controller.inspect(); expect(f.controller.state.outcome).toBeNull(); expect(f.stored()).not.toBeNull();
  f.transport.close = async () => result(f.intent(), 'published'); await f.controller.close(true); expect(f.controller.state.outcome?.state).toBe('committed'); expect(f.stored()?.command_sha256).toBe(sha);
});
test('recovery storage rejects corruption and confirms durable opaque write before any effectful dispatch', async () => {
  const map = new Map<string, string>(); const storage = { getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => { map.set(k, v); }, removeItem: (k: string) => { map.delete(k); } };
  const marker: PreSignMarker = { version: 1, org_id: org, user_id: user, request_id: executionID, document_id: documentID, materialization_id: materializationID, materialization_revision: 2, source_commitment: sha };
  savePreSignMarker(storage, marker); expect(readPreSignMarker(storage)).toEqual({ marker, invalid: false });
  expect(() => checkedPreSignMarker({ ...marker, receipt: 'private' })).toThrow();
  for (const raw of ['{', '{}', ' '.repeat(4097), JSON.stringify({ ...marker, materialization_revision: true })]) { map.set(preSignMarkerKey, raw); expect(readPreSignMarker(storage).invalid).toBe(true); }
  expect(() => savePreSignMarker({ ...storage, setItem: () => {}, getItem: () => null }, marker)).toThrow();
  const f = fixture(); await prepare(f); let writes = 0;
  const blocked = new PreSignController(f.transport, () => {}, () => { writes++; throw new Error('storage unavailable'); }, () => now);
  blocked.state = f.controller.state; await blocked.execute(); expect(writes).toBe(1); expect(blocked.state.markerError).toBe(true); expect(f.calls).toEqual([]);
});
