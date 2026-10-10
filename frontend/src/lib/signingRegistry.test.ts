import { expect, test } from 'bun:test';
import { SigningRegistryController, checkedSigningContext, checkedSigningDefinition, checkedSigningGrant, checkedSigningMarker, checkedSigningOutcome, checkedSigningPreview, readSigningMarker, saveSigningMarker, signingKey, signingNilUUID, signingRegistryMarkerKey,
  type SigningContext, type SigningGrantIntent, type SigningGrantPreview, type SigningMarker, type SigningOutcome, type SigningRegistryTransport, type SigningWorkflowDefinition, type SigningWorkflowIntent } from './signingRegistry';

const org = '11111111-1111-4111-8111-111111111111', user = '22222222-2222-4222-8222-222222222222';
const workflowID = '33333333-3333-4333-8333-333333333333', policyID = '44444444-4444-4444-8444-444444444444', grantID = '55555555-5555-4555-8555-555555555555';
const requestID = '66666666-6666-4666-8666-666666666666', templateID = '77777777-7777-4777-8777-777777777777';
const sha = 'a'.repeat(64), otherSHA = 'b'.repeat(64), now = Date.parse('2026-10-10T12:00:00Z');
const context = (): SigningContext => ({ org_id: org, user_id: user, self: { id: user, name: 'Åsa Example', email: 'asa@example.test', role: 'owner' }, execution_available: false,
  fonts: [{ font: 'Caveat', font_sha256: sha }], disclosure: { version: 1, sha256: sha, text: 'Future execution disclosure.' } });
const definition = (): SigningWorkflowDefinition => ({ version: 1, id: workflowID, policy_id: policyID, org_id: org, revision: 1, name: 'Reviewed proposal', kind: 'reviewed_document_send_v1',
  template: { id: templateID, version: 3, content_sha256: sha, approved_by: user, approved_at: '2026-10-09T12:00:00Z' }, executor: { kind: 'member', user_id: user, credential_id: signingNilUUID }, operation: 'pre_sign_and_send',
  input_rules: { version: 1, source_schema_version: 3, standalone: true, signature_fields_only: true, author_must_be_grantor: true }, data_rules: { version: 1, values: [], sections: [] },
  recipient_rules: { version: 1, provider: 'named_grantor_exact', customer: 'printed_profile_exact', mode: 'parallel', provider_company_name: 'Example AB', provider_company_id: '556000-0000', provider_authority_basis: 'Declared director authority' }, max_grant_duration_seconds: 86400, max_uses: 3 });
const grantIntent = (): SigningGrantIntent => ({ request_id: requestID, expected_org_id: org, expected_user_id: user, grant_id: grantID, expected_revision: 0,
  policy: { id: policyID, revision: 1, sha256: sha }, company_name: 'Example AB', company_id: '556000-0000', authority_basis: 'Declared director authority', font: 'Caveat', not_before: '0001-01-01T00:00:00Z', expires_at: '2026-10-11T12:00:00Z', max_uses: 3 });
const grantPreview = (intent = grantIntent()): SigningGrantPreview => ({ org_id: org, user_id: user, intent, grantor: { user_id: user, name: 'Åsa Example', email: 'asa@example.test', company_name: intent.company_name, company_id: intent.company_id, authority_basis: intent.authority_basis }, signature: context().fonts[0], disclosure: { version: 1, sha256: sha }, receipt: 'signed.preview.capability', expires_at: '2026-10-10T12:05:00Z' });
const committed = (operation: SigningOutcome['operation'] = 'grant.create'): SigningOutcome => ({ org_id: org, user_id: user, request_id: requestID, state: 'committed', operation, command_sha256: sha, resource_kind: operation.startsWith('workflow.') ? 'workflow' : 'grant', reference: { id: operation.startsWith('workflow.') ? workflowID : grantID, revision: 1, sha256: sha }, occurred_at: '2026-10-10T12:00:01Z' });
const closed = (): SigningOutcome => ({ org_id: org, user_id: user, request_id: requestID, state: 'closed', operation: 'request.close', reference: { id: signingNilUUID, revision: 0, sha256: '' }, occurred_at: '2026-10-10T12:00:02Z' });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve }; }
function fixture(ownerPage = false) {
  let actor = { org_id: org, user_id: user, role: 'owner' }, current = context(), saved: SigningMarker | null = null;
  const calls: { operation: string; input?: unknown; signal: AbortSignal }[] = [];
  const transport: SigningRegistryTransport = {
    identity: async () => actor, context: async () => current,
    templates: async () => ({ org_id: org, user_id: user, items: [], truncated: false }),
    workflows: async () => ({ org_id: org, user_id: user, items: [] }), grants: async () => ({ org_id: org, user_id: user, items: [] }),
    preview: async (kind, intent) => kind === 'grant' ? grantPreview(intent as SigningGrantIntent) : { org_id: org, user_id: user, intent, definition_sha256: sha, rules: { input_mode: 'reviewed_document', input_rules_sha256: sha, data_rules_sha256: sha, recipient_rules_sha256: sha }, receipt: 'signed.preview.capability', expires_at: '2026-10-10T12:05:00Z' },
    mutate: async (operation, input, signal) => { calls.push({ operation, input, signal }); return committed(operation); }, outcome: async () => committed(), close: async () => closed(), signatureFont: async () => 'HashAuthority_verified',
  };
  const controller = new SigningRegistryController(transport, () => {}, marker => { saved = marker; }, ownerPage, () => now);
  return { controller, transport, calls, marker: () => saved, setActor: (a: typeof actor) => { actor = a; }, setContext: (c: SigningContext) => { current = c; } };
}
async function prepare(f: ReturnType<typeof fixture>) { await f.controller.refresh(); await f.controller.preview(grantIntent()); f.controller.confirm(true); expect(f.controller.canConfirm).toBe(true); }

test('bounded strict context uses live self, server font assets and an unavailable execution gate', () => {
  expect(checkedSigningContext(context())).toEqual(context());
  for (const value of [{ ...context(), execution_available: true }, { ...context(), self: { ...context().self, id: grantID } }, { ...context(), fonts: ['Caveat'] }, { ...context(), credential: 'secret' }, { ...context(), disclosure: { ...context().disclosure, text: null } }]) expect(() => checkedSigningContext(value)).toThrow();
});
test('workflow normalization matches server sorted declarations, complete mode fields and decimal CRM generation', () => {
  const d = definition(); d.data_rules.values = [{ variable: 'zeta', mode: 'literal', literal: '' }, { variable: 'alpha', mode: 'grantor_field', grantor_field: 'name' }];
  expect(checkedSigningDefinition(d).data_rules.values.map(v => v.variable)).toEqual(['alpha', 'zeta']);
  d.data_rules.values = [{ variable: 'amount', mode: 'crm_scalar', source_kind: 'crm.deal', source_path: 'value' }];
  d.data_rules.crm = { connection_id: grantID, generation: '9007199254740993', origin: 'https://crm.example.test', team_id: 'team_CUID', user_id: 'user_CUID', selection: 'fixed_record_set', records: [{ kind: 'crm.deal', id: 'deal_CUID' }] };
  expect(checkedSigningDefinition(d).data_rules.crm?.generation).toBe('9007199254740993');
  for (const bad of [{ ...d, data_rules: { ...d.data_rules, crm: { ...d.data_rules.crm, generation: 9007199254740993 } } }, { ...d, data_rules: { ...d.data_rules, values: [{ variable: 'amount', mode: 'crm_scalar', literal: 'unused', source_kind: 'crm.deal', source_path: 'value' }] } }, { ...definition(), kind: 'approved_data_send_v1', data_rules: { version: 1, values: [{ variable: 'scope', mode: 'reviewed_value' }], sections: [] } }]) expect(() => checkedSigningDefinition(bad)).toThrow();
});
test('preview must be exact and explicit; editing candidate prevents dispatch without losing pending metadata', async () => {
  const f = fixture(); await prepare(f); expect(f.calls).toHaveLength(0); f.controller.invalidate(); await f.controller.approve(); expect(f.calls).toHaveLength(0);
  await f.controller.preview(grantIntent()); await f.controller.approve(); expect(f.calls).toHaveLength(0);
  f.controller.confirm(true); await f.controller.approve(); expect(f.calls).toHaveLength(1);
  expect(f.calls[0].input).toMatchObject({ intent: { expected_org_id: org, expected_user_id: user, request_id: requestID }, confirmed: true });
  expect(f.marker()).toMatchObject({ request_id: requestID, resource_id: grantID, operation: 'grant.create', command_sha256: sha });
  expect(f.controller.state.outcome?.state).toBe('committed'); expect(f.controller.canCreate).toBe(false);
  await f.controller.acknowledge(); expect(f.marker()).toBeNull(); expect(f.controller.canCreate).toBe(true);
});
test('font bytes/load failure, wrong live identity or changed copy cannot expose an actionable signature preview', async () => {
  for (const change of ['font', 'name', 'copy']) {
    const f = fixture(); await f.controller.refresh();
    if (change === 'font') f.transport.signatureFont = async () => { throw new Error('font unavailable'); };
    else f.transport.preview = async () => change === 'name' ? { ...grantPreview(), grantor: { ...grantPreview().grantor, name: 'Someone else' } } : { ...grantPreview(), disclosure: { version: 1, sha256: otherSHA } };
    await f.controller.preview(grantIntent()); f.controller.confirm(true); await f.controller.approve();
    expect(f.controller.state.preview).toBeNull(); expect(f.calls).toHaveLength(0);
  }
});
test('late preview after navigation or input change cannot adopt or authorize', async () => {
  for (const interrupt of ['navigation', 'edit']) {
    const f = fixture(); await f.controller.refresh(); const waiting = deferred<unknown>(); let started!: () => void; const dispatched = new Promise<void>(yes => { started = yes; });
    f.transport.preview = async () => { started(); return waiting.promise; };
    const running = f.controller.preview(grantIntent()); await dispatched;
    if (interrupt === 'navigation') f.controller.interrupt(); else f.controller.invalidate();
    waiting.resolve(grantPreview()); await running; expect(f.controller.state.preview).toBeNull(); expect(f.controller.canConfirm).toBe(false);
  }
});
test('A to B to A response witness is rejected independently of current identity probes', async () => {
  const f = fixture(); f.transport.context = async () => ({ ...context(), org_id: grantID, user_id: policyID, self: { ...context().self, id: policyID } });
  await f.controller.refresh(); expect(f.controller.state.context).toBeNull(); expect(f.controller.canWrite).toBe(false);
  const writes = fixture(); await prepare(writes); writes.transport.mutate = async () => ({ ...committed(), user_id: policyID });
  await writes.controller.approve(); expect(writes.controller.state.outcome).toBeNull(); expect(writes.marker()?.request_id).toBe(requestID);
});
test('lost success survives reload and real404; explicit committed or closed acknowledgment alone releases pending guard', async () => {
  const f = fixture(); await prepare(f); f.transport.mutate = async () => { throw new Error('lost response secret'); }; await f.controller.approve();
  expect(f.marker()?.request_id).toBe(requestID); expect(f.controller.state.error).not.toContain('secret');
  const reload = fixture(); reload.controller.restore(f.marker()); await reload.controller.refresh(); reload.transport.outcome = async () => { throw { status: 404 }; }; await reload.controller.inspect();
  expect(reload.controller.state.marker?.request_id).toBe(requestID); expect(reload.controller.canCreate).toBe(false); expect(reload.controller.state.outcome).toBeNull();
  reload.transport.outcome = async () => committed(); await reload.controller.inspect(); expect(reload.controller.canCreate).toBe(false); await reload.controller.acknowledge(); expect(reload.controller.canCreate).toBe(true);
  const stop = fixture(); stop.controller.restore(f.marker()); await stop.controller.refresh(); stop.transport.close = async () => { throw { status: 503 }; }; await stop.controller.stop(true); expect(stop.controller.state.marker?.request_id).toBe(requestID);
  stop.transport.outcome = async () => closed(); await stop.controller.inspect(); expect(stop.controller.state.outcome?.state).toBe('closed'); expect(stop.controller.canCreate).toBe(false); await stop.controller.acknowledge(); expect(stop.controller.canCreate).toBe(true);
});
test('known commit cannot become closed and wrong target/revision/digest cannot be adopted', async () => {
  const f = fixture(); await prepare(f); await f.controller.approve(); f.transport.outcome = async () => closed(); await f.controller.inspect(); expect(f.controller.state.outcome).toBeNull(); expect(f.controller.state.marker?.command_sha256).toBe(sha);
  for (const result of [{ ...committed(), reference: { ...committed().reference, id: policyID } }, { ...committed(), reference: { ...committed().reference, revision: 2 } }, { ...committed(), operation: 'grant.revise' }, { ...committed(), resource_kind: 'workflow' }]) {
    const x = fixture(); await prepare(x); x.transport.mutate = async () => result; await x.controller.approve(); expect(x.controller.state.outcome).toBeNull(); expect(x.controller.state.marker).not.toBeNull();
  }
});
test('foreign actor cannot inspect, stop or acknowledge original marker; late stopped callbacks stay fenced', async () => {
  const f = fixture(); await prepare(f); await f.controller.approve(); f.setActor({ org_id: org, user_id: policyID, role: 'owner' }); await f.controller.acknowledge(); expect(f.controller.state.marker?.request_id).toBe(requestID);
  const late = fixture(); await prepare(late); const waiting = deferred<unknown>(); let started!: () => void; const dispatched = new Promise<void>(yes => { started = yes; });
  late.transport.mutate = async () => { started(); return waiting.promise; }; const sending = late.controller.approve(); await dispatched;
  await late.controller.stop(true); expect(late.controller.state.outcome?.state).toBe('closed'); waiting.resolve(committed()); await sending; expect(late.controller.state.outcome?.state).toBe('closed');
});
test('same request retry retains exact immutable input and marker contains no personal assertions or receipts', async () => {
  const f = fixture(); await prepare(f); let tries = 0, first: unknown; f.transport.mutate = async (_, input) => { tries++; if (tries === 1) { first = structuredClone(input); throw new Error(); } expect(input).toEqual(first); return committed(); };
  await f.controller.approve(); f.controller.invalidate(); await f.controller.retry(); expect(tries).toBe(2);
  const map = new Map<string, string>(), storage = { getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => { map.set(k, v); }, removeItem: (k: string) => { map.delete(k); } };
  saveSigningMarker(storage, f.marker()); expect(readSigningMarker(storage)).toEqual(f.marker());
  const raw = map.get(signingRegistryMarkerKey)!; for (const privateText of ['Åsa', 'asa@example', 'Example AB', 'capability', 'receipt', 'company']) expect(raw).not.toContain(privateText);
  expect(() => checkedSigningMarker({ ...f.marker(), company_name: 'PII' })).toThrow();
});
test('viewer may revoke own recorded authority but cannot create or renew; removed or foreign memberships cannot mutate', async () => {
  const f = fixture(), c = context(); c.self.role = 'viewer'; f.setContext(c); f.setActor({ org_id: org, user_id: user, role: 'viewer' });
  const grant = { schema_version: 1, id: grantID, org_id: org, revision: 1, policy: grantIntent().policy, grantor: grantPreview().grantor, signature: grantPreview().signature, disclosure: grantPreview().disclosure, granted_at: '2026-10-10T12:00:00Z', not_before: '2026-10-10T12:00:00Z', expires_at: '2026-10-11T12:00:00Z', max_uses: 3 };
  const view = checkedSigningGrant({ org_id: org, user_id: user, grant, reference: { id: grantID, revision: 1, sha256: sha }, current_revision: 1, revoked: false, expired: false, consumed_uses: 0, execution_available: false });
  f.transport.grants = async () => ({ org_id: org, user_id: user, items: [view] }); await f.controller.refresh(); expect(f.controller.canCreate).toBe(false);
  await f.controller.preview(grantIntent()); expect(f.controller.state.preview).toBeNull();
  f.transport.mutate = async (operation, input, signal) => { f.calls.push({ operation, input, signal }); return { ...committed(operation), request_id: (input as { request_id: string }).request_id }; };
  await f.controller.resource('grant.self_revoke', view.reference, true); expect(f.calls).toHaveLength(1); expect(f.calls[0].operation).toBe('grant.self_revoke');
});
test('owner workflow confirmation uses exact template and normalized readable rule intent', async () => {
  const f = fixture(true); await f.controller.refresh(); const intent: SigningWorkflowIntent = { request_id: requestID, expected_org_id: org, expected_user_id: user, expected_revision: 0, definition: definition() };
  await f.controller.preview(intent); f.controller.confirm(true); await f.controller.approve(); expect(f.calls[0].operation).toBe('workflow.approve'); expect(f.controller.state.outcome?.reference.id).toBe(workflowID);
  expect(() => checkedSigningPreview({ ...grantPreview(), token: 'unexpected' }, 'grant')).toThrow();
  expect(() => checkedSigningOutcome({ ...closed(), command_sha256: sha })).toThrow();
  expect(signingKey({ a: 1, b: 2 })).toBe(signingKey({ b: 2, a: 1 }));
});
test('storage failure prevents dispatch, and navigating after dispatch retains a recoverable original request', async () => {
  const f = fixture(); const blocked = new SigningRegistryController(f.transport, () => {}, () => { throw new Error('storage denied'); }, false, () => now);
  await blocked.refresh(); await blocked.preview(grantIntent()); blocked.confirm(true); await blocked.approve(); expect(f.calls).toHaveLength(0); expect(blocked.state.outcome).toBeNull();
  const late = fixture(); await prepare(late); const waiting = deferred<unknown>(); let entered!: () => void; const dispatched = new Promise<void>(yes => { entered = yes; }); let signal!: AbortSignal;
  late.transport.mutate = async (_, __, captured) => { signal = captured; entered(); return waiting.promise; }; const running = late.controller.approve(); await dispatched;
  late.controller.interrupt(); expect(signal.aborted).toBe(true); expect(late.marker()?.request_id).toBe(requestID); waiting.resolve(committed()); await running;
  expect(late.controller.state.outcome).toBeNull(); await late.controller.inspect(); expect(late.controller.state.outcome?.state).toBe('committed');
});
test('a blank current member name permits request recovery but cannot record a new named authority', async () => {
  const f = fixture(), c = context(); c.self.name = ''; f.setContext(c); await f.controller.refresh();
  expect(f.controller.state.context?.self.name).toBe(''); expect(f.controller.canWrite).toBe(true); expect(f.controller.canCreate).toBe(false);
  f.controller.restore({ version: 1, org_id: org, user_id: user, request_id: requestID, operation: 'grant.create', resource_id: grantID, resource_revision: 1 }); await f.controller.inspect();
  expect(f.controller.state.outcome?.state).toBe('committed'); await f.controller.acknowledge(); expect(f.controller.state.marker).toBeNull(); expect(f.controller.canCreate).toBe(false);
});
