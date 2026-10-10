import { expect, test } from 'bun:test';
import { APIError, type DocumentResponse } from './api/client';
import { CRMDocumentController, checkedCRMApply, checkedCRMContext, checkedCRMObservation, checkedCRMSearch, crmExpected, crmMappingKey,
  validCRMSearch, type CRMDocumentActor, type CRMDocumentContext, type CRMDocumentTransport, type CRMObservation } from './crmDocument';

export const CRM_ACTOR: CRMDocumentActor = { org_id: '22222222-2222-4222-8222-222222222222', user_id: '11111111-1111-4111-8111-111111111111', role: 'sender' };
export const CRM_DOCUMENT_ID = '33333333-3333-4333-8333-333333333333';
export function crmDocumentFixture(): DocumentResponse {
  return { id: CRM_DOCUMENT_ID, org_id: CRM_ACTOR.org_id, sender_id: CRM_ACTOR.user_id, name: 'Reviewed contract', status: 'draft', routing_mode: 'parallel',
    source_kind: 'blocks', blocks_json: { version: 1, blocks: [] }, variables_json: { amount: '123.00' }, metadata: {}, default_locale: 'en',
    created_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:01:00.000000123Z' };
}
export function crmContextFixture(document = crmDocumentFixture()): CRMDocumentContext {
  return { org_id: CRM_ACTOR.org_id, user_id: CRM_ACTOR.user_id, document_id: document.id, updated_at: document.updated_at,
    html_source_commitment: document.html_source_commitment ?? '', binding_fingerprint: 'a'.repeat(64), connection: {
      id: '44444444-4444-4444-8444-444444444444', generation: '9007199254740993', status: 'active', origin: 'https://crm.example.test', crm_team_id: 'team_CUID2', crm_user_id: 'user_CUID2',
    }, supported: true, available: true, mapping_review_required: false,
    variables: [{ name: 'amount', required: true, max_chars: 8192, current_value: document.variables_json.amount }], bindings: [],
    catalog: { 'crm.deal': [{ path: 'value', type: 'decimal', nullable: true, derived: false }], 'crm.contact': [], 'crm.company': [] } };
}
export const CRM_MAPPING = { variable: 'amount', source_kind: 'crm.deal' as const, source_ref: 'deal_CUID2', source_path: 'value' };
export function crmObservationFixture(context = crmContextFixture(), value = '12345678901234567890.012300'): CRMObservation {
  return { org_id: context.org_id, user_id: context.user_id, document_id: context.document_id, updated_at: context.updated_at,
    html_source_commitment: context.html_source_commitment, binding_fingerprint: context.binding_fingerprint, connection: context.connection,
    mappings: [CRM_MAPPING], items: [{ ...CRM_MAPPING, current_value: context.variables[0].current_value, available: true, value,
      crm_observation: { connection_id: context.connection!.id, generation: context.connection!.generation, origin: context.connection!.origin,
        crm_team_id: context.connection!.crm_team_id, crm_user_id: context.connection!.crm_user_id, record_updated_at: '2026-10-10T12:00:00Z',
        observed_at: '2026-10-10T12:02:00Z', body_sha256: 'b'.repeat(64), value_sha256: 'c'.repeat(64) } }],
    review_digest: 'd'.repeat(64), can_apply: true, content_changed: value !== context.variables[0].current_value, observed_at: '2026-10-10T12:02:00Z' };
}
function fixture() {
  let doc = crmDocumentFixture(), context = crmContextFixture(doc), clean = true, clock = Date.parse('2026-10-10T12:02:01Z');
  const calls: any[] = [], adopted: DocumentResponse[] = [];
  const transport: CRMDocumentTransport = {
    identity: async () => CRM_ACTOR, context: async () => context, document: async () => doc,
    source: async () => { throw new Error('Unexpected HTML source read'); },
    search: async (id, input) => { calls.push({ kind: 'search', id, input }); return { ...contextWitness(context), kind: input.kind, query: input.query, offset: input.offset,
      choices: [{ kind: input.kind, id: 'deal_CUID2', label: 'Selected deal', secondary: '', record_updated_at: '2026-10-10T12:00:00Z' }], has_more: false, next_offset: 0 }; },
    observe: async (id, input) => { calls.push({ kind: 'observe', id, input }); return input.mappings.length ? crmObservationFixture(context) : {
      ...contextWitness(context), mappings: [], items: [], review_digest: 'd'.repeat(64), can_apply: true, content_changed: false, observed_at: '' }; },
    apply: async (id, input) => { calls.push({ kind: 'apply', id, input });
      doc = { ...doc, variables_json: { ...doc.variables_json, amount: '12345678901234567890.012300' }, updated_at: '2026-10-10T12:03:00.000000456Z' };
      context = { ...crmContextFixture(doc), binding_fingerprint: 'e'.repeat(64), bindings: input.mappings.map((m) => ({ ...m, updated_at: doc.updated_at })) };
      return { ...contextWitness(context), document: doc, content_changed: !!input.mappings.length, mapping_review_required: false }; },
  };
  const controller = new CRMDocumentController(doc, CRM_ACTOR, transport, () => {}, () => clean, (d) => { adopted.push(d); return true; }, () => clock);
  return { controller, transport, calls, adopted, setClean: (v: boolean) => { clean = v; }, setClock: (v: number) => { clock = v; },
    context: () => context, setContext: (v: CRMDocumentContext) => { context = v; }, document: () => doc };
}
function contextWitness(c: CRMDocumentContext) {
  const { org_id, user_id, document_id, updated_at, html_source_commitment, binding_fingerprint, connection } = c;
  return { org_id, user_id, document_id, updated_at, html_source_commitment, binding_fingerprint, connection };
}
async function proposal(f: ReturnType<typeof fixture>) {
  await f.controller.refresh(); f.controller.select({ kind: 'crm.deal', id: CRM_MAPPING.source_ref, label: 'Selected deal', secondary: '', record_updated_at: '2026-10-10T12:00:00Z' });
  f.controller.map('amount', { kind: 'crm.deal', path: 'value' }); await f.controller.observe();
}
test('manual unbound drafts remain usable without CRM; unknown state and durable review requirement fail closed', async () => {
  const f = fixture(); expect(f.controller.sendBlocked()).toBe(true);
  f.setContext({ ...f.context(), available: false, connection: null }); await f.controller.refresh();
  expect(f.controller.sendBlocked()).toBe(false); expect(f.controller.canDiscover()).toBe(false);
  f.setContext({ ...f.context(), mapping_review_required: true }); await f.controller.refresh(); expect(f.controller.sendBlocked()).toBe(true);
});
test('selection and mapping never write; exact decimal observation needs digest-specific confirmation and clean editor', async () => {
  const f = fixture(); await proposal(f);
  expect(f.calls.map((c) => c.kind)).toEqual(['observe']); expect(f.controller.state.observation?.items[0].value).toBe('12345678901234567890.012300');
  expect(f.controller.sendBlocked()).toBe(true); f.controller.confirm('0'.repeat(64), true); await f.controller.apply(); expect(f.calls).toHaveLength(1);
  f.controller.confirm('d'.repeat(64), true); f.setClean(false); await f.controller.apply(); expect(f.calls).toHaveLength(1);
  f.setClean(true); await f.controller.apply(); expect(f.calls.map((c) => c.kind)).toEqual(['observe', 'apply']);
  expect(f.calls[1].input).toMatchObject({ ...crmExpected(crmContextFixture()), mappings: [CRM_MAPPING], reviewed_digest: 'd'.repeat(64), confirmed: true });
  expect(f.adopted[0].variables_json.amount).toBe('12345678901234567890.012300'); expect(f.controller.sendBlocked()).toBe(false);
});
test('mapping equality binds semantic fields independently of JSON member order and still refuses changed references', () => {
  const reordered = { source_path: CRM_MAPPING.source_path, source_ref: CRM_MAPPING.source_ref, source_kind: CRM_MAPPING.source_kind, variable: CRM_MAPPING.variable };
  expect(crmMappingKey([reordered])).toBe(crmMappingKey([CRM_MAPPING]));
  expect(crmMappingKey([{ ...reordered, source_ref: 'other_deal_CUID2' }])).not.toBe(crmMappingKey([CRM_MAPPING]));
  expect(checkedCRMObservation({ ...crmObservationFixture(), mappings: [reordered] }).mappings).toEqual([CRM_MAPPING]);
});
test('undeclared destinations and uncatalogued source paths cannot be mapped, and changing mapping clears confirmation', async () => {
  const f = fixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true);
  f.controller.map('legal_prose', { kind: 'crm.deal', path: 'value' }); f.controller.map('amount', { kind: 'crm.deal', path: 'authority' });
  expect(f.controller.state.mappings).toEqual([CRM_MAPPING]); expect(f.controller.state.confirmation).toBe('d'.repeat(64));
  f.controller.map('amount'); expect(f.controller.state.confirmation).toBe(''); expect(f.controller.state.observation).toBeNull();
});
test('explicit empty mapping review can unlink without provider, retains current values and requires confirmation', async () => {
  const f = fixture(); f.setContext({ ...f.context(), available: false, connection: null, mapping_review_required: true,
    bindings: [{ ...CRM_MAPPING, updated_at: f.document().updated_at }] }); await f.controller.refresh(); f.controller.unlink(); await f.controller.observe();
  expect(f.controller.state.observation?.observed_at).toBe(''); expect(f.controller.canApply()).toBe(false);
  f.controller.confirm('d'.repeat(64), true);
  f.transport.apply = async (_id, input) => {
    f.calls.push({ kind: 'apply', input }); const context = { ...f.context(), bindings: [], mapping_review_required: false, binding_fingerprint: 'e'.repeat(64) }; f.setContext(context);
    return { ...contextWitness(context), document: f.document(), content_changed: false, mapping_review_required: false };
  };
  await f.controller.apply(); expect(f.adopted[0].variables_json.amount).toBe('123.00'); expect(f.controller.sendBlocked()).toBe(false);
});
test('expired confirmation and provider drift refuse Apply without adopting or automatically retrying', async () => {
  const expired = fixture(); await proposal(expired); expired.controller.confirm('d'.repeat(64), true); expired.setClock(Date.parse('2026-10-10T12:02:46Z')); expired.controller.expire();
  expect(expired.controller.state.confirmation).toBe(''); await expired.controller.apply(); expect(expired.calls).toHaveLength(1);
  const drift = fixture(); await proposal(drift); drift.controller.confirm('d'.repeat(64), true); drift.transport.apply = async () => { throw new APIError(409, 'secret provider details'); };
  await drift.controller.apply(); expect(drift.adopted).toEqual([]); expect(drift.controller.state.needsReadback).toBe(false);
  expect(drift.controller.state.error).not.toContain('secret'); expect(drift.controller.sendBlocked()).toBe(true); await drift.controller.apply(); expect(drift.adopted).toEqual([]);
});
test('response actor witness closes cookie A-B-A despite identity bookends returning A', async () => {
  for (const method of ['context', 'search', 'observe'] as const) {
    const f = fixture(); if (method !== 'context') await proposal(f);
    if (method === 'context') f.transport.context = async () => ({ ...f.context(), user_id: '55555555-5555-4555-8555-555555555555' });
    if (method === 'search') f.transport.search = async () => ({ ...contextWitness(f.context()), user_id: '55555555-5555-4555-8555-555555555555', kind: 'crm.deal', query: 'Deal', offset: 0, choices: [], has_more: false, next_offset: 0 });
    if (method === 'observe') f.transport.observe = async () => ({ ...crmObservationFixture(f.context()), user_id: '55555555-5555-4555-8555-555555555555' });
    if (method === 'context') await f.controller.refresh(); else if (method === 'search') await f.controller.search('crm.deal', 'Deal'); else await f.controller.observe();
    expect(f.controller.state.fresh).toBe(false); expect(f.adopted).toEqual([]); expect(f.controller.state.search).toBeNull();
  }
});
test('navigation and full binding-ledger change invalidate late search/observation completions', async () => {
  for (const operation of ['search', 'observe'] as const) {
    const f = fixture(); await proposal(f); let settle!: (v: unknown) => void;
    if (operation === 'search') f.transport.search = async () => new Promise((r) => { settle = r; });
    else f.transport.observe = async () => new Promise((r) => { settle = r; });
    const pending = operation === 'search' ? f.controller.search('crm.deal', 'Deal') : f.controller.observe(); await Promise.resolve();
    f.controller.interrupt(); f.setContext({ ...f.context(), binding_fingerprint: 'f'.repeat(64) }); await f.controller.refresh();
    if (operation === 'search') settle({ ...contextWitness(crmContextFixture()), kind: 'crm.deal', query: 'Deal', offset: 0, choices: [], has_more: false, next_offset: 0 });
    else settle(crmObservationFixture()); await pending;
    expect(f.controller.state.context?.binding_fingerprint).toBe('f'.repeat(64)); expect(f.controller.state.observation).toBeNull(); expect(f.controller.state.search).toBeNull();
  }
});
test('uncertain Apply cannot repeat; readback is explicit and never overwrites a dirty editor', async () => {
  const f = fixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); let writes = 0;
  f.transport.apply = async () => { writes++; throw new TypeError('network lost'); }; await f.controller.apply();
  expect(f.controller.state.needsReadback).toBe(true); await f.controller.apply(); await f.controller.refresh(); expect(writes).toBe(1);
  await f.controller.inspectReadback(); expect(f.controller.state.readback?.document.id).toBe(CRM_DOCUMENT_ID); expect(f.adopted).toEqual([]);
  f.setClean(false); f.controller.adoptReadback(); expect(f.adopted).toEqual([]); expect(f.controller.state.needsReadback).toBe(true);
  f.setClean(true); f.controller.adoptReadback(); expect(f.adopted).toHaveLength(1); expect(f.controller.state.needsReadback).toBe(false);
});
test('normal Apply adopts only the exact confirmed values and preserves every unmapped static value', async () => {
  for (const corruption of ['mapped', 'removed-static', 'changed-static', 'extra-static', 'context'] as const) {
    const f = fixture(); f.document().variables_json.manual_reference = 'Human reference'; await proposal(f); f.controller.confirm('d'.repeat(64), true);
    const actualApply = f.transport.apply;
    f.transport.apply = async (...args) => {
      const result = await actualApply(...args) as any;
      const variables = { ...result.document.variables_json };
      if (corruption === 'mapped') variables.amount = '999.00';
      if (corruption === 'removed-static') delete variables.manual_reference;
      if (corruption === 'changed-static') variables.manual_reference = 'Unexpected replacement';
      if (corruption === 'extra-static') variables.unrequested = 'Unexpected addition';
      if (corruption === 'context') f.setContext({ ...f.context(), variables: [{ ...f.context().variables[0], current_value: '999.00' }] });
      return { ...result, document: { ...result.document, variables_json: variables } };
    };
    await f.controller.apply(); expect(f.adopted).toEqual([]); expect(f.controller.state.needsReadback).toBe(true);
    expect(f.controller.sendBlocked()).toBe(true);
  }
  const correct = fixture(); correct.document().variables_json.manual_reference = 'Human reference'; await proposal(correct); correct.controller.confirm('d'.repeat(64), true);
  await correct.controller.apply(); expect(correct.adopted[0].variables_json.manual_reference).toBe('Human reference');
});
test('unknown-write inspection validates saved document and context while explicitly allowing a later legitimate value', async () => {
  for (const corruption of ['time', 'metadata', 'value', 'context'] as const) {
    const f = fixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); f.transport.apply = async () => { throw new TypeError('network lost'); };
    await f.controller.apply();
    const saved: any = { ...f.document(), variables_json: { amount: '987.00' }, updated_at: '2026-10-10T12:04:00Z' };
    f.setContext(crmContextFixture(saved));
    if (corruption === 'time') saved.updated_at = 'invalid';
    if (corruption === 'metadata') saved.metadata = [];
    if (corruption === 'value') saved.variables_json = { amount: 987 };
    if (corruption === 'context') f.setContext({ ...f.context(), variables: [{ ...f.context().variables[0], current_value: '999.00' }] });
    f.transport.document = async () => saved;
    await f.controller.inspectReadback(); f.controller.adoptReadback(); expect(f.adopted).toEqual([]); expect(f.controller.state.needsReadback).toBe(true);
  }
  const f = fixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); f.transport.apply = async () => { throw new TypeError('network lost'); };
  await f.controller.apply(); const saved = { ...f.document(), variables_json: { amount: '987.00' }, updated_at: '2026-10-10T12:04:00Z' };
  f.transport.document = async () => saved; f.setContext(crmContextFixture(saved));
  await f.controller.inspectReadback(); expect(f.adopted).toEqual([]); f.controller.adoptReadback(); expect(f.adopted[0].variables_json.amount).toBe('987.00');
});
test('known stale document refusal recovers through explicit inspection without discarding dirty local inputs', async () => {
  const f = fixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true);
  f.transport.apply = async () => { throw new APIError(409, 'Document changed'); }; await f.controller.apply();
  const saved = { ...f.document(), updated_at: '2026-10-10T12:04:00Z', variables_json: { amount: '987.00' } };
  f.transport.document = async () => saved; f.setContext(crmContextFixture(saved));
  await f.controller.refresh(); expect(f.controller.state.needsReadback).toBe(true); expect(f.controller.state.readbackReason).toBe('stale');
  expect(f.controller.state.error).not.toContain('uncertain'); expect(f.adopted).toEqual([]);
  await f.controller.inspectReadback(); f.setClean(false); f.controller.adoptReadback(); expect(f.adopted).toEqual([]);
  f.setClean(true); f.controller.adoptReadback(); expect(f.adopted[0].updated_at).toBe(saved.updated_at);
  expect(f.controller.state.needsReadback).toBe(false); expect(f.controller.state.notice).not.toContain('interrupted');
});
test('late Apply after interruption neither adopts nor clears the unknown-write fence', async () => {
  const f = fixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); let settle!: (v: unknown) => void;
  f.transport.apply = async () => new Promise((r) => { settle = r; }); const pending = f.controller.apply(); await Promise.resolve();
  f.controller.interrupt(); settle({ ...contextWitness(f.context()), document: f.document(), content_changed: true, mapping_review_required: false }); await pending;
  expect(f.adopted).toEqual([]); expect(f.controller.state.needsReadback).toBe(true); expect(f.controller.state.busy).toBeNull();
});
test('strict DTOs preserve opaque IDs and bigint strings, distinguish present empty, reject null/secret/proof/field corruption', () => {
  expect(checkedCRMContext(crmContextFixture()).connection?.generation).toBe('9007199254740993');
  expect(checkedCRMObservation(crmObservationFixture(undefined, '')).items[0].value).toBe('');
  for (const context of [{ ...crmContextFixture(), token: 'secret' }, { ...crmContextFixture(), connection: { ...crmContextFixture().connection, generation: 9007199254740993 } }]) expect(() => checkedCRMContext(context)).toThrow();
  const o = crmObservationFixture();
  for (const item of [{ ...o.items[0], value: null }, { ...o.items[0], crm_observation: { ...o.items[0].crm_observation, crm_team_id: 'differentTeam' } }, { ...o.items[0], available: false }]) expect(() => checkedCRMObservation({ ...o, items: [item] })).toThrow();
  expect(() => checkedCRMSearch({ ...contextWitness(crmContextFixture()), kind: 'crm.deal', query: 'Deal', offset: 0, choices: [], has_more: true, next_offset: 1001 })).toThrow();
  expect(validCRMSearch('x', 0)).toBe(false); expect(validCRMSearch('Deal', 21)).toBe(false); expect(validCRMSearch('Deal\u0000', 0)).toBe(false); expect(validCRMSearch('', 1000)).toBe(true);
  expect(() => checkedCRMApply({ ...contextWitness(crmContextFixture()), document: { ...crmDocumentFixture(), source_kind: 'pdf' }, content_changed: true, mapping_review_required: false })).toThrow();
});

test('contract design readiness issues are bounded and prevent Apply even when scalar values are available', async () => {
  const issue = { code: 'signing_page_text', path: 'parties.customer.company_name', message: 'The value does not fit the approved signing page.' };
  expect(() => checkedCRMObservation({ ...crmObservationFixture(), contract_issues: [issue] })).toThrow();
  const unavailable = { ...crmObservationFixture(), can_apply: false, contract_issues: [issue] };
  expect(checkedCRMObservation(unavailable).contract_issues).toEqual([issue]);
  expect(() => checkedCRMObservation({ ...unavailable, contract_issues: [{ ...issue, raw_record: 'forbidden' }] })).toThrow();
  const f = fixture(); await proposal(f); f.transport.observe = async () => unavailable; await f.controller.observe();
  f.controller.confirm('d'.repeat(64), true); expect(f.controller.canApply()).toBe(false); await f.controller.apply(); expect(f.adopted).toEqual([]);
});

test('HTML Apply verifies exact new retained source and fresh review; mapping-only Apply retains the old PDF and wording', async () => {
  for (const changed of [false, true]) {
    let doc = { ...crmDocumentFixture(), source_kind: 'pdf' as const, has_html_source: true,
      template_id: '66666666-6666-4666-8666-666666666666', html_source_commitment: '1'.repeat(64), pdf_sha256: '2'.repeat(64), html_materialization_revision: 1, html_review_required: false };
    const before = doc; let context = crmContextFixture(doc); const adopted: DocumentResponse[] = [];
    const value = changed ? '12345678901234567890.012300' : doc.variables_json.amount;
    const source = () => ({ document_id: doc.id, org_id: doc.org_id, template_id: doc.template_id, template_version: 1,
      template_content_sha256: '3'.repeat(64), updated_at: doc.updated_at, html_source_commitment: doc.html_source_commitment,
      pdf_sha256: doc.pdf_sha256, materialization_revision: doc.html_materialization_revision, page_count: 2, can_edit: true,
      values: [{ name: 'amount', required: true, max_chars: 8192, text: doc.variables_json.amount }],
      sections: [{ name: 'scope', max_chars: 32768, text: 'Human reviewed negotiated wording', default_text: 'Approved wording' }], changed_sections: ['scope'] });
    const transport: CRMDocumentTransport = { identity: async () => CRM_ACTOR, context: async () => context, document: async () => doc, source: async () => source(),
      search: async () => { throw new Error('not used'); }, observe: async () => crmObservationFixture(context, value),
      apply: async (_id, input) => {
        doc = { ...doc, updated_at: '2026-10-10T12:03:00Z', variables_json: { amount: value },
          ...(changed ? { html_source_commitment: '4'.repeat(64), pdf_sha256: '5'.repeat(64), html_materialization_revision: 2, html_review_required: true } : {}) };
        context = { ...crmContextFixture(doc), binding_fingerprint: 'e'.repeat(64), bindings: input.mappings.map((m) => ({ ...m, updated_at: doc.updated_at })) };
        return { ...contextWitness(context), document: doc, content_changed: changed, mapping_review_required: false,
          ...(changed ? { materialization_revision: 2, page_count: 2, review_required: true, placement_reset: true } : {}) };
      } };
    const controller = new CRMDocumentController(doc, CRM_ACTOR, transport, () => {}, () => true, (d) => { adopted.push(d); return true; }, () => Date.parse('2026-10-10T12:02:01Z'));
    await controller.refresh(); controller.select({ kind: 'crm.deal', id: CRM_MAPPING.source_ref, label: 'Deal', secondary: '', record_updated_at: '2026-10-10T12:00:00Z' });
    controller.map('amount', { kind: 'crm.deal', path: 'value' }); await controller.observe(); controller.confirm('d'.repeat(64), true); await controller.apply();
    expect(adopted).toHaveLength(1); expect(controller.state.needsReadback).toBe(false); expect(source().sections[0].text).toBe('Human reviewed negotiated wording');
    expect(doc.pdf_sha256 === before.pdf_sha256).toBe(!changed); expect(doc.html_source_commitment === before.html_source_commitment).toBe(!changed);
    expect(doc.html_review_required).toBe(changed);
  }
});
