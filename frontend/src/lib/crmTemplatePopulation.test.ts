import { expect, test } from 'bun:test';
import { APIError, type DocumentResponse, type HTMLDocumentInput, type HTMLDocumentSource, type TemplateResponse } from './api/client';
import { signingPageTemplateFixture } from './htmlTemplateFixtures';
import { signingPageSourceFixture } from './htmlRevision.test';
import { CRMTemplatePopulationController, checkedCreationMarker, checkedCreationOutcome, checkedCreationReadback, checkedCreationResult, checkedTemplateObservation,
  initialCRMTemplateState, readCreationMarker, storeCreationMarker, templateExpected, templateWitnessKey, type CRMTemplateCandidate, type CRMTemplateContext,
  type CRMTemplateObservation, type CRMTemplateTransport, type HTMLCreationMarker } from './crmTemplatePopulation';

export const TP_ACTOR = { org_id: '22222222-2222-4222-8222-222222222222', user_id: '11111111-1111-4111-8111-111111111111', role: 'sender' as const };
export const TP_ID = '33333333-3333-4333-8333-333333333333', TP_REQUEST = '55555555-5555-4555-8555-555555555555';
export function templatePopulationFixture(): TemplateResponse {
  return { id: TP_ID, org_id: TP_ACTOR.org_id, name: 'Approved design', source_kind: 'html', fields_json: [], version: 7,
    created_by: TP_ACTOR.user_id, created_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:00:00Z', content_sha256: 'a'.repeat(64), variables_json: { sticky: 'Approved static information' },
    html_master_json: { schema_version: 1, html: '<p data-hash-value="price"></p>', css: '', values: [
      { name: 'price', required: true, max_chars: 100 }, { name: 'sticky', required: false, max_chars: 200 }, { name: 'optional', required: false, max_chars: 100 }],
      sections: [{ name: 'scope_text', default_text: 'Approved scope.', max_chars: 1000 }] },
    html_approval: { version: 7, content_sha256: 'a'.repeat(64), approved_by: TP_ACTOR.user_id, approved_at: '2026-10-10T12:00:00.000000123Z' } };
}
export function templateContextFixture(t = templatePopulationFixture()): CRMTemplateContext {
  const defaults = t.variables_json as Record<string, string>;
  return { org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: t.id, template_version: t.version, template_content_sha256: t.content_sha256!,
    template_approved_by: t.html_approval!.approved_by!, template_approved_at: t.html_approval!.approved_at!, connection: { id: '44444444-4444-4444-8444-444444444444', generation: '9007199254740993',
      status: 'active', origin: 'https://crm.example.test', crm_team_id: 'team_CUID2', crm_user_id: 'user_CUID2' }, available: true,
    variables: (t.html_master_json!.values ?? []).map(f => ({ ...f, current_present: Object.hasOwn(defaults, f.name), current_value: defaults[f.name] ?? '' })),
    catalog: { 'crm.deal': [{ path: 'value', type: 'decimal', nullable: true, derived: false }, { path: 'description', type: 'string', nullable: true, derived: false }], 'crm.contact': [], 'crm.company': [] } };
}
export const TP_MAPPING = { variable: 'price', source_kind: 'crm.deal' as const, source_ref: 'deal_CUID2', source_path: 'value' };
export function templateObservationFixture(c = templateContextFixture(), candidate: CRMTemplateCandidate = { name: 'New document', values: { price: '', sticky: 'Typed manual information', optional: '' } }, value = '1490.7500'): CRMTemplateObservation {
  return { ...c, available: undefined, variables: undefined, catalog: undefined,
    mappings: [{ ...TP_MAPPING }], items: [{ ...TP_MAPPING, current_present: Object.hasOwn(candidate.values, 'price'), current_value: candidate.values.price ?? '', available: true, value,
      crm_observation: { connection_id: c.connection!.id, generation: c.connection!.generation, origin: c.connection!.origin, crm_team_id: c.connection!.crm_team_id, crm_user_id: c.connection!.crm_user_id,
        record_updated_at: '2026-10-10T12:01:00Z', observed_at: '2026-10-10T12:02:00Z', body_sha256: 'b'.repeat(64), value_sha256: new Bun.CryptoHasher('sha256').update(value).digest('hex') } }],
    review_digest: 'd'.repeat(64), can_create: true, observed_at: '2026-10-10T12:02:00.500Z', expires_at: '2026-10-10T12:02:45.500Z', review_receipt: 'purpose-bound.synthetic.receipt' } as unknown as CRMTemplateObservation;
}
function witness(c: CRMTemplateContext) { const { available, variables, catalog, ...w } = c; return w; }
export function cleanObservation(c = templateContextFixture(), candidate?: CRMTemplateCandidate, value?: string) {
  const o = templateObservationFixture(c, candidate, value) as unknown as Record<string, unknown>;
  delete o.available; delete o.variables; delete o.catalog; return o as unknown as CRMTemplateObservation;
}
export function creationFixture(input: HTMLDocumentInput, effective = input.values) {
  const document: DocumentResponse = { id: '66666666-6666-4666-8666-666666666666', org_id: TP_ACTOR.org_id, sender_id: TP_ACTOR.user_id, template_id: TP_ID, name: input.name,
    status: 'draft', routing_mode: 'parallel', source_kind: 'pdf', has_html_source: true, html_review_required: true, html_source_commitment: 'e'.repeat(64), html_materialization_revision: 1,
    pdf_sha256: 'f'.repeat(64), variables_json: { ...effective }, metadata: {}, default_locale: 'en', created_at: '2026-10-10T12:03:00Z', updated_at: '2026-10-10T12:03:00Z' };
  const creation = { document_id: document.id, html_materialization_id: '77777777-7777-4777-8777-777777777777', html_source_commitment: document.html_source_commitment!,
    pdf_sha256: document.pdf_sha256!, page_count: 2, created_at: document.created_at };
  return { org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, document, creation, request_id: input.request_id!, input_digest: '9'.repeat(64), page_count: 2, review_required: true, replayed: false };
}
export function populationControllerFixture() {
  const template = templatePopulationFixture(); let context = templateContextFixture(template), clock = Date.parse('2026-10-10T12:02:01Z');
  let candidate: CRMTemplateCandidate = { name: 'Typed document name', values: { price: '', sticky: 'Typed manual information', optional: '' }, sections: { scope_text: 'Manual negotiated wording.\nSecond line.' } };
  const calls: { kind: string; input?: any; id?: string }[] = [], opened: DocumentResponse[] = [], markers: (HTMLCreationMarker | null)[] = [];
  let created: ReturnType<typeof creationFixture> | null = null;
  const transport: CRMTemplateTransport = {
    identity: async () => TP_ACTOR, context: async () => context,
    search: async (id, input) => { calls.push({ kind: 'search', id, input }); return { ...witness(context), kind: input.kind, query: input.query, offset: input.offset,
      choices: [{ kind: input.kind, id: 'deal_CUID2', label: 'Synthetic selected deal', secondary: '', record_updated_at: '2026-10-10T12:01:00Z' }], has_more: false, next_offset: 0 }; },
    observe: async (id, input) => { calls.push({ kind: 'observe', id, input }); return input.mappings.length ? cleanObservation(context, input.candidate) : {
      ...witness(context), mappings: [], items: [], review_digest: 'd'.repeat(64), can_create: true, observed_at: '2026-10-10T12:02:00.500Z', expires_at: '2026-10-10T12:02:45.500Z', review_receipt: 'purpose-bound.synthetic.receipt' }; },
    create: async (id, input) => { calls.push({ kind: 'create', id, input }); created = creationFixture(input, { ...input.values, ...(input.crm_population ? { price: '1490.7500' } : {}) }); return created; },
    source: async () => { const d = created!.document; return { document_id: d.id, org_id: d.org_id, updated_at: d.updated_at, html_source_commitment: d.html_source_commitment!, materialization_revision: 1,
      pdf_sha256: d.pdf_sha256!, page_count: 2, template_id: TP_ID, template_version: template.version, template_content_sha256: template.content_sha256!,
      values: template.html_master_json!.values!.map(v => ({ ...v, text: d.variables_json[v.name] })), sections: [{ name: 'scope_text', max_chars: 1000, default_text: 'Approved scope.', text: candidate.sections!.scope_text }],
      changed_sections: ['scope_text'], can_edit: true, source_schema_version: 1 } satisfies HTMLDocumentSource; },
    readback: async () => { if (!created) throw new APIError(404, 'Unconfirmed'); return { state: 'committed', org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, request_id: created.request_id, input_digest: created.input_digest, template_id: TP_ID, document: created.document, creation: created.creation }; },
    stop: async (marker) => { calls.push({ kind: 'stop', id: marker.template_id, input: structuredClone(marker) }); return created ? { state: 'committed', org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, request_id: created.request_id, input_digest: created.input_digest, template_id: TP_ID, document: created.document, creation: created.creation } : closedCreationFixture(marker); },
  };
  const controller = new CRMTemplatePopulationController(template, transport, () => candidate, () => {}, m => markers.push(m), d => { opened.push(d); }, null, () => clock, () => TP_REQUEST);
  return { template, controller, transport, calls, opened, markers, candidate: () => candidate, setCandidate: (c: CRMTemplateCandidate) => { candidate = c; }, context: () => context, setContext: (c: CRMTemplateContext) => { context = c; }, setClock: (c: number) => { clock = c; }, setCreated: (c: ReturnType<typeof creationFixture>) => { created = c; } };
}
export function closedCreationFixture(marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST }) {
  return { state: 'closed' as const, org_id: marker.org_id, user_id: marker.user_id, template_id: marker.template_id, request_id: marker.request_id, closed_at: '2026-10-10T12:03:01.123456789Z' };
}
async function proposal(f: ReturnType<typeof populationControllerFixture>) {
  await f.controller.load(); await f.controller.search('crm.deal', ''); f.controller.select(f.controller.state.search!.choices[0]); f.controller.map('price', { kind: 'crm.deal', path: 'value' }); await f.controller.observe();
}
async function reached(predicate: () => boolean) { for (let i = 0; i < 20 && !predicate(); i++) await Promise.resolve(); expect(predicate()).toBe(true); }
test('initial observation is template scoped, preserves raw manual values and allows verified mapped required fields only after confirmation', async () => {
  const f = populationControllerFixture(), raw = structuredClone(f.candidate()); await proposal(f);
  expect(f.controller.state.observation?.items[0].value).toBe('1490.7500'); expect(f.candidate()).toEqual(raw);
  expect(f.controller.effectiveValues()).toEqual({ ...raw.values, price: '1490.7500' }); expect(f.controller.canCreate()).toBe(false);
  f.controller.confirm('0'.repeat(64), true); expect(f.controller.canCreate()).toBe(false);
  f.controller.confirm('d'.repeat(64), true); expect(f.controller.canCreate()).toBe(true); await f.controller.create();
  const input = f.calls.find(c => c.kind === 'create')!.input;
  expect(input).toMatchObject({ ...raw, request_id: TP_REQUEST, expected_org_id: TP_ACTOR.org_id, expected_user_id: TP_ACTOR.user_id, expected_template_version: 7,
    crm_population: { ...templateExpected(f.context()), mappings: [TP_MAPPING], confirmed: true, reviewed_digest: 'd'.repeat(64) } });
  expect(input.values.price).toBe(''); expect(f.opened[0].variables_json).toEqual({ ...raw.values, price: '1490.7500' }); expect(f.markers.at(-1)).toBeNull(); expect(f.candidate()).toEqual(raw);
});
test('manual population survives unconfigured CRM, captures actor and request identity, and missing manual required fields block creation', async () => {
  const f = populationControllerFixture(); f.setContext({ ...f.context(), connection: null, available: false }); await f.controller.load(); expect(f.controller.canCreate()).toBe(false);
  f.setCandidate({ ...f.candidate(), values: { ...f.candidate().values, price: '1290.2500' } }); f.controller.inputChanged(); expect(f.controller.canCreate()).toBe(true); await f.controller.create();
  expect(f.calls.find(c => c.kind === 'create')?.input).toMatchObject({ request_id: TP_REQUEST, expected_org_id: TP_ACTOR.org_id, expected_user_id: TP_ACTOR.user_id });
  expect(f.calls.find(c => c.kind === 'create')?.input.crm_population).toBeUndefined(); expect(f.opened).toHaveLength(1);
});
test('candidate edits and reverts, expiry, mapping changes and approval/account drift cannot revive confirmation', async () => {
  const f = populationControllerFixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true);
  const original = structuredClone(f.candidate()); f.setCandidate({ ...original, name: 'Other name' }); f.controller.inputChanged(); f.setCandidate(original); f.controller.inputChanged(); expect(f.controller.canCreate()).toBe(false);
  await f.controller.observe(); f.controller.confirm('d'.repeat(64), true); f.setClock(Date.parse('2026-10-10T12:02:45.500Z')); f.controller.expire(); expect(f.controller.canCreate()).toBe(false);
  f.setClock(Date.parse('2026-10-10T12:02:01Z')); await f.controller.observe(); f.controller.confirm('d'.repeat(64), true); f.controller.map('price'); expect(f.controller.state.confirmation).toBe(''); expect(f.candidate()).toEqual(original);
  f.setContext({ ...f.context(), template_approved_at: '2026-10-10T12:00:01Z' }); await f.controller.load(); expect(f.controller.state.context).toBeNull();
  f.setContext({ ...templateContextFixture(), connection: { ...templateContextFixture().connection!, generation: '9007199254740994' } }); await f.controller.load();
  expect(f.controller.state.mappings).toEqual([]); expect(f.controller.state.confirmation).toBe('');
});
test('late observation after text edit or navigation cannot adopt an old candidate, clear new errors or confirmation', async () => {
  const f = populationControllerFixture(); await proposal(f); let settle!: (v: unknown) => void;
  f.transport.observe = async () => new Promise(r => { settle = r; }); const pending = f.controller.observe(); await reached(() => !!settle);
  f.setCandidate({ ...f.candidate(), values: { ...f.candidate().values, sticky: 'New manual wording' } }); f.controller.inputChanged();
  settle(cleanObservation(f.context(), { ...f.candidate(), values: { ...f.candidate().values, sticky: 'Old wording' } })); await pending;
  expect(f.controller.state.observation).toBeNull(); expect(f.controller.state.busy).toBeNull(); expect(f.candidate().values.sticky).toBe('New manual wording');
  settle = undefined as any; const late = f.controller.observe(); await reached(() => !!settle); f.controller.dispose(); settle(cleanObservation(f.context(), f.candidate())); await late; expect(f.opened).toEqual([]);
});
test('exact witnesses refuse foreign response and A-B-A switched identity; mapping and account JSON member order is semantic', async () => {
  const f = populationControllerFixture(); await f.controller.load(); const old = f.transport.search;
  f.transport.search = async (id, input, signal) => ({ ...await old(id, input, signal) as object, user_id: '88888888-8888-4888-8888-888888888888' }); await f.controller.search('crm.deal', ''); expect(f.controller.state.search).toBeNull();
  f.transport.search = old; await f.controller.search('crm.deal', ''); f.controller.select(f.controller.state.search!.choices[0]); f.controller.map('price', { kind: 'crm.deal', path: 'value' });
  f.transport.observe = async () => { const o = cleanObservation(f.context(), f.candidate()); return { ...o, mappings: [{ source_path: 'value', source_ref: 'deal_CUID2', source_kind: 'crm.deal', variable: 'price' }], connection: { crm_user_id: o.connection!.crm_user_id, crm_team_id: o.connection!.crm_team_id, origin: o.connection!.origin, status: o.connection!.status, generation: o.connection!.generation, id: o.connection!.id } }; };
  await f.controller.observe(); expect(f.controller.state.observation).not.toBeNull(); expect(templateWitnessKey(f.controller.state.observation!)).toBe(templateWitnessKey(f.context()));
  f.controller.confirm('d'.repeat(64), true); f.transport.identity = async () => ({ ...TP_ACTOR, user_id: '88888888-8888-4888-8888-888888888888' }); await f.controller.create();
  expect(f.calls.filter(c => c.kind === 'create')).toEqual([]); expect(f.controller.state.pending?.request_id).toBe(TP_REQUEST); f.transport.identity = async () => TP_ACTOR; await f.controller.inspect(); expect(f.controller.state.pending).not.toBeNull();
});
test('optional empty is an available present value; missing/null/required-empty never becomes a fallback', () => {
  const absent = { name: 'Document', values: {} }; const o = cleanObservation(templateContextFixture(), absent, ''); o.mappings[0].variable = 'optional'; o.items[0].variable = 'optional';
  expect(TP_MAPPING.variable).toBe('price'); expect(cleanObservation().mappings[0].variable).toBe('price');
  expect(checkedTemplateObservation(o).items[0]).toMatchObject({ current_present: false, current_value: '', available: true, value: '' });
  for (const value of [null, undefined, 0]) { const bad = structuredClone(o) as any; if (value === undefined) delete bad.items[0].value; else bad.items[0].value = value; expect(() => checkedTemplateObservation(bad)).toThrow(); }
  const unavailable = structuredClone(o) as any; unavailable.can_create = false; delete unavailable.review_receipt; delete unavailable.items[0].value; delete unavailable.items[0].crm_observation; unavailable.items[0].available = false; unavailable.items[0].unavailable_reason = 'field_unavailable';
  expect(checkedTemplateObservation(unavailable).items[0].value).toBeUndefined(); unavailable.items[0].current_value = 'fabricated'; expect(() => checkedTemplateObservation(unavailable)).toThrow();
});
test('lost creation response keeps one UUID and raw input; reload404 stays blocked then committed current document is explicitly opened', async () => {
  const f = populationControllerFixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); const actual = f.transport.create;
  f.transport.create = async (...args) => { await actual(...args); throw new TypeError('Lost response'); }; await f.controller.create();
  expect(f.opened).toEqual([]); expect(f.controller.state.pending?.request_id).toBe(TP_REQUEST); await f.controller.create(); expect(f.calls.filter(c => c.kind === 'create')).toHaveLength(1);
  const marker = structuredClone(f.controller.state.pending!); let persisted = marker as HTMLCreationMarker | null, opened: DocumentResponse | null = null;
  const restored = new CRMTemplatePopulationController(null, f.transport, () => { throw new Error('No candidate after reload'); }, () => {}, m => { persisted = m; }, d => { opened = d; }, marker);
  const read = f.transport.readback; f.transport.readback = async () => { throw new APIError(404, 'Unconfirmed'); }; await restored.inspect(); expect(restored.state.pending).toEqual(marker); expect(restored.canRetry()).toBe(false); expect(restored.canCreate()).toBe(false);
  f.transport.readback = read; await restored.inspect(); expect(opened).toBeNull(); expect(restored.state.readback?.state === 'committed' && restored.state.readback.document?.variables_json.sticky).toBe('Typed manual information'); await restored.adoptReadback(); expect(opened).not.toBeNull(); expect(persisted).toBeNull();
});
test('explicit retry uses the same frozen command despite interrupted observation and edited candidate; a replay is not automatically adopted', async () => {
  const f = populationControllerFixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); const actual = f.transport.create;
  f.transport.create = async (...args) => { await actual(...args); throw new TypeError('Lost response'); }; await f.controller.create(); const first = structuredClone(f.calls.find(c => c.kind === 'create')!.input);
  f.controller.invalidate(); f.setCandidate({ ...f.candidate(), name: 'Changed after failure' }); f.transport.create = async (id, input) => { f.calls.push({ kind: 'retry', id, input }); const r = creationFixture(input, { ...input.values, price: '1490.7500' }); return { ...r, replayed: true }; };
  await f.controller.retry(); expect(f.calls.find(c => c.kind === 'retry')!.input).toEqual(first); expect(f.opened).toEqual([]); expect(f.controller.state.readback).not.toBeNull();
});
test('creation output name/value/section/source/schema drift is refused and cannot clear the pending marker', async () => {
  for (const mode of ['name', 'value', 'section', 'source', 'schema']) {
    const f = populationControllerFixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true);
    const create = f.transport.create, source = f.transport.source;
    if (mode === 'value' || mode === 'name') f.transport.create = async (...args) => { const r = await create(...args) as ReturnType<typeof creationFixture>; return { ...r, document: { ...r.document, ...(mode === 'name' ? { name: 'Replaced document name' } : { variables_json: { ...r.document.variables_json, sticky: 'Replaced manual data' } }) } }; };
    else f.transport.source = async (...args) => { const s = await source(...args); return mode === 'section' ? { ...s, sections: s.sections.map(v => ({ ...v, text: 'Replaced prose' })) } : mode === 'schema' ? { ...s, source_schema_version: undefined } : { ...s, html_source_commitment: '0'.repeat(64) }; };
    await f.controller.create(); expect(f.opened).toEqual([]); expect(f.controller.state.pending).not.toBeNull(); expect(f.controller.state.error).toBeTruthy();
  }
});
test('readback separates immutable original pins from later current review/layout and preserves tombstone identity', async () => {
  const f = populationControllerFixture(), c = { ...f.candidate(), values: { ...f.candidate().values, price: '1290.2500' } }; f.setCandidate(c); await f.controller.load();
  const input = { ...c, request_id: TP_REQUEST, expected_template_version: 7, expected_template_content_sha256: 'a'.repeat(64) }, created = creationFixture(input);
  const marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST };
  const current = { ...created.document, status: 'completed', variables_json: { price: 'Later value' }, html_source_commitment: '8'.repeat(64), pdf_sha256: '7'.repeat(64), html_materialization_revision: 3 }; delete current.html_review_required;
  const response = { state: 'committed', org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, request_id: TP_REQUEST, input_digest: '9'.repeat(64), template_id: TP_ID, document: current, creation: created.creation };
  expect(checkedCreationReadback(response, marker).document?.html_materialization_revision).toBe(3); expect(checkedCreationResult({ ...created, document: current, replayed: true, review_required: false }, marker).page_count).toBe(2);
  let cleared = false; const controller = new CRMTemplatePopulationController(null, { ...f.transport, readback: async () => ({ ...response, document: null }) }, () => c, () => {}, m => { cleared = m === null; }, () => {}, marker);
  await controller.inspect(); expect(cleared).toBe(false); controller.acknowledgeDeleted(); expect(cleared).toBe(true); expect(controller.state.pending).toBeNull();
  for (const bad of [{ ...response, request_id: '88888888-8888-4888-8888-888888888888' }, { ...response, user_id: '88888888-8888-4888-8888-888888888888', document: null }, { ...response, document: { ...current, org_id: '88888888-8888-4888-8888-888888888888' } }, { ...response, document: { ...current, html_review_required: null } }]) expect(() => checkedCreationReadback(bad, marker)).toThrow();
});
test('metadata marker is bounded, exact, contains no candidate or receipt, and rejects corrupt or foreign extra state', () => {
  const data = new Map<string, string>(), storage = { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => { data.set(k, v); }, removeItem: (k: string) => { data.delete(k); } };
  const marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST }; storeCreationMarker(storage, marker); expect(readCreationMarker(storage)).toEqual(marker);
  expect([...data.values()][0]).not.toContain('Typed'); expect(() => checkedCreationMarker({ ...marker, review_receipt: 'secret' })).toThrow(); expect(() => checkedCreationMarker({ ...marker, values: {} })).toThrow();
  storeCreationMarker(storage, null); expect(readCreationMarker(storage)).toBeNull(); expect(initialCRMTemplateState().pending).toBeNull();
});

test('fresh source3 creation must retain the approved profile and signing policy; legacy-shaped downgrade and changed policy are refused', async () => {
  for (const mode of ['valid', 'downgrade', 'policy']) {
    const t = { ...signingPageTemplateFixture(), id: TP_ID, org_id: TP_ACTOR.org_id, created_by: TP_ACTOR.user_id,
      html_approval: { version: 3, content_sha256: 'a'.repeat(64), approved_by: TP_ACTOR.user_id, approved_at: '2026-10-10T12:00:00Z' } };
    const candidate: CRMTemplateCandidate = { name: 'New signing-page document', values: { ...t.variables_json as Record<string, string> }, sections: { scope_text: 'Reviewed service scope.' } };
    let source = signingPageSourceFixture(), result!: ReturnType<typeof creationFixture>; const opened: DocumentResponse[] = [];
    const transport: CRMTemplateTransport = { identity: async () => TP_ACTOR, context: async () => templateContextFixture(t), search: async () => { throw new Error('No CRM search'); }, observe: async () => { throw new Error('No CRM observation'); }, readback: async () => { throw new Error('No recovery'); }, stop: async () => { throw new Error('No pending stop'); },
      create: async (_id, input) => { result = creationFixture(input); result.document.pdf_sha256 = source.pdf_sha256; result.document.html_source_commitment = source.html_source_commitment; result.creation.pdf_sha256 = source.pdf_sha256; result.creation.html_source_commitment = source.html_source_commitment; return result; },
      source: async () => { source = { ...source, document_id: result.document.id, org_id: TP_ACTOR.org_id, updated_at: result.document.updated_at, template_id: TP_ID, template_version: t.version, template_content_sha256: t.content_sha256! };
        if (mode === 'downgrade') { delete source.source_schema_version; delete source.contract_profile; delete source.contract_profile_digest; delete source.contract_parties; delete source.signing_page; delete source.signing_artifact; }
        if (mode === 'policy') source.signing_page!.branding.text_hex = '#101010'; return source; } };
    const c = new CRMTemplatePopulationController(t, transport, () => candidate, () => {}, () => {}, d => { opened.push(d); }, null, () => Date.parse('2026-10-10T12:02:01Z'), () => TP_REQUEST);
    await c.load(); expect(c.canCreate()).toBe(true); await c.create(); expect(opened).toHaveLength(mode === 'valid' ? 1 : 0); if (mode !== 'valid') expect(c.state.pending).not.toBeNull();
  }
});
test('double creation and failed navigation retain the known created draft; opening retries navigation without another POST', async () => {
  const f = populationControllerFixture(); f.setCandidate({ ...f.candidate(), values: { ...f.candidate().values, price: '1290.2500' } }); let fail = true, marker: HTMLCreationMarker | null = null;
  const opened: DocumentResponse[] = [], c = new CRMTemplatePopulationController(f.template, f.transport, f.candidate, () => {}, m => { marker = m; }, d => { if (fail) throw new Error('Navigation unavailable'); opened.push(d); }, null, () => Date.parse('2026-10-10T12:02:01Z'), () => TP_REQUEST);
  await c.load(); const first = c.create(); await c.create(); await first;
  expect(f.calls.filter(c => c.kind === 'create')).toHaveLength(1); expect(c.state.created).not.toBeNull(); expect(marker).not.toBeNull(); expect(opened).toEqual([]);
  fail = false; await c.openCreated(); expect(opened).toHaveLength(1); expect(marker).toBeNull(); expect(f.calls.filter(c => c.kind === 'create')).toHaveLength(1);
});

test('a switched-cookie recovery response cannot adopt a foreign actor tombstone even if /me returns to the original actor', async () => {
  const f = populationControllerFixture(), marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST };
  const result = creationFixture({ ...f.candidate(), expected_template_version: 7, expected_template_content_sha256: 'a'.repeat(64), request_id: TP_REQUEST }); let clears = 0;
  const c = new CRMTemplatePopulationController(null, { ...f.transport, readback: async () => ({ state: 'committed', org_id: TP_ACTOR.org_id, user_id: '88888888-8888-4888-8888-888888888888', request_id: TP_REQUEST, input_digest: result.input_digest, template_id: TP_ID, creation: result.creation, document: null }) }, f.candidate, () => {}, m => { if (!m) clears++; }, () => {}, marker);
  await c.inspect(); expect(c.state.readback).toBeNull(); expect(c.state.pending).toEqual(marker); c.acknowledgeDeleted(); expect(clears).toBe(0);
});

test('approved static schema1 designs with no values or sections still create a verified manual draft', async () => {
  const f = populationControllerFixture(); f.template.html_master_json = { schema_version: 1, html: '<h1>Approved static document</h1>', css: '' }; f.template.variables_json = {};
  f.setCandidate({ name: 'Static manual document', values: {} }); f.setContext({ ...templateContextFixture(f.template), connection: null, available: false });
  f.transport.source = async () => ({ document_id: '66666666-6666-4666-8666-666666666666', org_id: TP_ACTOR.org_id, updated_at: '2026-10-10T12:03:00Z', html_source_commitment: 'e'.repeat(64), materialization_revision: 1,
    pdf_sha256: 'f'.repeat(64), page_count: 2, template_id: TP_ID, template_version: 7, template_content_sha256: 'a'.repeat(64), values: [], sections: [], changed_sections: [], can_edit: true, source_schema_version: 1 });
  await f.controller.load(); expect(f.controller.canCreate()).toBe(true); await f.controller.create(); expect(f.opened).toHaveLength(1); expect(f.opened[0].variables_json).toEqual({}); expect(f.controller.state.pending).toBeNull();
});

test('lost Stop response and reload404 keep the original nonce until exact closed readback is explicitly acknowledged', async () => {
  const f = populationControllerFixture(), raw = structuredClone(f.candidate()); await proposal(f); f.controller.confirm('d'.repeat(64), true);
  f.transport.create = async () => { throw new APIError(409, 'Changed observation'); }; await f.controller.create(); const marker = structuredClone(f.controller.state.pending!);
  await f.controller.stop(false); expect(f.calls.filter(c => c.kind === 'stop')).toEqual([]);
  const stop = f.transport.stop; f.transport.stop = async (...args) => { await stop(...args); throw new TypeError('Lost close response'); };
  await f.controller.stop(true); expect(f.controller.state.pending).toEqual(marker); expect(f.controller.state.readback).toBeNull(); expect(f.controller.canRetry()).toBe(false); expect(f.candidate()).toEqual(raw);
  let stored: HTMLCreationMarker | null = marker;
  const restored = new CRMTemplatePopulationController(null, f.transport, () => { throw new Error('No restored prose'); }, () => {}, m => { stored = m; }, () => { throw new Error('No document should open'); }, marker);
  await restored.inspect(); expect(restored.state.pending).toEqual(marker); expect(restored.canCreate()).toBe(false);
  restored.acknowledgeClosed(); expect(stored).toEqual(marker);
  f.transport.readback = async () => closedCreationFixture(marker); await restored.inspect(); expect(restored.state.readback?.state).toBe('closed'); expect(stored).toEqual(marker);
  restored.acknowledgeDeleted(); expect(stored).toEqual(marker); await restored.adoptReadback(); expect(stored).toEqual(marker);
  restored.acknowledgeClosed(); expect(stored).toBeNull(); expect(restored.state.requires_refresh).toBe(true); expect(f.candidate()).toEqual(raw);
});

test('stopping an in-flight create aborts its reads and late201 cannot adopt or clear the terminal pending result', async () => {
  const f = populationControllerFixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true);
  let settle!: (v: unknown) => void, originalSignal!: AbortSignal, originalInput!: HTMLDocumentInput;
  f.transport.create = async (_id, input, signal) => { originalInput = input; originalSignal = signal; return new Promise(r => { settle = r; }); };
  const create = f.controller.create(); await reached(() => !!settle); expect(f.controller.canStop()).toBe(true);
  await f.controller.stop(true); expect(originalSignal.aborted).toBe(true); expect(f.controller.state.readback?.state).toBe('closed');
  settle(creationFixture(originalInput, { ...originalInput.values, price: '1490.7500' })); await create;
  expect(f.opened).toEqual([]); expect(f.controller.state.created).toBeNull(); expect(f.controller.state.readback?.state).toBe('closed'); expect(f.controller.state.pending?.request_id).toBe(TP_REQUEST);
});

test('Stop returning an already committed document requires Open; known committed digest contradicts every closed outcome', async () => {
  const f = populationControllerFixture(); await proposal(f); f.controller.confirm('d'.repeat(64), true); const create = f.transport.create;
  f.transport.create = async (...args) => { await create(...args); throw new TypeError('Lost201'); }; await f.controller.create();
  await f.controller.stop(true); expect(f.controller.state.readback?.state).toBe('committed'); expect(f.controller.state.pending?.input_digest).toBe('9'.repeat(64));
  f.controller.acknowledgeClosed(); expect(f.controller.state.pending).not.toBeNull(); expect(f.opened).toEqual([]);
  const known = structuredClone(f.controller.state.pending!); expect(() => checkedCreationOutcome(closedCreationFixture(known), known)).toThrow();
  const readback = f.transport.readback; f.transport.readback = async () => closedCreationFixture(known); await f.controller.inspect(); expect(f.controller.state.readback).toBeNull(); f.controller.acknowledgeClosed(); expect(f.controller.state.pending).toEqual(known);
  // A close response can never be used as permission to forget a known committed digest.
  expect(f.controller.canCreate()).toBe(false);
  f.transport.readback = readback; await f.controller.inspect(); expect(f.opened).toEqual([]); await f.controller.adoptReadback(); expect(f.opened).toHaveLength(1); expect(f.controller.state.pending).toBeNull();
});

test('closed outcome rejects wrong actors, requests, templates, malformed time and extra keys without permitting acknowledgement', async () => {
  const marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST }, closed = closedCreationFixture(marker);
  for (const bad of [{ ...closed, user_id: '88888888-8888-4888-8888-888888888888' }, { ...closed, org_id: '88888888-8888-4888-8888-888888888888' }, { ...closed, template_id: '88888888-8888-4888-8888-888888888888' }, { ...closed, request_id: '88888888-8888-4888-8888-888888888888' }, { ...closed, closed_at: null }, { ...closed, closed_at: '2026-10-10T12:03:01+01:00' }, { ...closed, input_digest: '9'.repeat(64) }]) expect(() => checkedCreationOutcome(bad, marker)).toThrow();
  const f = populationControllerFixture(); f.controller.restorePending(marker); f.transport.stop = async () => ({ ...closed, user_id: '88888888-8888-4888-8888-888888888888' });
  await f.controller.stop(true); expect(f.controller.state.readback).toBeNull(); expect(f.controller.state.pending).toEqual(marker); f.controller.acknowledgeClosed(); expect(f.controller.state.pending).toEqual(marker);
});

test('acknowledged closure preserves resident manual inputs and requires design refresh and an explicit new create before a fresh nonce', async () => {
  const f = populationControllerFixture(); f.setCandidate({ ...f.candidate(), values: { ...f.candidate().values, price: '1290.2500' } }); const raw = structuredClone(f.candidate());
  let nonceCalls = 0, rejectFirst = true; const create = f.transport.create;
  f.transport.create = async (id, input, signal) => { if (rejectFirst) { rejectFirst = false; f.calls.push({ kind: 'create', id, input }); throw new APIError(409, 'Changed pins'); } return create(id, input, signal); };
  const c = new CRMTemplatePopulationController(f.template, f.transport, f.candidate, () => {}, m => f.markers.push(m), d => { f.opened.push(d); }, null, () => Date.parse('2026-10-10T12:02:01Z'), () => { nonceCalls++; return nonceCalls === 1 ? TP_REQUEST : '99999999-9999-4999-8999-999999999999'; });
  await c.load(); await c.create(); await c.stop(true); expect(c.state.pending?.request_id).toBe(TP_REQUEST); c.acknowledgeClosed();
  expect(f.candidate()).toEqual(raw); expect(c.state.requires_refresh).toBe(true); expect(c.canCreate()).toBe(false); await c.load(); await c.create(); expect(nonceCalls).toBe(1);
  c.setTemplate(structuredClone(f.template)); await c.load(); expect(c.canCreate()).toBe(true); expect(nonceCalls).toBe(1); await c.create();
  expect(nonceCalls).toBe(2); expect(f.calls.filter(v => v.kind === 'create').map(v => v.input.request_id)).toEqual([TP_REQUEST, '99999999-9999-4999-8999-999999999999']); expect(f.opened).toHaveLength(1); expect(f.candidate()).toEqual(raw);
});
