import { expect, test } from 'bun:test';
import { advanceCleanHTMLObservation, currentHTMLSource, htmlPlacementPins, htmlRevisionGroups, htmlRevisionInput, revisionDraft, validateHTMLHistory, validateHTMLSource, verifiedHTMLGeneratedFields, verifiedHTMLRevision } from './htmlRevision';
import type { DocumentField, DocumentResponse, HTMLDocumentSource, Recipient } from './api/client';
import { blankHTMLSigningPage } from './htmlAuthor';
import { contractTemplateFixture } from './htmlTemplate.test';

export const documentID = '10000000-0000-4000-8000-000000000001', orgID = '20000000-0000-4000-8000-000000000002';
export const senderID = '30000000-0000-4000-8000-000000000003', templateID = '40000000-0000-4000-8000-000000000004';
export function sourceFixture(): HTMLDocumentSource {
  return { document_id: documentID, org_id: orgID, updated_at: '2026-10-10T05:00:00.000000123Z', html_source_commitment: 'a'.repeat(64),
    materialization_revision: 1, pdf_sha256: 'b'.repeat(64), page_count: 2, template_id: templateID, template_version: 4,
    template_content_sha256: 'c'.repeat(64), values: [{ name: 'company', required: true, max_chars: 64, text: 'Original <AB> & Co' }],
    sections: [{ name: 'scope', max_chars: 128, text: 'Approved scope', default_text: 'Approved scope' }], changed_sections: [], can_edit: true };
}
export function contractSourceFixture(): HTMLDocumentSource {
  const template = contractTemplateFixture(), master = template.html_master_json!, values = template.variables_json as Record<string, string>, profile = master.contract_profile!;
  return { ...sourceFixture(), contract_profile: profile, contract_profile_digest: 'f'.repeat(64),
    values: master.values!.map((field) => ({ ...field, text: values[field.name] })),
    sections: master.sections!.map((section) => ({ ...section, text: section.default_text })),
    contract_parties: profile.parties.map((party, index) => ({ slot: party.slot, role: party.slot, recipient_id: `${index + 5}0000000-0000-4000-8000-00000000000${index + 5}`,
      name: values[party.representative_name], email: values[party.representative_email], company_name: values[party.company_name],
      company_id: values[party.company_id], representative_authority: values[party.representative_authority] })) };
}
export function signingPageSourceFixture(): HTMLDocumentSource {
  const source = contractSourceFixture();
  source.source_schema_version = 3; source.signing_page = blankHTMLSigningPage();
  source.signing_artifact = { version: 1, policy: 'hash-branded-signing-page-a4-v1', plan_sha256: '7'.repeat(64), composition: {
    schema_version: 1, policy: 'hash-pdf-signing-page-a4-v1', body_sha256: '8'.repeat(64), signing_page_sha256: '9'.repeat(64),
    merged_sha256: 'd'.repeat(64), merged_bytes: 1000, output_sha256: source.pdf_sha256, body_pages: 1, final_pages: source.page_count,
    body_geometry_sha256: 'e'.repeat(64), geometry_sha256: 'f'.repeat(64),
    signing_page: { boxes_milli_points: Array.from({ length: 5 }, () => [0, 0, 594960, 841920]), rotation: 0, user_unit_milli: 1000 },
  }, fields: [
    { slot: 'customer', page: source.page_count, x: 100000, y: 420000, w: 800000, h: 70000 },
    { slot: 'provider', page: source.page_count, x: 100000, y: 790000, w: 800000, h: 70000 },
  ] };
  return source;
}
export function generatedAssignmentFixture(source = signingPageSourceFixture()) {
  const recipients = source.contract_parties!.map((party, index) => ({ id: party.recipient_id, document_id: source.document_id,
    role: party.role, name: party.name, email: party.email, order_index: index, locale: 'en', status: 'pending', created_at: source.updated_at })) as Recipient[];
  const fields = source.signing_artifact!.fields.map((slot, index) => ({ id: `${index + 7}0000000-0000-4000-8000-00000000000${index + 7}`,
    document_id: source.document_id, recipient_id: source.contract_parties!.find((party) => party.slot === slot.slot)!.recipient_id,
    type: 'signature', required: true, page: slot.page, x_pct: slot.x / 10000, y_pct: slot.y / 10000, w_pct: slot.w / 10000, h_pct: slot.h / 10000 })) as DocumentField[];
  return { source, recipients, fields };
}

test('source3 keeps the exact automatic page while legacy descriptors cannot infer or downgrade page policy', () => {
  const source = signingPageSourceFixture();
  expect(validateHTMLSource(source, documentID, orgID)).toBe(source);
  for (const original of [sourceFixture(), contractSourceFixture()]) {
    const before = JSON.stringify(original);
    expect(validateHTMLSource(original, documentID, orgID)).toBe(original);
    expect(JSON.stringify(original)).toBe(before);
  }
  const changes: ((source: HTMLDocumentSource) => void)[] = [
    (source) => { delete source.source_schema_version; }, (source) => { source.source_schema_version = 2; },
    (source) => { delete source.signing_page; }, (source) => { delete source.signing_artifact; },
    (source) => { source.signing_artifact!.composition.output_sha256 = 'a'.repeat(64); },
    (source) => { source.signing_artifact!.composition.final_pages++; },
    (source) => { source.signing_artifact!.composition.body_pages = 0; },
    (source) => { source.signing_artifact!.composition.signing_page.boxes_milli_points[1][2]++; },
    (source) => { source.signing_artifact!.composition.signing_page.rotation = 90; },
    (source) => { source.signing_artifact!.composition.signing_page.user_unit_milli = 2000; },
    (source) => { source.signing_artifact!.fields.reverse(); },
    (source) => { source.signing_artifact!.fields[0].y++; },
    (source) => { (source.signing_artifact!.composition as any).unapproved = true; },
    (source) => { delete (source.signing_artifact!.composition as any).geometry_sha256; },
  ];
  for (const change of changes) { const altered = structuredClone(source); change(altered); expect(() => validateHTMLSource(altered, documentID, orgID)).toThrow(); }
});

test('automatic generated field readback verifies both exact parties, complete cardinality and every pinned rectangle', () => {
  const fixture = generatedAssignmentFixture();
  expect(verifiedHTMLGeneratedFields(fixture.source, fixture.fields, fixture.recipients)).toBe(fixture.fields);
  const changes: ((fixture: ReturnType<typeof generatedAssignmentFixture>) => void)[] = [
    (fixture) => { fixture.fields.pop(); }, (fixture) => { fixture.fields.push({ ...fixture.fields[0] }); },
    (fixture) => { fixture.fields[0].id = fixture.fields[1].id; },
    (fixture) => { fixture.fields[0].recipient_id = fixture.fields[1].recipient_id; },
    (fixture) => { fixture.fields[0].type = 'text'; }, (fixture) => { fixture.fields[0].required = false; },
    (fixture) => { fixture.fields[0].page--; }, (fixture) => { fixture.fields[0].x_pct += 0.0001; },
    (fixture) => { fixture.fields[0].w_pct = 79.9999; },
    (fixture) => { fixture.fields[0].document_id = orgID; }, (fixture) => { fixture.fields[0].h_pct = Number.NaN; },
    (fixture) => { fixture.recipients.pop(); }, (fixture) => { fixture.recipients[0].name = 'Different representative'; },
    (fixture) => { fixture.recipients[0].email = fixture.recipients[0].email.toUpperCase(); },
    (fixture) => { fixture.recipients[0].role = 'signer'; },
  ];
  for (const change of changes) { const altered = generatedAssignmentFixture(); change(altered); expect(() => verifiedHTMLGeneratedFields(altered.source, altered.fields, altered.recipients)).toThrow(); }
});

test('new body page count regenerates final-page fields while old source and party assertions remain read-only exact', () => {
  const old = generatedAssignmentFixture(), next = generatedAssignmentFixture(structuredClone(old.source));
  next.source.materialization_revision++; next.source.html_source_commitment = '4'.repeat(64); next.source.pdf_sha256 = '5'.repeat(64);
  next.source.page_count = 4; next.source.signing_artifact!.composition.body_pages = 3; next.source.signing_artifact!.composition.final_pages = 4;
  next.source.signing_artifact!.composition.output_sha256 = next.source.pdf_sha256;
  next.source.signing_artifact!.fields.forEach((field) => field.page = 4);
  expect(() => verifiedHTMLGeneratedFields(next.source, old.fields, next.recipients)).toThrow();
  next.fields.forEach((field, index) => { field.page = 4; field.id = `${index + 1}0000000-0000-4000-8000-00000000000${index + 1}`; });
  expect(verifiedHTMLGeneratedFields(next.source, next.fields, next.recipients)).toBe(next.fields);
  expect(old.source.page_count).toBe(2); expect(old.source.signing_artifact!.fields[0].page).toBe(2);
  expect(old.source.contract_parties).toEqual(next.source.contract_parties);
});
export function documentFixture(source = sourceFixture()): DocumentResponse {
  return { id: documentID, org_id: orgID, sender_id: senderID, template_id: templateID, source_kind: 'pdf', status: 'draft', has_html_source: true,
    html_review_required: true, html_source_commitment: source.html_source_commitment, html_materialization_revision: source.materialization_revision,
    pdf_sha256: source.pdf_sha256, updated_at: source.updated_at } as DocumentResponse;
}
export function savedRevision() {
  const source = { ...sourceFixture(), materialization_revision: 2, html_source_commitment: 'd'.repeat(64), updated_at: '2026-10-10T05:01:00.000000123Z' };
  return { source, result: { document: documentFixture(source), materialization_revision: 2, page_count: 2, placement_reset: true as const, review_required: true as const } };
}

test('revision input preserves literal text and pins current source without allowing layout/assets/default edits', () => {
  const source = sourceFixture(), draft = revisionDraft(source);
  draft.values.company = '<script>alert(1)</script> & 🦊'; draft.sections.scope = 'Human-proposed wording\nSecond line';
  const input = htmlRevisionInput(source, draft.values, draft.sections, 'Agreed clarification');
  expect(input).toEqual({ expected_updated_at: source.updated_at, expected_html_source_commitment: source.html_source_commitment,
    values: draft.values, sections: draft.sections, summary: 'Agreed clarification' });
  expect(source.sections[0].default_text).toBe('Approved scope');
  for (const values of [{ company: 'Okay', unknown: 'bad' }, {}, { company: '  ' }, { company: '\uD800' }, { company: '\u0000' }, null, []]) {
    expect(() => htmlRevisionInput(source, values as any, draft.sections, '')).toThrow();
  }
  expect(() => htmlRevisionInput(source, draft.values, { css: 'unsafe' }, '')).toThrow();
  expect(() => htmlRevisionInput(source, draft.values, draft.sections, '🦊'.repeat(501))).toThrow('500');
  expect(htmlRevisionInput(source, { company: '🦊'.repeat(64) }, draft.sections, '🦊'.repeat(500)).summary).toHaveLength(1000);
});

test('combined text is bounded by encoded JSON request size as well as each declaration limit', () => {
  const source = sourceFixture();
  source.sections = Array.from({ length: 33 }, (_, i) => ({ name: `section_${i}`, max_chars: 32768, text: '', default_text: '' }));
  const sections = Object.fromEntries(source.sections.map((s) => [s.name, 'x'.repeat(32768)]));
  expect(() => htmlRevisionInput(source, { company: 'Company' }, sections, '')).toThrow('1 MiB');
  for (const section of source.sections) sections[section.name] = 'x';
  expect(htmlRevisionInput(source, { company: 'Company' }, sections, '').sections.section_32).toBe('x');
});

test('source refuses malformed definitions, foreign identities, source drift and inconsistent wording changes', () => {
  const source = sourceFixture(), document = documentFixture();
  expect(currentHTMLSource(source, document)).toBe(source);
  for (const change of [{ org_id: senderID }, { html_source_commitment: 'e'.repeat(64) }, { pdf_sha256: 'e'.repeat(64) },
    { updated_at: '2026-10-10T05:01:00Z' }, { html_materialization_revision: 2 }, { has_html_source: false }]) {
    expect(() => currentHTMLSource(source, { ...document, ...change } as DocumentResponse)).toThrow();
  }
  for (const change of [{ values: [{ ...source.values[0], required: 'true' }] }, { values: [source.values[0], source.values[0]] },
    { values: [{ ...source.values[0], name: undefined }] }, { sections: [{ ...source.sections[0], name: undefined }] }, { updated_at: 1 },
    { sections: [{ ...source.sections[0], text: 'New prose' }] }, { changed_sections: ['scope'] }, { page_count: 0 }, { template_version: 0 }]) {
    expect(() => validateHTMLSource({ ...source, ...change } as HTMLDocumentSource, documentID, orgID)).toThrow();
  }
});

test('clean review or field metadata adopts only the timestamp of the same immutable source', () => {
  const source = sourceFixture(), before = documentFixture(), stamp = '2026-10-10T05:02:00.000000987Z';
  for (const metadata of [{ html_review_required: false }, { name: 'Updated draft metadata' }]) {
    const next = advanceCleanHTMLObservation(source, { ...before, ...metadata, updated_at: stamp }, false);
    expect(next).toEqual({ ...source, updated_at: stamp });
    expect(next?.values).toBe(source.values); expect(next?.sections).toBe(source.sections);
    expect(source.updated_at).toBe(before.updated_at);
    expect(htmlRevisionInput(next!, { company: 'New company' }, { scope: 'Approved scope' }, '').expected_updated_at).toBe(stamp);
  }
  expect(advanceCleanHTMLObservation(source, { ...before, updated_at: stamp }, true)).toBeNull();
  for (const changes of [{ id: templateID }, { org_id: senderID }, { template_id: senderID }, { html_source_commitment: 'd'.repeat(64) },
    { pdf_sha256: 'e'.repeat(64) }, { html_materialization_revision: 2 }, { has_html_source: false }, { source_kind: 'blocks' },
    { status: 'sent' }, { updated_at: 'invalid' }]) {
    expect(advanceCleanHTMLObservation(source, { ...before, updated_at: stamp, ...changes } as DocumentResponse, false)).toBeNull();
  }
});

test('same PDF bytes with a new source commitment still require fresh review and reset field placement', () => {
  const source = sourceFixture(), before = documentFixture(), saved = savedRevision();
  expect(saved.result.document.pdf_sha256).toBe(before.pdf_sha256);
  expect(verifiedHTMLRevision(saved.result, before, source)).toBe(saved.result.document);
  for (const change of [{ placement_reset: false }, { review_required: false }, { materialization_revision: 3 }, { page_count: 0 },
    { document: { ...saved.result.document, html_source_commitment: source.html_source_commitment } },
    { document: { ...saved.result.document, html_review_required: false } }, { document: { ...saved.result.document, sender_id: orgID } }]) {
    expect(() => verifiedHTMLRevision({ ...saved.result, ...change } as any, before, source)).toThrow();
  }
  expect(htmlPlacementPins(true, before.pdf_sha256, source.html_source_commitment)).toEqual({ expected_pdf_sha256: before.pdf_sha256, expected_html_source_commitment: source.html_source_commitment });
  expect(() => htmlPlacementPins(true, before.pdf_sha256)).toThrow('pins');
  expect(htmlPlacementPins(false)).toBeUndefined();
});

test('history rejects duplicate or malformed immutable revisions and conflicting current markers', () => {
  const row = { sequence: 1, id: templateID, source_commitment: 'a'.repeat(64), pdf_sha256: 'b'.repeat(64), page_count: 2,
    created_by: senderID, created_at: '2026-10-10T05:00:00Z', summary: 'Initial materialization', current: true };
  expect(validateHTMLHistory([row])).toEqual([row]);
  for (const rows of [[row, row], [row, { ...row, sequence: 2 }], [{ ...row, page_count: 501 }], [{ ...row, source_commitment: 'bad' }],
    [{ ...row, summary: '🦊'.repeat(501) }], [{ ...row, created_by: null }]]) expect(() => validateHTMLHistory(rows as any)).toThrow();
});

test('contract source checks both pinned recipients against every printed identity and rejects drifting or incomplete bindings', () => {
  const source = contractSourceFixture(); expect(validateHTMLSource(source, documentID, orgID)).toBe(source);
  expect(htmlRevisionGroups(source).map((group) => group.id)).toEqual(['provider', 'customer', 'terms']);
  const mutations: ((value: HTMLDocumentSource) => void)[] = [
    (value) => { delete value.contract_profile_digest; }, (value) => { value.contract_profile_digest = 'bad'; },
    (value) => { value.contract_parties!.pop(); }, (value) => { value.contract_parties![1].recipient_id = value.contract_parties![0].recipient_id; },
    (value) => { value.contract_parties![1].recipient_id = '00000000-0000-0000-0000-000000000000'; },
    (value) => { value.contract_parties![1].name = 'Different person'; }, (value) => { value.contract_parties![1].email = 'different@example.test'; },
    (value) => { value.contract_parties![1].role = 'provider'; }, (value) => { value.contract_parties![1].company_id = 'Different company'; },
    (value) => { value.contract_parties![1].representative_authority = 'Different authority'; },
    (value) => { value.sections[0].text = ' '; value.changed_sections = [value.sections[0].name]; },
  ];
  for (const mutate of mutations) { const value = structuredClone(source); mutate(value); expect(() => validateHTMLSource(value, documentID, orgID)).toThrow(); }
  const unprofiled = { ...sourceFixture(), contract_parties: source.contract_parties };
  expect(() => validateHTMLSource(unprofiled, documentID, orgID)).toThrow('without a reviewed');
});

test('contract revisions preserve declared mappings and require canonical distinct identities and nonblank essential wording', () => {
  const source = contractSourceFixture(), draft = revisionDraft(source);
  const identity = source.contract_profile!.parties.find((party) => party.slot === 'customer')!;
  draft.values[identity.representative_name] = 'New designated representative';
  draft.values[identity.representative_email] = 'new@example.test';
  expect(htmlRevisionInput(source, draft.values, draft.sections, 'New representative').values[identity.representative_email]).toBe('new@example.test');
  draft.values[identity.representative_email] = source.contract_parties![0].email;
  expect(() => htmlRevisionInput(source, draft.values, draft.sections, '')).toThrow('different');
  draft.values[identity.representative_email] = 'new@example.test'; draft.sections.scope_text = ' ';
  expect(() => htmlRevisionInput(source, draft.values, draft.sections, '')).toThrow('scope');
});

test('historical source keeps its former representative assertions while a fresh revision uses the same stable party IDs', () => {
  const history = { ...contractSourceFixture(), can_edit: false }, current = structuredClone(history), party = current.contract_profile!.parties[1];
  current.materialization_revision = 2; current.html_source_commitment = 'e'.repeat(64);
  current.values.find((field) => field.name === party.representative_name)!.text = 'Updated representative';
  current.contract_parties![1].name = 'Updated representative';
  expect(validateHTMLSource(history, documentID, orgID)).toBe(history); expect(validateHTMLSource(current, documentID, orgID)).toBe(current);
  expect(history.contract_parties![1].recipient_id).toBe(current.contract_parties![1].recipient_id);
  expect(history.contract_parties![1].name).not.toBe(current.contract_parties![1].name);
});

test('retained profile accepts explicit nonblank document wording even when its frozen template default is blank', () => {
  const source = contractSourceFixture(); source.sections[0].default_text = ''; source.changed_sections = ['scope_text'];
  expect(validateHTMLSource(source, documentID, orgID)).toBe(source);
  const draft = revisionDraft(source); expect(htmlRevisionInput(source, draft.values, draft.sections, '').sections.scope_text).toBe('Reviewed service scope.');
  source.sections[0].text = ''; source.changed_sections = [];
  expect(() => validateHTMLSource(source, documentID, orgID)).toThrow('terms');
});
