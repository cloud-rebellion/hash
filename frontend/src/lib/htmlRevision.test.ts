import { expect, test } from 'bun:test';
import { advanceCleanHTMLObservation, currentHTMLSource, htmlPlacementPins, htmlRevisionGroups, htmlRevisionInput, revisionDraft, validateHTMLHistory, validateHTMLSource, verifiedHTMLRevision } from './htmlRevision';
import type { DocumentResponse, HTMLDocumentSource } from './api/client';
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
