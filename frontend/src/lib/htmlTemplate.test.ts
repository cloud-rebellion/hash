import { expect, test } from 'bun:test';
import { htmlContractProfile, htmlPartyBindings, htmlProfileIssues, htmlProfileSectionValues, htmlTemplateFields, htmlTemplateGroups, htmlValuesForSubmission, isApprovedHTMLTemplate, requiredHTMLContractTerms, type HTMLContractProfile } from './htmlTemplate';
import type { TemplateResponse } from './api/client';

export function htmlTemplateFixture(): TemplateResponse {
  return { id: 'design', org_id: 'org', name: 'Approved design', source_kind: 'html', version: 3,
    content_sha256: 'a'.repeat(64), variables_json: { customer: 'Approved customer' }, fields_json: [],
    html_master_json: { schema_version: 1, html: '<p></p>', css: '', values: [{ name: 'customer', required: true, max_chars: 200 }],
      sections: [{ name: 'scope', default_text: 'Approved wording', max_chars: 1000 }] },
    html_approval: { version: 3, content_sha256: 'a'.repeat(64), approved_by: 'owner', approved_at: '2026-10-10T04:00:00Z' },
    created_by: 'owner', created_at: 'now', updated_at: 'now' };
}
export function contractTemplateFixture(kind: HTMLContractProfile['kind'] = 'proposal'): TemplateResponse {
  const parties = (['provider', 'customer'] as const).map((slot) => ({ slot, ...Object.fromEntries(htmlPartyBindings.map((name) => [name, `${slot}_${name}`])) })) as HTMLContractProfile['parties'];
  const terms = requiredHTMLContractTerms(kind).map((name) => name === 'scope' ? { name, section: 'scope_text' } : { name, value: `term_${name}` });
  const names = [...parties.flatMap((party) => htmlPartyBindings.map((binding) => party[binding])), ...terms.flatMap((term) => term.value ? [term.value] : [])];
  return { ...htmlTemplateFixture(), html_master_json: { schema_version: 2, html: '<p></p>', css: '',
    values: names.map((name) => ({ name, required: true, max_chars: 256 })),
    sections: [{ name: 'scope_text', default_text: 'Reviewed service scope.', max_chars: 2000 }],
    contract_profile: { id: 'reviewed_sales', version: 1, kind, parties, terms } }, variables_json: Object.fromEntries(names.map((name) => [name,
      name.endsWith('representative_email') ? `${name}@example.test` : `Approved ${name}`])) };
}

test('HTML approval belongs to the exact returned revision and reload cannot infer missing approval', () => {
  const template = htmlTemplateFixture();
  expect(isApprovedHTMLTemplate(template)).toBe(true);
  for (const approval of [undefined, { version: 3, content_sha256: 'a'.repeat(64) },
    { ...template.html_approval!, version: 2 }, { ...template.html_approval!, content_sha256: 'b'.repeat(64) },
    { ...template.html_approval!, approved_at: 'invalid' }]) {
    expect(isApprovedHTMLTemplate({ ...template, html_approval: approval })).toBe(false);
  }
});

test('declared fields load approved defaults and submission preserves exact Unicode/whitespace only for declared values', () => {
  const fields = htmlTemplateFields(htmlTemplateFixture());
  expect(fields[0].defaultValue).toBe('Approved customer');
  const value = '  Reviewed <AB> & Co 𝄞  ';
  expect(htmlValuesForSubmission(fields, { customer: value, undeclared: 'ignored', scope: 'unapproved prose' })).toEqual({ customer: value });
  fields[0].max_chars = 2;
  expect(htmlValuesForSubmission(fields, { customer: '𝄞𝄞' })).toEqual({ customer: '𝄞𝄞' });
  expect(() => htmlValuesForSubmission(fields, { customer: '𝄞𝄞x' })).toThrow('within 2');
  expect(() => htmlValuesForSubmission(fields, { customer: '  ' })).toThrow('required');
});

test('malformed definitions and null/undeclared defaults fail without coercing approved content', () => {
  for (const defaults of [null, [], { customer: null }, { customer: 4 }, { customer: 'Valid', hidden: 'Other' }]) {
    expect(() => htmlTemplateFields({ ...htmlTemplateFixture(), variables_json: defaults })).toThrow();
  }
  const template = htmlTemplateFixture();
  template.html_master_json!.values!.push({ name: 'customer', required: false, max_chars: 10 });
  expect(() => htmlTemplateFields(template)).toThrow();
  expect(() => htmlTemplateFields({ ...htmlTemplateFixture(), source_kind: 'pdf' })).toThrow();
});

test('reviewed contract profiles preserve both printed parties and group commercial values and approved wording', () => {
  for (const kind of ['proposal', 'b2b_services'] as const) {
    const template = contractTemplateFixture(kind), master = template.html_master_json!;
    expect(htmlContractProfile(master)).toEqual(master.contract_profile!);
    const groups = htmlTemplateGroups(template);
    expect(groups.map((group) => [group.id, group.label])).toEqual([['provider', 'Our company'], ['customer', 'Customer'], ['terms', 'Commercial terms']]);
    expect(groups[0].fields.map((field) => field.name)).toEqual(htmlPartyBindings.map((binding) => `provider_${binding}`));
    expect(groups[1].fields.map((field) => field.name)).toEqual(htmlPartyBindings.map((binding) => `customer_${binding}`));
    expect(groups[2].sections).toEqual([{ name: 'scope_text', label: 'scope', default_text: 'Reviewed service scope.', max_chars: 2000 }]);
    expect(groups[2].fields.map((field) => field.name)).toEqual(requiredHTMLContractTerms(kind).filter((name) => name !== 'scope').map((name) => `term_${name}`));
    const returned = htmlContractProfile(master)!; returned.parties[0].representative_name = 'changed';
    expect(master.contract_profile!.parties[0].representative_name).toBe('provider_representative_name');
  }
  expect(htmlContractProfile(htmlTemplateFixture().html_master_json!)).toBeNull();
  expect(htmlTemplateGroups(htmlTemplateFixture()).map((group) => group.id)).toEqual(['values']);
});

test('profile validation refuses missing parties, reused assertions, omitted essentials and incomplete or hidden mappings', () => {
  const mutations: ((master: NonNullable<TemplateResponse['html_master_json']>) => void)[] = [
    (master) => { master.schema_version = 1; },
    (master) => { delete master.contract_profile; },
    (master) => { master.contract_profile!.version = 1_000_001; },
    (master) => { (master.contract_profile as any).id = undefined; },
    (master) => { (master.contract_profile as any).unreviewed = 'hidden'; },
    (master) => { master.contract_profile!.parties.pop(); },
    (master) => { master.contract_profile!.parties[1].slot = 'provider'; },
    (master) => { master.contract_profile!.parties[1].representative_name = master.contract_profile!.parties[0].representative_name; },
    (master) => { master.values![0].required = false; },
    (master) => { master.contract_profile!.terms.pop(); },
    (master) => { master.contract_profile!.terms[1].value = 'undeclared'; },
    (master) => { master.contract_profile!.terms[1].value = master.contract_profile!.parties[0].company_name; },
    (master) => { master.contract_profile!.terms[2].value = master.contract_profile!.terms[1].value; },
    (master) => { master.contract_profile!.terms[0].value = 'term_price'; },
    (master) => { master.sections = []; },
    (master) => { master.contract_profile!.terms.push(...Array.from({ length: 11 }, (_, index) => ({ name: `extra_${index}`, value: `extra_${index}` }))); },
  ];
  for (const mutate of mutations) { const template = contractTemplateFixture(); mutate(template.html_master_json!); expect(() => htmlTemplateFields(template)).toThrow(); }
});

test('populate checks intended representatives from printed values without claiming verified identity or authority', () => {
  const template = contractTemplateFixture(), profile = template.html_master_json!.contract_profile!, values = template.variables_json as Record<string, string>;
  const issues = (next: Record<string, string>) => htmlProfileIssues(profile, next, { scope_text: 'Reviewed scope.' });
  expect(issues(values)).toEqual([]);
  expect(issues({ ...values, customer_company_id: '', term_price: ' ' })).toContain('Enter customer company or registration identifier.');
  expect(issues({ ...values, customer_company_id: '', term_price: ' ' })).toContain('Enter price.');
  expect(issues({ ...values, customer_representative_email: 'Person <p@example.test>' })).toContain('Enter a plain valid customer representative email without surrounding spaces.');
  expect(issues({ ...values, customer_representative_email: values.provider_representative_email.toUpperCase() })).toContain('Provider and customer need different representative email addresses.');
  expect(issues({ ...values, customer_representative_email: 'person@internal' })).toEqual([]);
  expect(issues({ ...values, customer_representative_name: 'a'.repeat(201) })).toContain('Keep customer representative name within 200 characters without surrounding spaces or control characters.');
  expect(issues({ ...values, customer_representative_name: 'Name\nOther' })).toContain('Keep customer representative name within 200 characters without surrounding spaces or control characters.');
  expect(issues({ ...values, customer_representative_email: ' p@example.test ' }).some((issue) => issue.includes('surrounding spaces'))).toBe(true);
  expect(issues({ ...values, customer_company_id: ` ${values.provider_company_id.toUpperCase()} ` })).toContain('Provider and customer company identifiers conflict.');
});

test('declared section can have a blank template default but effective contract wording remains required', () => {
  const template = contractTemplateFixture(), master = template.html_master_json!, profile = master.contract_profile!;
  master.sections![0].default_text = '';
  expect(htmlContractProfile(master)).toEqual(profile);
  expect(htmlTemplateFields(template).length).toBeGreaterThan(0);
  expect(htmlProfileIssues(profile, template.variables_json as Record<string, string>, { scope_text: '' })).toEqual(['Enter scope wording.']);
  expect(htmlProfileIssues(profile, template.variables_json as Record<string, string>, { scope_text: 'Explicit human-reviewed document scope.' })).toEqual([]);
  expect(htmlProfileSectionValues(master, { scope_text: 'Explicit human-reviewed document scope.', scope: 'Wrong semantic key', undeclared: 'Unapproved' })).toEqual({ scope_text: 'Explicit human-reviewed document scope.' });
  expect(() => htmlProfileSectionValues(master, { scope_text: ' ' })).toThrow('scope');
  expect(htmlProfileSectionValues(htmlTemplateFixture().html_master_json!, { scope: 'Untouched generic design behavior' })).toBeUndefined();
});
