import { expect, test } from 'bun:test';
import { htmlContractProfile, htmlPartyBindings, htmlPreviewSections, htmlProfileIssues, htmlProfileSectionValues, htmlSigningPage, htmlSigningPageIssues, htmlSigningPagePlainText, htmlTemplateFields, htmlTemplateGroups, htmlValuesForSubmission, isApprovedHTMLTemplate, requiredHTMLContractTerms } from './htmlTemplate';
import { blankHTMLSigningPage } from './htmlAuthor';
import type { TemplateResponse } from './api/client';
import { htmlTemplateFixture, contractTemplateFixture, signingPageTemplateFixture } from './htmlTemplateFixtures';

test('initial manual candidate defers only required blanks for observed overlay while preserving declared text/empty and size limits', () => {
  const fields = htmlTemplateFields(htmlTemplateFixture());
  expect(htmlValuesForSubmission(fields, { customer: '' }, true)).toEqual({ customer: '' });
  expect(() => htmlValuesForSubmission(fields, { customer: '' })).toThrow('required');
  expect(() => htmlValuesForSubmission(fields, { customer: 'x'.repeat(201) }, true)).toThrow('within');
  expect(() => htmlValuesForSubmission(fields, { customer: null as any }, true)).toThrow();
  const template = contractTemplateFixture(), manual = { scope_text: '' };
  expect(htmlProfileSectionValues(template.html_master_json!, manual, true)).toEqual(manual);
  expect(() => htmlProfileSectionValues(template.html_master_json!, manual)).toThrow('scope');
  expect(htmlProfileSectionValues(template.html_master_json!, { scope_text: 'Human text.\nSecond line.' }, true)).toEqual({ scope_text: 'Human text.\nSecond line.' });
});

test('appended signing page is explicit and preserved while version 1 and 2 designs retain their original bytes', () => {
  for (const template of [htmlTemplateFixture(), contractTemplateFixture()]) {
    const before = JSON.stringify(template);
    expect(htmlSigningPage(template.html_master_json!)).toBeNull();
    htmlTemplateFields(template);
    expect(JSON.stringify(template)).toBe(before);
  }
  const template = signingPageTemplateFixture(), master = template.html_master_json!;
  expect(htmlSigningPage(master)).toEqual(blankHTMLSigningPage());
  expect(htmlTemplateGroups(template).map((group) => group.id)).toEqual(['provider', 'customer', 'terms']);
  expect(htmlContractProfile(master)).toEqual(master.contract_profile!);
  delete master.contract_profile;
  expect(() => htmlTemplateFields(template)).toThrow('both parties');
});

test('page refuses incomplete branding, unsupported policy, mutable logos and missing or mismatched local image', () => {
  const mutations: ((master: NonNullable<TemplateResponse['html_master_json']>) => void)[] = [
    (master) => { master.schema_version = 2; },
    (master) => { delete master.signing_page; },
    (master) => { (master.signing_page as any).version = 2; },
    (master) => { (master.signing_page as any).policy = 'unknown'; },
    (master) => { delete (master.signing_page as any).font_sha256; },
    (master) => { (master.signing_page as any).font_sha256 = 'a'.repeat(64); },
    (master) => { (master.signing_page as any).extra = true; },
    (master) => { delete (master.signing_page!.branding as any).muted_hex; },
    (master) => { master.signing_page!.branding.font_body = 'Mutable Font'; },
    (master) => { master.signing_page!.branding.logo_url = '/branding/logo/org.png'; },
    (master) => { master.signing_page!.branding.logo_alt = 'Fallback logo'; },
    (master) => { master.signing_page!.branding.signature_color = 'red'; },
    (master) => { master.signing_page!.branding.text_hex = '#FFFFFF'; },
    (master) => { master.signing_page!.branding.muted_hex = '#DDDDDD'; },
    (master) => { master.signing_page!.logo_alt = 'No-logo drift'; },
    (master) => { master.signing_page!.logo_asset = 'unavailable'; master.signing_page!.logo_sha256 = 'a'.repeat(64); master.signing_page!.logo_alt = 'Company logo'; },
  ];
  for (const mutate of mutations) { const template = signingPageTemplateFixture(); mutate(template.html_master_json!); expect(() => htmlTemplateFields(template)).toThrow(); }
  const template = signingPageTemplateFixture(), master = template.html_master_json!;
  master.assets = [{ name: 'company_logo', media_type: 'image/png', data_base64: 'AA==', sha256: 'a'.repeat(64) }];
  Object.assign(master.signing_page!, { logo_asset: 'company_logo', logo_sha256: 'a'.repeat(64), logo_alt: 'Company logo' });
  expect(htmlSigningPage(master)?.logo_asset).toBe('company_logo');
  master.assets[0].sha256 = 'b'.repeat(64); expect(() => htmlSigningPage(master)).toThrow('exact design');
  master.assets[0].sha256 = 'a'.repeat(64); master.assets[0].media_type = 'font/woff2'; expect(() => htmlSigningPage(master)).toThrow('image asset');
});

test('signing-page text bounds preserve Unicode and reject invisible, overflowing or clipped identity assertions', () => {
  expect(htmlSigningPagePlainText('Å'.repeat(80), 80)).toBe(true);
  expect(htmlSigningPagePlainText('™'.repeat(40), 80)).toBe(true);
  expect(htmlSigningPagePlainText('a\u0301'.repeat(40), 80)).toBe(true);
  for (const text of ['™'.repeat(41), '界', 'Αθήνα', 'Москва', 'a'.repeat(81), '\u0301Name', 'Name\u202e', 'Name\nOther', ' Name', 'Name ', '\uD800']) expect(htmlSigningPagePlainText(text, 80)).toBe(false);
  const template = signingPageTemplateFixture(), values = template.variables_json as Record<string, string>, profile = template.html_master_json!.contract_profile!;
  expect(htmlSigningPageIssues(profile, values)).toEqual([]);
  const longer = { ...values, customer_representative_name: 'N'.repeat(81) };
  expect(htmlProfileIssues(profile, longer, { scope_text: 'Human reviewed terms' })).toEqual([]);
  expect(htmlSigningPageIssues(profile, longer)[0]).toContain('80 characters');
  expect(longer.customer_representative_name).toHaveLength(81);
});

test('owner can preview synthetic essential wording without changing blank saved defaults or template commitment', () => {
  const template = signingPageTemplateFixture(), master = template.html_master_json!;
  master.sections![0].default_text = '';
  const before = JSON.stringify(template);
  expect(() => htmlPreviewSections(master, { scope_text: '' })).toThrow('scope');
  const samples = { scope_text: 'Synthetic preview scope <text> & terms' };
  expect(htmlPreviewSections(master, samples)).toEqual(samples);
  expect(JSON.stringify(template)).toBe(before);
  expect(() => htmlPreviewSections(master, { ...samples, undisclosed: 'Unapproved section' })).toThrow('declared');
});

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
