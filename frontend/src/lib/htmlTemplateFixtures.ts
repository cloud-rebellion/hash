import { htmlPartyBindings, requiredHTMLContractTerms, type HTMLContractProfile } from './htmlTemplate';
import { blankHTMLSigningPage } from './htmlAuthor';
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
export function signingPageTemplateFixture(): TemplateResponse {
  const template = contractTemplateFixture();
  template.html_master_json!.schema_version = 3;
  template.html_master_json!.signing_page = blankHTMLSigningPage();
  return template;
}
