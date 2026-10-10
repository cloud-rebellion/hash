import { expect, test } from 'bun:test';
import { htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate } from './htmlTemplate';
import type { TemplateResponse } from './api/client';

export function htmlTemplateFixture(): TemplateResponse {
  return { id: 'design', org_id: 'org', name: 'Approved design', source_kind: 'html', version: 3,
    content_sha256: 'a'.repeat(64), variables_json: { customer: 'Approved customer' }, fields_json: [],
    html_master_json: { schema_version: 1, html: '<p></p>', css: '', values: [{ name: 'customer', required: true, max_chars: 200 }],
      sections: [{ name: 'scope', default_text: 'Approved wording', max_chars: 1000 }] },
    html_approval: { version: 3, content_sha256: 'a'.repeat(64), approved_by: 'owner', approved_at: '2026-10-10T04:00:00Z' },
    created_by: 'owner', created_at: 'now', updated_at: 'now' };
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
