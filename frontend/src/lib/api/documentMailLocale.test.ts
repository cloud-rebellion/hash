import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { staffLocale, setStaffLocale } from '../staffPreferences';
import { checkedTemplateCandidate, templateCandidateKey } from '../crmTemplatePopulation';
import { createBlocksDocument, createDocumentFromTemplate, createHTMLTemplateDocument, importProposalPDF, importProposalHTML } from './client';

test('new UI documents carry Swedish email language in their original creation request', async () => {
  const original = globalThis.fetch, previous = get(staffLocale);
  const calls: RequestInit[] = [];
  globalThis.fetch = (async (_url: unknown, init: RequestInit) => { calls.push(init); return Response.json({}); }) as typeof fetch;
  try {
    setStaffLocale('sv');
    await createBlocksDocument('Swedish document', 'document');
    await createDocumentFromTemplate('Swedish PDF', 'template', 'pdf', { expected_template_version: 1, parties: [{ role: 'client', name: 'English customer', email: 'customer@example.invalid', locale: 'en' }] }, 'signing');
    await importProposalPDF('Swedish upload', new File(['%PDF-synthetic'], 'synthetic.pdf'), 'document');
    await importProposalHTML('Swedish design', '<h1>Synthetic</h1>', false, 'presentation');
    await createHTMLTemplateDocument('template', { name: 'Captured design', default_locale: 'sv', expected_template_version: 1, expected_template_content_sha256: 'a'.repeat(64), values: {}, request_id: 'unchanged-request' });
    expect(calls).toHaveLength(5);
    for (const index of [0, 1, 3, 4]) expect(JSON.parse(calls[index].body as string).default_locale).toBe('sv');
    expect((calls[2].body as FormData).get('default_locale')).toBe('sv');
    expect(JSON.parse(calls[1].body as string).parties[0].locale).toBe('en');
    for (const call of calls) expect(call.method).toBe('POST');
    setStaffLocale('en');
    await createHTMLTemplateDocument('template', { name: 'Captured design', default_locale: 'sv', expected_template_version: 1, expected_template_content_sha256: 'a'.repeat(64), values: {}, request_id: 'unchanged-request' });
    expect(JSON.parse(calls[5].body as string).default_locale).toBe('sv');
    expect(JSON.parse(calls[5].body as string).request_id).toBe('unchanged-request');
    setStaffLocale('sv');
    await createDocumentFromTemplate('Explicit English', 'template', 'pdf', { expected_template_version: 1, default_locale: 'en' });
    expect(JSON.parse(calls[6].body as string).default_locale).toBe('en');
    await createDocumentFromTemplate('Unspecified layout language', 'template', 'pdf', { expected_template_version: 1, default_locale: undefined });
    expect(JSON.parse(calls[7].body as string).default_locale).toBe('sv');
  } finally { globalThis.fetch = original; setStaffLocale(previous); }
});

test('a designed creation captures email language in its retained identity while legacy identities remain unchanged', () => {
  const legacy = { name: 'Design', values: {} };
  expect(templateCandidateKey(legacy)).toBe(JSON.stringify(['Design', [], null, null]));
  const sv = checkedTemplateCandidate({ ...legacy, default_locale: 'sv' });
  const en = checkedTemplateCandidate({ ...legacy, default_locale: 'en' });
  expect(sv.default_locale).toBe('sv');
  expect(templateCandidateKey(sv)).not.toBe(templateCandidateKey(en));
  for (const default_locale of ['', null, 'unknown', 7]) expect(() => checkedTemplateCandidate({ ...legacy, default_locale })).toThrow();
});
