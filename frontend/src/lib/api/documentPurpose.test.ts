import { expect, test } from 'bun:test';
import { createBlocksDocument, createDocumentFromTemplate, createHTMLTemplateDocument, importProposalPDF, importProposalHTML, updateDocument } from './client';
import { checkedTemplateCandidate, templateCandidateKey } from '../crmTemplatePopulation';
import { blockTemplateNeedsSigning } from '../documentPurpose';

test('template capability follows native recipient-fillable block kinds without scanning wording or guessing malformed source', () => {
  for (const type of ['signature_field', 'initial_field', 'text_field', 'date_field', 'checkbox']) expect(blockTemplateNeedsSigning({ version: 1, blocks: [{ type: 'conditional', content: [{ type }] }] })).toBe(true);
  expect(blockTemplateNeedsSigning({ version: 1, blocks: [{ type: 'paragraph', text: 'signature_field is ordinary quoted wording' }] })).toBe(false);
  for (const value of [null, undefined, 'raw', {}, { version: 2, blocks: [] }, { version: 1, blocks: [{ type: 'paragraph', content: null }] }, { version: 1, blocks: Array.from({ length: 20001 }, () => ({ type: 'paragraph' })) }]) expect(blockTemplateNeedsSigning(value)).toBeNull();
  const cycle: any = { type: 'paragraph' }; cycle.content = [cycle]; expect(blockTemplateNeedsSigning({ version: 1, blocks: [cycle] })).toBeNull();
});

test('native create, import, reuse and purpose-only PATCH carry the explicit purpose without replacing content or signature policy', async () => {
  const calls: { path: string; init: RequestInit }[] = [], original = globalThis.fetch;
  globalThis.fetch = (async (path: RequestInfo | URL, init: RequestInit) => { calls.push({ path: String(path), init }); return Response.json({ purpose: 'document' }); }) as typeof fetch;
  try {
    await createBlocksDocument('Name', 'document'); await createDocumentFromTemplate('Name', 'template', 'pdf', undefined, 'presentation');
    await importProposalPDF('Name', new File(['%PDF-synthetic'], 'design.pdf'), 'document'); await importProposalHTML('Name', '<h1>Content</h1>', false, 'presentation');
    const input = { name: 'Name', purpose: 'document' as const, expected_template_version: 2, expected_template_content_sha256: 'a'.repeat(64), values: { customer: 'Preserved' }, request_id: 'request' };
    await createHTMLTemplateDocument('template', input); await updateDocument('document', { expected_updated_at: 'exact', purpose: 'document' });
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ name: 'Name', purpose: 'document', source_kind: 'blocks', blocks_json: { version: 1, blocks: [] }, variables_json: {} });
    expect(JSON.parse(calls[1].init.body as string)).toEqual({ name: 'Name', purpose: 'presentation', source_kind: 'pdf', template_id: 'template' });
    expect((calls[2].init.body as FormData).get('purpose')).toBe('document'); expect((calls[2].init.body as FormData).get('pdf')).toBeInstanceOf(File);
    expect(JSON.parse(calls[3].init.body as string)).toEqual({ name: 'Name', html: '<h1>Content</h1>', landscape: false, purpose: 'presentation' });
    expect(JSON.parse(calls[4].init.body as string)).toEqual(input); expect(JSON.parse(calls[5].init.body as string)).toEqual({ expected_updated_at: 'exact', purpose: 'document' });
    for (const call of calls) expect(call.init.credentials).toBe('include');
  } finally { globalThis.fetch = original; }
});
test('legacy omitted purpose retains the original payload; explicit HTML mode participates in the retained local candidate identity', async () => {
  const original = globalThis.fetch, bodies: unknown[] = [];
  globalThis.fetch = (async (_path: unknown, init: RequestInit) => { bodies.push(JSON.parse(init.body as string)); return Response.json({}); }) as typeof fetch;
  try { await createBlocksDocument('Name'); expect(bodies[0]).not.toHaveProperty('purpose'); } finally { globalThis.fetch = original; }
  const legacy = { name: 'Name', values: { customer: 'Preserved' } };
  const before = templateCandidateKey(legacy); expect(before).toBe(JSON.stringify(['Name', [['customer', 'Preserved']], null, null]));
  for (const purpose of ['document', 'presentation', 'signing'] as const) { const candidate = checkedTemplateCandidate({ ...legacy, purpose }); expect(candidate.purpose).toBe(purpose); expect(templateCandidateKey(candidate)).not.toBe(before); }
  for (const purpose of ['', 'signature', null, 1]) expect(() => checkedTemplateCandidate({ ...legacy, purpose })).toThrow();
});
