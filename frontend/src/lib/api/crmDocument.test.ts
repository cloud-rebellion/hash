import { expect, test } from 'bun:test';
import { APIError } from './client';
import { applyCRMDocument, getCRMDocumentContext, observeCRMDocument, searchCRMDocumentRecords } from './crmDocument';
import { crmExpected } from '../crmDocument';
import { CRM_DOCUMENT_ID, CRM_MAPPING, crmContextFixture, crmDocumentFixture, crmObservationFixture } from '../crmDocument.test';

async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: (path: string) => Response) {
  const original = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options?: RequestInit) => { calls.push({ path: String(path), options: options ?? {} }); return respond(String(path)); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}
function witness() { const { org_id, user_id, document_id, updated_at, html_source_commitment, binding_fingerprint, connection } = crmContextFixture(); return { org_id, user_id, document_id, updated_at, html_source_commitment, binding_fingerprint, connection }; }
test('document transport uses exact scoped routes and captures actor, full bindings, decimal generation and AbortSignal', async () => {
  await mocked(async (calls) => {
    const signal = new AbortController().signal, expected = crmExpected(crmContextFixture());
    await getCRMDocumentContext(CRM_DOCUMENT_ID, signal);
    await searchCRMDocumentRecords(CRM_DOCUMENT_ID, { ...expected, kind: 'crm.deal', query: 'Contract', offset: 20 }, signal);
    await observeCRMDocument(CRM_DOCUMENT_ID, { ...expected, mappings: [CRM_MAPPING] }, signal);
    await applyCRMDocument(CRM_DOCUMENT_ID, { ...expected, mappings: [CRM_MAPPING], reviewed_digest: 'd'.repeat(64), confirmed: true }, signal);
    expect(calls.map((c) => c.path)).toEqual(['context', 'records/search', 'observations', 'apply'].map((tail) => `/api/v1/documents/${CRM_DOCUMENT_ID}/crm/${tail}`));
    for (const call of calls) expect(call.options).toMatchObject({ credentials: 'include', cache: 'no-store', signal });
    expect(calls[0].options.method).toBe('GET'); expect(calls[0].options.body).toBeUndefined();
    expect(JSON.parse(calls[1].options.body as string)).toEqual({ ...expected, kind: 'crm.deal', query: 'Contract', offset: 20 });
    expect(JSON.parse(calls[2].options.body as string)).toEqual({ ...expected, mappings: [CRM_MAPPING] });
    expect(JSON.parse(calls[3].options.body as string)).toEqual({ ...expected, mappings: [CRM_MAPPING], reviewed_digest: 'd'.repeat(64), confirmed: true });
  }, (path) => path.endsWith('/context') ? Response.json(crmContextFixture()) : path.endsWith('/search') ? Response.json({ ...witness(), kind: 'crm.deal', query: 'Contract', offset: 20, choices: [], has_more: false, next_offset: 0 })
    : path.endsWith('/observations') ? Response.json(crmObservationFixture()) : Response.json({ ...witness(), document: crmDocumentFixture(), content_changed: false, mapping_review_required: false }));
});
test('invalid actor, rounded generation, query, target and absent confirmation cannot dispatch', async () => {
  await mocked(async (calls) => {
    const signal = new AbortController().signal, expected = crmExpected(crmContextFixture());
    await expect(getCRMDocumentContext('CRM_CUID2', signal)).rejects.toThrow();
    await expect(searchCRMDocumentRecords(CRM_DOCUMENT_ID, { ...expected, expected_user_id: 'user_CUID2', kind: 'crm.deal', query: 'Contract', offset: 0 }, signal)).rejects.toThrow();
    await expect(searchCRMDocumentRecords(CRM_DOCUMENT_ID, { ...expected, expected_connection_generation: '01', kind: 'crm.deal', query: 'Contract', offset: 0 }, signal)).rejects.toThrow();
    await expect(searchCRMDocumentRecords(CRM_DOCUMENT_ID, { ...expected, kind: 'crm.deal', query: 'x', offset: 0 }, signal)).rejects.toThrow();
    await expect(observeCRMDocument(CRM_DOCUMENT_ID, { ...expected, mappings: [{ ...CRM_MAPPING, source_ref: 'trimmed ID ' }] }, signal)).rejects.toThrow();
    await expect(applyCRMDocument(CRM_DOCUMENT_ID, { ...expected, mappings: [CRM_MAPPING], reviewed_digest: 'd'.repeat(64), confirmed: false as true }, signal)).rejects.toThrow();
    expect(calls).toEqual([]);
  }, () => Response.json({}));
});
test('raw error bodies, non-JSON and streamed oversized responses are cancelled without leaking upstream data', async () => {
  for (const response of [() => new Response('login', { headers: { 'Content-Type': 'text/html' } }),
    () => Response.json({ ...crmContextFixture(), credential: 'secret' }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String(8 * 1024 * 1024 + 1) } })]) {
    await mocked(async () => { await expect(getCRMDocumentContext(CRM_DOCUMENT_ID, new AbortController().signal)).rejects.toThrow(); }, response);
  }
  let cancelled = false;
  await mocked(async () => { await expect(getCRMDocumentContext(CRM_DOCUMENT_ID, new AbortController().signal)).rejects.toThrow(); expect(cancelled).toBe(true); },
    () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(8 * 1024 * 1024 + 1)); }, cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } }));
  await mocked(async () => {
    try { await getCRMDocumentContext(CRM_DOCUMENT_ID, new AbortController().signal); throw new Error('accepted'); }
    catch (error) { expect(error).toBeInstanceOf(APIError); expect((error as APIError).status).toBe(503); expect((error as Error).message).not.toContain('secret'); }
  }, () => Response.json({ error: 'secret upstream bearer' }, { status: 503 }));
});
test('aborted streams cannot return a verified DTO after response headers', async () => {
  const abort = new AbortController();
  await mocked(async () => { await expect(getCRMDocumentContext(CRM_DOCUMENT_ID, abort.signal)).rejects.toThrow(); }, () => {
    const bytes = new TextEncoder().encode(JSON.stringify(crmContextFixture()));
    return new Response(new ReadableStream({ pull(c) { c.enqueue(bytes); abort.abort(); c.close(); } }), { headers: { 'Content-Type': 'application/json' } });
  });
});
