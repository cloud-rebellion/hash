import { expect, test } from 'bun:test';
import { APIError } from './client';
import { createCRMTemplateDocument, getCRMTemplateContext, getHTMLCreationRequest, observeCRMTemplate, searchCRMTemplateRecords, stopHTMLCreationRequest } from './crmTemplatePopulation';
import { templateExpected, type HTMLCreationMarker } from '../crmTemplatePopulation';
import { TP_ACTOR, TP_ID, TP_REQUEST, cleanObservation, closedCreationFixture, creationFixture, templateContextFixture, templatePopulationFixture } from '../crmTemplatePopulation.test';

async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: (path: string, options: RequestInit) => Response) {
  const original = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path, options = {}) => { calls.push({ path: String(path), options }); return respond(String(path), options); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}
const signal = () => new AbortController().signal;
test('initial transport has no document placeholder, preserves exact witness, decimal generation, raw values and declared empty', async () => {
  const c = templateContextFixture(), expected = templateExpected(c), candidate = { name: 'Manual name', values: { price: '', sticky: 'Manual wording', optional: '' }, sections: { scope_text: 'Preserved human prose.' } };
  await mocked(async calls => {
    const s = signal(); await getCRMTemplateContext(templatePopulationFixture(), s);
    expect(calls[0].path).toBe(`/api/v1/templates/${TP_ID}/html/crm/context?expected_template_version=7&expected_template_content_sha256=${'a'.repeat(64)}`);
    await searchCRMTemplateRecords(TP_ID, { ...expected, kind: 'crm.deal', query: '', offset: 0 }, s);
    expect(JSON.parse(calls[1].options.body as string)).toEqual({ ...expected, kind: 'crm.deal', query: '', offset: 0 });
    await observeCRMTemplate(TP_ID, { ...expected, candidate, mappings: [{ variable: 'price', source_kind: 'crm.deal', source_ref: 'deal_CUID2', source_path: 'value' }] }, s);
    expect(JSON.parse(calls[2].options.body as string).candidate).toEqual(candidate); expect(calls[2].options.body).not.toContain('document_id');
    for (const call of calls) expect(call.options).toMatchObject({ credentials: 'include', cache: 'no-store', signal: s });
  }, path => { const { available, variables, catalog, ...w } = c; return Response.json(path.includes('/context?') ? c : path.includes('/search') ? { ...w, kind: 'crm.deal', query: '', offset: 0, choices: [], has_more: false, next_offset: 0 } : cleanObservation(c, candidate)); });
});
test('create transports both actor witnesses and stable request, omits absent CRM, and rejects status/replay contradictions', async () => {
  const input = { name: 'Manual document', values: { price: '1290.2500', sticky: 'Manual', optional: '' }, sections: { scope_text: 'Manual scope.' }, expected_template_version: 7,
    expected_template_content_sha256: 'a'.repeat(64), request_id: TP_REQUEST, expected_org_id: TP_ACTOR.org_id, expected_user_id: TP_ACTOR.user_id };
  await mocked(async calls => { await createCRMTemplateDocument(TP_ID, input, signal()); expect(JSON.parse(calls[0].options.body as string)).toEqual(input); }, () => Response.json(creationFixture(input), { status: 201 }));
  await mocked(async () => { await expect(createCRMTemplateDocument(TP_ID, input, signal())).rejects.toThrow('Invalid template creation response'); }, () => Response.json(creationFixture(input), { status: 200 }));
  await mocked(async calls => { await expect(createCRMTemplateDocument(TP_ID, { ...input, expected_user_id: undefined }, signal())).rejects.toThrow('identity'); expect(calls).toEqual([]); }, () => Response.json({}));
});
test('authenticated recovery is exact request scoped; 404 and foreign refusal do not retry, use another UUID or expose response messages', async () => {
  const marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST };
  for (const status of [404, 401, 403, 409, 503]) await mocked(async calls => {
    try { await getHTMLCreationRequest(marker, signal()); throw new Error('Unexpected acceptance'); } catch (e) { expect(e).toBeInstanceOf(APIError); expect((e as APIError).status).toBe(status); expect((e as Error).message).not.toContain('private'); }
    expect(calls).toHaveLength(1); expect(calls[0].path).toBe(`/api/v1/templates/${TP_ID}/html/document-requests/${TP_REQUEST}`); expect(calls[0].options.method).toBe('GET');
  }, () => Response.json({ error: 'private source or credential detail' }, { status }));
});
test('bounded transport refuses invalid content/oversized streamed bodies, aborted reads and oversized observation before network', async () => {
  await mocked(async () => { await expect(getCRMTemplateContext(templatePopulationFixture(), signal())).rejects.toThrow('Invalid template creation response'); }, () => new Response('<h1>Login</h1>', { headers: { 'Content-Type': 'text/html' } }));
  let cancelled = false;
  await mocked(async () => { await expect(getCRMTemplateContext(templatePopulationFixture(), signal())).rejects.toThrow('Invalid template creation response'); expect(cancelled).toBe(true); },
    () => new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(2 * 1024 * 1024)); }, cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } }));
  await mocked(async calls => {
    const abort = new AbortController(); abort.abort(); await expect(getCRMTemplateContext(templatePopulationFixture(), abort.signal)).rejects.toThrow('aborted'); expect(calls).toEqual([]);
    await expect(observeCRMTemplate(TP_ID, { ...templateExpected(templateContextFixture()), candidate: { name: 'Large candidate', values: { a: 'x'.repeat(131072), b: 'x'.repeat(131072) } }, mappings: [] }, signal())).rejects.toThrow('request limit'); expect(calls).toEqual([]);
  }, () => Response.json({}));
});

test('Stop posts only the original actor and explicit confirmation to the same nonce with captured abort and no-store guards', async () => {
  const marker: HTMLCreationMarker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST };
  await mocked(async calls => {
    const s = signal(); await stopHTMLCreationRequest(marker, s);
    expect(calls).toHaveLength(1); expect(calls[0].path).toBe(`/api/v1/templates/${TP_ID}/html/document-requests/${TP_REQUEST}/close`);
    expect(calls[0].options).toMatchObject({ method: 'POST', credentials: 'include', cache: 'no-store', signal: s });
    expect(JSON.parse(calls[0].options.body as string)).toEqual({ expected_org_id: TP_ACTOR.org_id, expected_user_id: TP_ACTOR.user_id, confirmed: true });
  }, () => Response.json(closedCreationFixture(marker)));
  for (const status of [401, 403, 404, 409, 429, 503]) await mocked(async calls => {
    await expect(stopHTMLCreationRequest(marker, signal())).rejects.toBeInstanceOf(APIError); expect(calls).toHaveLength(1);
  }, () => Response.json({ error: 'private details' }, { status }));
});
