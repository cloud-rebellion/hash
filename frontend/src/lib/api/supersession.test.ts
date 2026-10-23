import { expect, test } from 'bun:test';
import { closeSupersession, createSupersession, getSupersessionContext, inspectSupersession } from './supersession';
import { supersessionFixture } from '../supersessionFixtures';
async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, replies: Response[]) {
  const old = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options?: RequestInit) => { calls.push({ path: String(path), options: options ?? {} }); const next = replies.shift(); if (!next) throw new Error('unexpected request'); return next; }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = old; }
}
test('session context and fresh source creation use exact fixed routes and unchanged cookie/error transport', async () => {
  const { actor, ready, marker, result } = supersessionFixture(); const signal = new AbortController().signal;
  await mocked(async calls => {
    const context = await getSupersessionContext(ready.prior.document_id, actor, signal); expect(context.state).toBe('ready');
    const outcome = await createSupersession(ready, 'Fresh draft', { customer_name: 'New Customer' }, {}, marker, signal); expect(outcome.document_id).toBe(result.document_id);
    expect(calls.map(c => [c.path, c.options.method, c.options.credentials, c.options.cache, c.options.signal])).toEqual([
      [`/api/v1/presign/supersessions/documents/${marker.prior_document_id}/context`, 'GET', 'include', 'no-store', signal], ['/api/v1/presign/supersessions', 'POST', 'include', 'no-store', signal],
    ]);
    expect(JSON.parse(calls[1].options.body as string).source.request_id).toBe(marker.request_id);
  }, [Response.json(ready), Response.json(result)]);
});
test('unconfirmed recovery never mints another request and only original serialized M79 closure releases it', async () => {
  const { marker } = supersessionFixture(); const signal = new AbortController().signal;
  const closed = { state: 'closed', org_id: marker.org_id, user_id: marker.user_id, template_id: marker.template_id, request_id: marker.request_id, closed_at: '2026-10-23T12:00:00Z' };
  await mocked(async calls => { expect(await inspectSupersession(marker, signal)).toEqual({ state: 'unconfirmed' }); expect(calls.every(c => c.options.method === 'GET')).toBe(true); }, [new Response('', { status: 404 }), new Response('', { status: 404 })]);
  await mocked(async calls => { expect(await closeSupersession(marker, signal)).toEqual({ state: 'closed' }); expect(calls[0].path).toBe(`/api/v1/templates/${marker.template_id}/html/document-requests/${marker.request_id}/close`); expect(JSON.parse(calls[0].options.body as string)).toEqual({ expected_org_id: marker.org_id, expected_user_id: marker.user_id, confirmed: true }); }, [Response.json(closed)]);
  await mocked(async () => { await expect(inspectSupersession(marker, signal)).rejects.toThrow(); }, [new Response('', { status: 404 }), Response.json({ ...closed, user_id: marker.prior_document_id })]);
  await mocked(async () => { await expect(inspectSupersession(marker, signal)).rejects.toThrow(); }, [new Response('', { status: 404 }), Response.json({ state: 'committed', document_id: marker.prior_document_id })]);
});
