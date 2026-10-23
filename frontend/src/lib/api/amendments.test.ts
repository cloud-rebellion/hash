import { afterEach, expect, test } from 'bun:test';
import { createDocumentAmendment, getDocumentAmendment, getDocumentAmendments, issueAmendmentNotice, revokeAmendmentAccess } from './amendments';
import { accessID, candidateID, deferred, input, inventory, noticeID, originalID, record, recordID, requestID, time } from '../amendmentFixtures';
const originalFetch = globalThis.fetch; afterEach(() => { globalThis.fetch = originalFetch; });
test('staff create posts only the exact reviewed ABI and refuses invented policy fields before fetch', async () => {
 let calls = 0; globalThis.fetch = (async (url, init) => { calls++; expect(String(url)).toBe('/api/v1/documents/' + originalID + '/amendments'); expect(init?.credentials).toBe('include'); expect(init?.cache).toBe('no-store'); expect(init?.redirect).toBe('error'); expect(JSON.parse(init?.body as string)).toEqual(input()); return Response.json({ state: 'committed', request_id: requestID, amendment: record() }); }) as typeof fetch;
 await createDocumentAmendment(originalID, input(), new AbortController().signal); expect(calls).toBe(1);
 await expect(createDocumentAmendment(originalID, { ...input(), fake_approval: true } as any, new AbortController().signal)).rejects.toThrow(); expect(calls).toBe(1);
});
test('only a candidate relation 404 means an ordinary document; inventory and permission failures remain blocked', async () => {
 let cancelled = 0; globalThis.fetch = (async () => new Response(new ReadableStream({ cancel() { cancelled++; } }, { highWaterMark: 0 }), { status: 404 })) as typeof fetch;
 expect(await getDocumentAmendment(candidateID, new AbortController().signal)).toBeNull(); await expect(getDocumentAmendments(originalID, new AbortController().signal)).rejects.toThrow(); expect(cancelled).toBe(2);
 globalThis.fetch = (async () => new Response('private provider error', { status: 403 })) as typeof fetch; await expect(getDocumentAmendment(candidateID, new AbortController().signal)).rejects.toThrow('permission');
});
test('staff JSON is bounded, exact-identity and excludes private or alternate original fields', async () => {
 for (const body of [{ ...inventory(), original_document_id: candidateID }, { ...inventory(), storage_key: 'private' }]) { globalThis.fetch = (async () => Response.json(body)) as typeof fetch; await expect(getDocumentAmendments(originalID, new AbortController().signal)).rejects.toThrow(); }
 globalThis.fetch = (async () => new Response(null, { headers: { 'Content-Type': 'application/json', 'Content-Length': String(4 * 1024 * 1024 + 1) } })) as typeof fetch; await expect(getDocumentAmendments(originalID, new AbortController().signal)).rejects.toThrow();
});
test('staff request abort cancels a pending body read and joined HTTP refusal does not leak response text', async () => {
 const started = deferred<void>(), abort = new AbortController(); let cancelled = false;
 globalThis.fetch = (async () => new Response(new ReadableStream({ pull() { started.resolve(); }, cancel() { cancelled = true; } }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } })) as typeof fetch;
 const reading = getDocumentAmendments(originalID, abort.signal); await started.promise; abort.abort(); await expect(reading).rejects.toThrow(); expect(cancelled).toBe(true);
 const entered = deferred<void>(), release = deferred<void>(); let settled = false; globalThis.fetch = (async () => new Response(new ReadableStream({ cancel() { entered.resolve(); return release.promise; } }, { highWaterMark: 0 }), { status: 429 })) as typeof fetch;
 const refused = getDocumentAmendments(originalID, new AbortController().signal).finally(() => { settled = true; }); await entered.promise; expect(settled).toBe(false); release.resolve(); await expect(refused).rejects.toThrow('Too many');
});
test('notice issue rejects unreviewed content or invalid audience without a request', async () => {
 let calls = 0; globalThis.fetch = (async () => { calls++; throw Error('must not fetch'); }) as typeof fetch;
 const issue = { request_id: requestID, expected_head_revision: '1', expected_document_updated_at: time, subject: 'Subject', text: 'Text', recipient_emails: ['person@example.test'], reviewed: true };
 for (const value of [{ ...issue, reviewed: false }, { ...issue, recipient_emails: [] }, { ...issue, expected_head_revision: 1 }]) await expect(issueAmendmentNotice(originalID, noticeID, value as any, new AbortController().signal)).rejects.toThrow(); expect(calls).toBe(0);
});

test('access revocation is an exact owner POST with no client proof or new notice request', async () => {
 globalThis.fetch = (async (url, init) => { expect(String(url)).toBe('/api/v1/documents/' + originalID + '/amendments/' + recordID + '/notice/access/' + accessID + '/revoke'); expect(init?.method).toBe('POST'); expect(init?.body).toBe('{}'); return Response.json({ schema: 'hash-later-amendments-v1', state: 'unknown', access_id: accessID, reconciliation_required: true }); }) as typeof fetch;
 expect((await revokeAmendmentAccess(originalID, recordID, accessID, new AbortController().signal)).state).toBe('unknown');
 globalThis.fetch = (async () => Response.json({ schema: 'hash-later-amendments-v1', state: 'committed', access_id: accessID })) as typeof fetch; await expect(revokeAmendmentAccess(originalID, recordID, accessID, new AbortController().signal)).rejects.toThrow();
});
