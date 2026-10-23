import { expect, test } from 'bun:test';
import { checkedPublicNotice, exchangeNoticeAccess, fetchNoticePDF, getPublicNotice, noticeUnavailable, takeNoticeFragment, type PublicNotice } from './noticeAccess';
import { candidateID, deferred, noticeID, originalID, time } from './amendmentFixtures';
const data = new TextEncoder().encode('%PDF-exact-notice-document');
const sha = async (value: Uint8Array) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', value))].map(x => x.toString(16).padStart(2, '0')).join('');
async function fixture() {
 const notice: PublicNotice = { schema: 'hash-amendment-notice-access-v1', notice_id: noticeID, original_document_id: originalID, document_id: candidateID, subject: 'Recorded changes', text: 'Read the accompanying documents.', issued_at: time, expires_at: '2026-10-28T01:02:03.123456Z', file_commitment_sha256: 'b'.repeat(64), files: [{ position: 0, title: 'Amendment', pdf_sha256: await sha(data), pdf_bytes: data.length, pdf_pages: 1, file_version_sha256: 'c'.repeat(64) }] };
 const file = notice.files[0], headers = new Headers({ 'Content-Type': 'application/pdf', 'Content-Length': String(data.length), ETag: '"' + notice.file_commitment_sha256 + '.' + file.pdf_sha256 + '"', 'X-Hash-Notice-Id': noticeID, 'X-Hash-Notice-File-Commitment-SHA256': notice.file_commitment_sha256, 'X-Hash-PDF-SHA256': file.pdf_sha256, 'X-Hash-PDF-Bytes': String(data.length), 'X-Hash-PDF-Pages': '1', 'X-Hash-Notice-File-Position': '0', 'X-Hash-Notice-File-Version-SHA256': file.file_version_sha256 }); return { notice, file, headers };
}
test('notice capability is a single canonical fragment token, never a query or signer token', () => {
 const token = 'hn1.' + 'A'.repeat(43); expect(takeNoticeFragment('#access=' + token)).toBe(token); expect(takeNoticeFragment('')).toBeNull();
 for (const value of ['#token=' + token, '#access=' + token + '&access=' + token, '#access=' + token + '&redirect=/sign', '#access=' + 'A'.repeat(43), '#access=hn1.' + 'A'.repeat(42) + 'B']) expect(() => takeNoticeFragment(value)).toThrow(noticeUnavailable);
});
test('notice exchange places the capability only in the exact no-store JSON POST and leaves cookie ownership to the server', async () => {
 const token = 'hn1.' + 'A'.repeat(43), abort = new AbortController(); let calls = 0;
 const fetcher = (async (url, init) => { calls++; expect(String(url)).toBe('/api/v1/notices/' + noticeID + '/access'); expect(String(url)).not.toContain(token); expect(init?.body).toBe(JSON.stringify({ token })); expect(new TextEncoder().encode(init?.body as string).length).toBeLessThanOrEqual(128); expect(init?.credentials).toBe('include'); expect(init?.cache).toBe('no-store'); expect(init?.redirect).toBe('error'); expect(init?.referrerPolicy).toBe('no-referrer'); expect(new Headers(init?.headers).has('Authorization')).toBe(false); return new Response(null, { status: 204 }); }) as typeof fetch;
 await exchangeNoticeAccess(noticeID, token, abort.signal, fetcher); expect(calls).toBe(1);
});
test('public notice metadata is closed, exact-version and cookie-only without signer identity', async () => {
 const f = await fixture(); const fetcher = (async (url, init) => { expect(String(url)).toBe('/api/v1/notices/' + noticeID); expect(init?.body).toBeUndefined(); expect(init?.credentials).toBe('include'); expect(init?.cache).toBe('no-store'); return Response.json(f.notice); }) as typeof fetch;
 expect(await getPublicNotice(noticeID, new AbortController().signal, fetcher)).toEqual(f.notice);
 for (const value of [{ ...f.notice, private_key: 'hidden' }, { ...f.notice, notice_id: originalID }, { ...f.notice, files: [{ ...f.file, position: 1 }] }, { ...f.notice, files: [{ ...f.file, pdf_bytes: 50 * 1024 * 1024 + 1 }] }, { ...f.notice, expires_at: time }]) expect(() => checkedPublicNotice(value, noticeID)).toThrow();
});
test('read and download bind the exact frozen notice file without private keys or latest fallback', async () => {
 const f = await fixture(), signal = new AbortController().signal;
 const fetcher = (async (url, init) => { expect(String(url)).toBe('/api/v1/notices/' + noticeID + '/files/0'); expect(new Headers(init?.headers).get('If-Match')).toBe(f.headers.get('ETag')); expect(init?.credentials).toBe('include'); expect(init?.cache).toBe('no-store'); expect(init?.redirect).toBe('error'); return new Response(data.slice(), { headers: f.headers }); }) as typeof fetch;
 expect(await fetchNoticePDF(f.notice, f.file, signal, fetcher)).toEqual(data);
 let calls = 0; await expect(fetchNoticePDF(f.notice, { ...f.file, file_version_sha256: 'd'.repeat(64) }, signal, (async () => { calls++; throw Error('not called'); }) as typeof fetch)).rejects.toThrow(); expect(calls).toBe(0);
});
test('all exact notice file headers are checked before consuming any PDF body', async () => {
 const f = await fixture(); for (const name of f.headers.keys()) { let consumed = 0, cancelled = 0; const headers = new Headers(f.headers); headers.set(name, 'wrong'); const fetcher = (async () => new Response(new ReadableStream({ pull(controller) { consumed++; controller.enqueue(data); controller.close(); }, cancel() { cancelled++; } }, { highWaterMark: 0 }), { headers })) as typeof fetch; await expect(fetchNoticePDF(f.notice, f.file, new AbortController().signal, fetcher)).rejects.toThrow(); expect(consumed).toBe(0); expect(cancelled).toBe(1); }
});
test('short, oversized, changed and aborted PDF bytes cannot become a preview', async () => {
 const f = await fixture(); for (const mode of ['short', 'long', 'digest', 'abort'] as const) { const abort = new AbortController(); let sent = false; const body = mode === 'short' ? data.slice(1) : mode === 'long' ? new Uint8Array(data.length + 1) : mode === 'digest' ? new Uint8Array(data.length) : data.slice(); const fetcher = (async () => new Response(new ReadableStream({ pull(controller) { if (sent) { controller.close(); return; } sent = true; controller.enqueue(body); if (mode === 'abort') abort.abort(); } }, { highWaterMark: 0 }), { headers: f.headers })) as typeof fetch; await expect(fetchNoticePDF(f.notice, f.file, abort.signal, fetcher)).rejects.toThrow(noticeUnavailable); }
});
test('revoked access joins body cancellation and never displays provider response text', async () => {
 const f = await fixture(), cancelling = deferred<void>(), started = deferred<void>(); let settled = false;
 const fetcher = (async () => new Response(new ReadableStream({ cancel() { started.resolve(); return cancelling.promise; } }, { highWaterMark: 0 }), { status: 403 })) as typeof fetch;
 const result = fetchNoticePDF(f.notice, f.file, new AbortController().signal, fetcher).finally(() => { settled = true; }); await started.promise; expect(settled).toBe(false); cancelling.resolve(); await expect(result).rejects.toThrow(noticeUnavailable);
});
test('metadata abort cancels a pending body read and oversized JSON is refused', async () => {
 const abort = new AbortController(), started = deferred<void>(); let cancelled = false;
 const fetcher = (async () => new Response(new ReadableStream({ pull() { started.resolve(); }, cancel() { cancelled = true; } }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } })) as typeof fetch;
 const reading = getPublicNotice(noticeID, abort.signal, fetcher); await started.promise; abort.abort(); await expect(reading).rejects.toThrow(); expect(cancelled).toBe(true);
 await expect(getPublicNotice(noticeID, new AbortController().signal, (async () => new Response(' '.repeat(131073), { headers: { 'Content-Type': 'application/json' } })) as typeof fetch)).rejects.toThrow();
});

test('public notice titles use the native512 UTF8 byte bound without broadening file or authority limits', async () => {
 const f = await fixture(); expect(checkedPublicNotice({ ...f.notice, files: [{ ...f.file, title: 'é'.repeat(256) }] }, noticeID).files[0].title.length).toBe(256);
 expect(() => checkedPublicNotice({ ...f.notice, files: [{ ...f.file, title: 'é'.repeat(257) }] }, noticeID)).toThrow();
});
