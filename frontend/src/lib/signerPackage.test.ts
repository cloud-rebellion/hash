import { describe, expect, test } from 'bun:test';
import { AttachmentPreviewFamily } from './documentAttachmentPreview';
import { checkedSignerPackage, fetchSignerPackage, fetchSignerPackagePDF, SignerPackagePreviewController,
  signerPackageResponse, type SignerPackage, type SignerPackageScope } from './signerPackage';

const hash = async (bytes: Uint8Array) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
const encode = (text: string) => new TextEncoder().encode(text);
const main = encode('%PDF main'), annex = encode('%PDF annex');
const mainSHA = await hash(main), annexSHA = await hash(annex);
const text = 'I agree to the listed main document and attachments.';
const copySHA = await hash(encode(text));
const scope: SignerPackageScope = { token: 'original/token', key: 'current-ceremony',
  documentID: '10000000-0000-4000-8000-000000000001', recipientID: '20000000-0000-4000-8000-000000000001', noticeDigest: 'd'.repeat(64),
  observation: { document_id: '10000000-0000-4000-8000-000000000001', recipient_id: '20000000-0000-4000-8000-000000000001', pdf_sha256: mainSHA } };
const value: SignerPackage = { schema: 'hash-recipient-package-v1', package_id: '30000000-0000-4000-8000-000000000001', revision: '9223372036854775807',
  manifest_sha256: 'a'.repeat(64), legal_commitment_sha256: 'b'.repeat(64),
  main: { title: 'Agreement', category: 'Contract', pdf_sha256: mainSHA, bytes: main.length, pages: 1 },
  annexes: [{ title: 'DPA', category: 'Data processing', pdf_sha256: annexSHA, bytes: annex.length, pages: 2 }],
  incorporation: { version: 'hash-package-incorporation-v1', sha256: copySHA, text } };
function headers(type = 'application/json') {
  return new Headers({ 'Content-Type': type, 'X-Hash-Document-Id': scope.documentID, 'X-Hash-Recipient-Id': scope.recipientID, 'X-Hash-Notice-Digest': scope.noticeDigest });
}
function pdfHeaders() {
  const h = headers('application/pdf');
  for (const [key, v] of Object.entries({ ETag: `"${value.manifest_sha256}.${value.legal_commitment_sha256}"`, 'Content-Length': String(annex.length),
    'X-Hash-Package-Manifest-SHA256': value.manifest_sha256, 'X-Hash-Package-Legal-Commitment-SHA256': value.legal_commitment_sha256,
    'X-Hash-Package-Member-Position': '1', 'X-Hash-PDF-SHA256': annexSHA, 'X-Hash-PDF-Bytes': String(annex.length), 'X-Hash-PDF-Pages': '2' })) h.set(key, v);
  return h;
}
const fetcher = (fn: () => Response | Promise<Response>) => fn as typeof fetch;
function deferred<T>() { let resolve!: (v: T) => void, reject!: (e: unknown) => void; const promise = new Promise<T>((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; }
const flush = async () => { for (let i=0;i<16;i++) await Promise.resolve(); };

describe('recipient package identity and consent', () => {
  test('binds the main PDF observation, retains exact int64 revisions and sends only public consent commitments', () => {
    const result = checkedSignerPackage({ package: value }, scope)!;
    expect(result.revision).toBe('9223372036854775807');
    expect(Object.isFrozen(result)).toBe(true); expect(Object.isFrozen(result.annexes[0])).toBe(true);
    expect(checkedSignerPackage({ package: null }, scope)).toBeNull();
    expect(signerPackageResponse(result)).toEqual({ manifest_sha256: value.manifest_sha256, legal_commitment_sha256: value.legal_commitment_sha256,
      incorporation_version: value.incorporation.version, incorporation_sha256: copySHA, consent: true });
    for (const invalid of [undefined, {}, { package: { ...value, revision: 1 } }, { package: { ...value, revision: '9223372036854775808' } },
      { package: { ...value, main: { ...value.main, pdf_sha256: annexSHA } } },
      { package: { ...value, annexes: [{ ...value.annexes[0], pages: 500 }] } },
      { package: { ...value, annexes: [{ ...value.annexes[0], bytes: 50 * 1024 * 1024 }] } },
      { package: { ...value, annexes: [{ ...value.annexes[0], title: 'DPA\nInjected' }] } }]) expect(() => checkedSignerPackage(invalid, scope)).toThrow();
    expect(() => checkedSignerPackage({ package: value }, { ...scope, recipientID: scope.documentID })).toThrow();
  });
  test('metadata checks recipient, notice and copy digest before exposing consent; uses the original encoded token', async () => {
    const signal = new AbortController().signal; let call: unknown[] = [];
    const result = await fetchSignerPackage(scope, signal, (async (...args: unknown[]) => { call=args; return new Response(JSON.stringify({ package: value }), { headers: headers() }); }) as typeof fetch);
    expect(result).toEqual(value);
    expect(call).toEqual(['/sign/original%2Ftoken/package', { signal, cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } }]);
    for (const key of ['X-Hash-Document-Id', 'X-Hash-Recipient-Id', 'X-Hash-Notice-Digest']) {
      const h = headers(); h.delete(key);
      await expect(fetchSignerPackage(scope, signal, fetcher(() => new Response(JSON.stringify({ package: null }), { headers: h })))).rejects.toThrow();
    }
    await expect(fetchSignerPackage(scope, signal, fetcher(() => new Response(JSON.stringify({ package: { ...value, incorporation: { ...value.incorporation, text: 'Different consent' } } }), { headers: headers() })))).rejects.toThrow();
    await expect(fetchSignerPackage(scope, signal, fetcher(() => new Response(new Uint8Array(65537), { headers: headers() })))).rejects.toThrow();
  });
});

describe('recipient annex transport', () => {
  test('checks exact member pins, scope, ETag, bytes and digest before returning a PDF', async () => {
    const signal = new AbortController().signal; let call: unknown[] = [];
    const result = await fetchSignerPackagePDF(scope, value, 1, signal, (async (...args: unknown[]) => { call=args; return new Response(annex, { headers: pdfHeaders() }); }) as typeof fetch);
    expect(result).toEqual(annex);
    expect(call).toEqual(['/sign/original%2Ftoken/package/members/1/pdf', { signal, cache: 'no-store', credentials: 'same-origin',
      headers: { Accept: 'application/pdf', 'If-Match': `"${value.manifest_sha256}.${value.legal_commitment_sha256}"` } }]);
    for (const key of ['ETag', 'Content-Length', 'X-Hash-Package-Member-Position', 'X-Hash-Package-Legal-Commitment-SHA256', 'X-Hash-PDF-Pages', 'X-Hash-Notice-Digest']) {
      const h = pdfHeaders(); h.set(key, 'wrong');
      await expect(fetchSignerPackagePDF(scope, value, 1, signal, fetcher(() => new Response(annex, { headers: h })))).rejects.toThrow();
    }
    const h = pdfHeaders(); h.set('X-Hash-HTML-Source-Commitment', 'c'.repeat(64));
    await expect(fetchSignerPackagePDF(scope, value, 1, signal, fetcher(() => new Response(annex, { headers: h })))).rejects.toThrow();
    for (const body of [annex.subarray(1), new Uint8Array(annex.length + 1), new Uint8Array(annex.length)]) {
      await expect(fetchSignerPackagePDF(scope, value, 1, signal, fetcher(() => new Response(body, { headers: pdfHeaders() })))).rejects.toThrow();
    }
  });
  test('cancels the actual streaming body on abort and a late fetch response after route retirement', async () => {
    let canceled=0; const controller=new AbortController();
    const response=new Response(new ReadableStream({ start(c) { c.enqueue(annex.subarray(0,1)); }, cancel() { canceled++; } }), { headers: pdfHeaders() });
    const pending=fetchSignerPackagePDF(scope,value,1,controller.signal,fetcher(()=>response));
    await flush(); controller.abort(); await expect(pending).rejects.toThrow(); expect(canceled).toBe(1);
    const late=deferred<Response>(), next=new AbortController(); let lateCanceled=0;
    const waiting=fetchSignerPackagePDF(scope,value,1,next.signal,fetcher(()=>late.promise)); next.abort();
    late.resolve(new Response(new ReadableStream({ cancel() { lateCanceled++; } }), { headers: pdfHeaders() }));
    await expect(waiting).rejects.toThrow(); expect(lateCanceled).toBe(1);
  });
});

describe('recipient attachment view ownership', () => {
  test('joins a late canceled fetch, zeros its bytes and admits only the latest replacement', async () => {
    const pending=deferred<Uint8Array>(); let calls=0;
    const c=new SignerPackagePreviewController(async()=> ++calls===1?pending.promise:new Uint8Array([4,5,6]),async()=>{},()=>{},new AttachmentPreviewFamily());
    const first=c.open(scope,value,1); await flush(); const second=c.open(scope,value,1), third=c.open(scope,value,1);
    await flush(); expect(calls).toBe(1); const stale=new Uint8Array([1,2,3]); pending.resolve(stale);
    await Promise.all([first,second,third]); expect(calls).toBe(2); expect([...stale]).toEqual([0,0,0]);
    expect([...c.state.selection!.bytes]).toEqual([4,5,6]); await c.dispose();
  });
  test('keeps the old bytes until actual child retirement and blocks a new route until it settles', async () => {
    const retirement=deferred<void>(), family=new AttachmentPreviewFamily(); let calls=0;
    const old=new SignerPackagePreviewController(async()=>new Uint8Array([1,2,3]),async()=>{},()=>{},family);
    await old.open(scope,value,1); const bytes=old.state.selection!.bytes; old.observeRetirement(retirement.promise);
    const disposing=old.dispose();
    const next=new SignerPackagePreviewController(async()=>{calls++;return new Uint8Array([4,5,6]);},async()=>{},()=>{},family);
    const opening=next.open(scope,value,1); await flush(); expect(calls).toBe(0); expect([...bytes]).toEqual([1,2,3]);
    retirement.resolve(); await Promise.all([disposing,opening]); expect([...bytes]).toEqual([0,0,0]); expect(calls).toBe(1); await next.dispose();
  });
  test('a rejected PDF destruction remains closed across route replacement', async () => {
    const retirement=deferred<void>(), family=new AttachmentPreviewFamily(); let calls=0;
    const old=new SignerPackagePreviewController(async()=>new Uint8Array([1,2,3]),async()=>{},()=>{},family);
    await old.open(scope,value,1); old.observeRetirement(retirement.promise); const disposing=old.dispose();
    const next=new SignerPackagePreviewController(async()=>{calls++;return new Uint8Array([4,5,6]);},async()=>{},()=>{},family);
    const opening=next.open(scope,value,1); retirement.reject(Error('actual worker retirement failed'));
    await disposing.catch(()=>{}); await opening; expect(calls).toBe(0); expect(next.state.blocked).toBe(true);
    await next.open(scope,value,1); expect(calls).toBe(0); await next.dispose().catch(()=>{});
  });
});
