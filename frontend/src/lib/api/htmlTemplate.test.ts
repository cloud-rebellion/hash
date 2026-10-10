import { expect, test } from 'bun:test';
import { createHTMLTemplateDocument, fetchVerifiedDocumentPDF, reviewHTMLDocument, APIError } from './client';

async function mockedFetch(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: (path: string, options: RequestInit) => Response) {
  const original = globalThis.fetch;
  const calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options?: RequestInit) => {
    calls.push({ path: String(path), options: options ?? {} });
    return respond(String(path), options ?? {});
  }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}

test('HTML creation uses its exact-pinned route and always omits new section prose; review sends observed PDF pins', async () => {
  await mockedFetch(async (calls) => {
    await createHTMLTemplateDocument('design', { name: 'Reviewed customer draft', expected_template_version: 3,
      expected_template_content_sha256: 'a'.repeat(64), values: { customer: '<AB> & Co' }, sections: { scope: 'New prose must not dispatch' } } as any);
    expect(calls[0].path).toBe('/api/v1/templates/design/html/documents');
    expect(calls[0].options.credentials).toBe('include');
    expect(JSON.parse(calls[0].options.body as string)).toEqual({ name: 'Reviewed customer draft', expected_template_version: 3,
      expected_template_content_sha256: 'a'.repeat(64), values: { customer: '<AB> & Co' } });
    await reviewHTMLDocument('document', 'observed-nanosecond-timestamp', 'b'.repeat(64));
    expect(calls[1].path).toBe('/api/v1/documents/document/html/review');
    expect(JSON.parse(calls[1].options.body as string)).toEqual({ expected_updated_at: 'observed-nanosecond-timestamp', expected_pdf_sha256: 'b'.repeat(64) });
  }, () => Response.json({}));
});

test('PDF preview authenticates and returns only bytes matching the observed SHA, refusing changed bytes and error HTML', async () => {
  const bytes = new TextEncoder().encode('%PDF-1.7 synthetic digest protocol');
  const digest = new Bun.CryptoHasher('sha256').update(bytes).digest('hex');
  await mockedFetch(async (calls) => {
    const signal = new AbortController().signal;
    expect(await fetchVerifiedDocumentPDF('document', digest, signal)).toEqual(bytes);
    expect(calls[0].options).toMatchObject({ credentials: 'include', cache: 'no-store', signal });
    await expect(fetchVerifiedDocumentPDF('document', '0'.repeat(64), signal)).rejects.toThrow('PDF changed');
  }, () => new Response(bytes, { headers: { 'Content-Type': 'application/pdf' } }));
  await mockedFetch(async () => {
    await expect(fetchVerifiedDocumentPDF('document', digest, new AbortController().signal)).rejects.toThrow('did not return a PDF');
  }, () => new Response('<h1>Sign in</h1>', { headers: { 'Content-Type': 'text/html' } }));
  await mockedFetch(async () => {
    try { await fetchVerifiedDocumentPDF('document', digest, new AbortController().signal); throw new Error('accepted expired session'); }
    catch (e) { expect(e).toBeInstanceOf(APIError); expect((e as APIError).status).toBe(401); }
  }, () => Response.json({ error: 'expired' }, { status: 401 }));
});

test('PDF preview bounds streamed input before allocating a full oversized artifact', async () => {
  let canceled = false;
  const chunk = new Uint8Array(2 * 1024 * 1024);
  await mockedFetch(async () => {
    await expect(fetchVerifiedDocumentPDF('document', 'a'.repeat(64), new AbortController().signal)).rejects.toThrow('preview limit');
    expect(canceled).toBe(true);
  }, () => new Response(new ReadableStream({ pull(controller) { controller.enqueue(chunk); }, cancel() { canceled = true; } }),
    { headers: { 'Content-Type': 'application/pdf' } }));
});
