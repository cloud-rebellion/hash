import { expect, test } from 'bun:test';
import { addField, deleteField, fetchVerifiedHTMLRevisionPDF, getHTMLDocumentHistory, getHTMLDocumentSource, getHTMLRevisionSource, reviewHTMLDocument, reviseHTMLDocument, type HTMLDocumentSource } from './client';

async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, reply: () => Response) {
  const original = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options?: RequestInit) => { calls.push({ path: String(path), options: options ?? {} }); return reply(); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}
const pins = { expected_pdf_sha256: 'b'.repeat(64), expected_html_source_commitment: 'a'.repeat(64) };
test('HTML revision/source/history routes and review/placement writes carry exact observed source pins', async () => {
  await mocked(async (calls) => {
    await getHTMLDocumentSource('doc'); await getHTMLDocumentHistory('doc'); await getHTMLRevisionSource('doc', 4);
    const body = { expected_updated_at: '2026-10-10T06:00:00.000000123Z', expected_html_source_commitment: pins.expected_html_source_commitment,
      values: { company: '<AB> & Co' }, sections: { scope: 'Human-reviewed wording' }, summary: 'Negotiated scope' };
    await reviseHTMLDocument('doc', body); await reviewHTMLDocument('doc', body.expected_updated_at, pins.expected_pdf_sha256, pins.expected_html_source_commitment);
    await addField('doc', { type: 'signature', page: 1, x_pct: 5, y_pct: 5, w_pct: 20, h_pct: 5, ...pins }); await deleteField('field', pins);
    await deleteField('static-field');
    expect(calls.map((c) => c.path)).toEqual(['/api/v1/documents/doc/html/source', '/api/v1/documents/doc/html/history', '/api/v1/documents/doc/html/revisions/4/source',
      '/api/v1/documents/doc/html/revisions', '/api/v1/documents/doc/html/review', '/api/v1/documents/doc/fields', '/api/v1/fields/field', '/api/v1/fields/static-field']);
    expect(JSON.parse(calls[3].options.body as string)).toEqual(body);
    expect(JSON.parse(calls[4].options.body as string)).toEqual({ expected_updated_at: body.expected_updated_at, ...pins });
    expect(JSON.parse(calls[5].options.body as string)).toMatchObject(pins);
    expect(JSON.parse(calls[6].options.body as string)).toEqual(pins);
    expect(calls[6].options.method).toBe('DELETE'); expect(calls[7].options.body).toBeUndefined();
    expect(calls.every((c) => c.options.credentials === 'include')).toBe(true);
  }, () => Response.json({}));
});

test('historical PDF validates all revision headers and exact bytes before exposing them to the renderer', async () => {
  const bytes = new TextEncoder().encode('%PDF-1.7 historical protocol fixture');
  const source = { document_id: 'doc', materialization_revision: 3, html_source_commitment: 'a'.repeat(64),
    pdf_sha256: new Bun.CryptoHasher('sha256').update(bytes).digest('hex'), page_count: 2 } as HTMLDocumentSource;
  const headers = { 'Content-Type': 'application/pdf', 'X-Hash-Document-Id': 'doc', 'X-Hash-Materialization-Revision': '3',
    'X-Hash-HTML-Source-Commitment': source.html_source_commitment, 'X-Hash-PDF-SHA256': source.pdf_sha256, 'X-Hash-PDF-Pages': '2' };
  await mocked(async (calls) => {
    const signal = new AbortController().signal;
    expect(await fetchVerifiedHTMLRevisionPDF('doc', source, signal)).toEqual(bytes);
    expect(calls[0].path).toBe('/api/v1/documents/doc/html/revisions/3/pdf');
    expect(calls[0].options).toMatchObject({ credentials: 'include', cache: 'no-store', signal });
  }, () => new Response(bytes, { headers }));
  for (const name of Object.keys(headers)) {
    await mocked(async () => { await expect(fetchVerifiedHTMLRevisionPDF('doc', source, new AbortController().signal)).rejects.toThrow(); },
      () => new Response(bytes, { headers: { ...headers, [name]: 'incorrect' } }));
  }
  await mocked(async () => { await expect(fetchVerifiedHTMLRevisionPDF('doc', source, new AbortController().signal)).rejects.toThrow('PDF changed'); },
    () => new Response(new TextEncoder().encode('%PDF changed'), { headers }));
  await mocked(async (calls) => {
    for (const invalid of [{ ...source, document_id: 'other' }, { ...source, materialization_revision: 0 }, { ...source, materialization_revision: 1.1 }]) {
      await expect(fetchVerifiedHTMLRevisionPDF('doc', invalid, new AbortController().signal)).rejects.toThrow('valid immutable');
    }
    await expect(getHTMLRevisionSource('doc', -1)).rejects.toThrow('valid immutable'); expect(calls).toEqual([]);
  }, () => Response.json({}));
});

test('historical PDF refuses unbounded streamed content and cancels the body', async () => {
  let canceled = false;
  const source = { document_id: 'doc', materialization_revision: 1, html_source_commitment: 'a'.repeat(64), pdf_sha256: 'b'.repeat(64), page_count: 1 } as HTMLDocumentSource;
  await mocked(async () => { await expect(fetchVerifiedHTMLRevisionPDF('doc', source, new AbortController().signal)).rejects.toThrow('preview limit'); expect(canceled).toBe(true); },
    () => new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(2 * 1024 * 1024)); }, cancel() { canceled = true; } }), { headers: {
      'Content-Type': 'application/pdf', 'X-Hash-Document-Id': 'doc', 'X-Hash-Materialization-Revision': '1', 'X-Hash-HTML-Source-Commitment': source.html_source_commitment,
      'X-Hash-PDF-SHA256': source.pdf_sha256, 'X-Hash-PDF-Pages': '1' } }));
});
