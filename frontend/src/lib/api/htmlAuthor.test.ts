import { expect, test } from 'bun:test';
import { APIError, approveHTMLTemplate, createHTMLTemplate, previewHTMLTemplate, updateHTMLTemplate } from './client';

const bytes = new TextEncoder().encode('%PDF-1.7 synthetic saved design protocol');
const pdfSHA = new Bun.CryptoHasher('sha256').update(bytes).digest('hex');
function headers() {
  return { 'Content-Type': 'application/pdf', 'X-Hash-Template-Id': 'design', 'X-Hash-Template-Version': '3',
    'X-Hash-Template-Content-SHA256': 'a'.repeat(64), 'X-Hash-Materialization-SHA256': 'b'.repeat(64),
    'X-Hash-PDF-SHA256': pdfSHA, 'X-Hash-PDF-Pages': '2', 'X-Hash-Preview-Receipt': 'session_bound_receipt',
    'X-Hash-Preview-Expires-At': new Date(Date.now() + 600_000).toISOString() };
}
async function mockedFetch(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: () => Response) {
  const original = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options?: RequestInit) => {
    calls.push({ path: String(path), options: options ?? {} }); return respond();
  }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}
test('author create/update persist structured source and defaults on exact routes with optimistic revision', async () => {
  const input = { name: 'Design', html_master_json: { schema_version: 1, html: '<p></p>', css: '', values: [] }, variables_json: {} } as const;
  await mockedFetch(async (calls) => {
    await createHTMLTemplate(input); await updateHTMLTemplate('design', 3, input);
    expect(calls.map((call) => [call.path, call.options.method, call.options.credentials])).toEqual([
      ['/api/v1/templates/html', 'POST', 'include'], ['/api/v1/templates/design/html', 'PATCH', 'include']]);
    expect(JSON.parse(calls[0].options.body as string)).toEqual(input);
    expect(JSON.parse(calls[1].options.body as string)).toEqual({ ...input, expected_version: 3 });
  }, () => Response.json({}));
});
test('preview verifies exact saved revision metadata and bytes; samples stay separate from defaults and sections', async () => {
  let phase = 0;
  await mockedFetch(async (calls) => {
    const signal = new AbortController().signal;
    const result = await previewHTMLTemplate('design', 3, 'a'.repeat(64), { company: 'Sample <AB>' }, signal);
    expect(result).toMatchObject({ bytes, templateID: 'design', version: 3, contentSHA256: 'a'.repeat(64),
      materializationSHA256: 'b'.repeat(64), pdfSHA256: pdfSHA, pages: 2, receipt: 'session_bound_receipt' });
    expect(calls[0].options).toMatchObject({ method: 'POST', credentials: 'include', cache: 'no-store', signal });
    expect(JSON.parse(calls[0].options.body as string)).toEqual({ expected_version: 3, expected_content_sha256: 'a'.repeat(64), values: { company: 'Sample <AB>' } });
    await approveHTMLTemplate('design', 3, 'a'.repeat(64), result);
    expect(calls[1].path).toBe('/api/v1/templates/design/html/approve');
    expect(JSON.parse(calls[1].options.body as string)).toEqual({ expected_version: 3, expected_content_sha256: 'a'.repeat(64),
      preview_receipt: 'session_bound_receipt', expected_preview_pdf_sha256: pdfSHA });
  }, () => ++phase === 1 ? new Response(bytes, { headers: headers() }) : Response.json({}));
});
test('preview refuses mismatched, malformed, missing or expired receipt metadata before consuming PDF bytes', async () => {
  const mutations: [string, string | null][] = [
    ['X-Hash-Template-Id', 'other'], ['X-Hash-Template-Version', '03'], ['X-Hash-Template-Content-SHA256', 'c'.repeat(64)],
    ['X-Hash-Materialization-SHA256', 'not-a-digest'], ['X-Hash-PDF-SHA256', null], ['X-Hash-PDF-Pages', '501'],
    ['X-Hash-PDF-Pages', '2.0'], ['X-Hash-PDF-Pages', '0'], ['X-Hash-Preview-Receipt', 'bad receipt'],
    ['X-Hash-Preview-Receipt', 'a'.repeat(8193)], ['X-Hash-Preview-Receipt', null], ['X-Hash-Preview-Expires-At', new Date(0).toISOString()],
  ];
  for (const [key, value] of mutations) {
    let canceled = false;
    await mockedFetch(async () => {
      await expect(previewHTMLTemplate('design', 3, 'a'.repeat(64), {}, new AbortController().signal)).rejects.toThrow('does not match');
      expect(canceled).toBe(true);
    }, () => {
      const current = new Headers(headers()); if (value === null) current.delete(key); else current.set(key, value);
      return new Response(new ReadableStream({ cancel() { canceled = true; } }), { headers: current });
    });
  }
});
test('preview refuses changed/error/oversized PDF bytes and forwards authorization failures', async () => {
  for (const response of [
    () => new Response('different', { headers: headers() }),
    () => new Response('<h1>Login</h1>', { headers: { ...headers(), 'Content-Type': 'text/html' } }),
  ]) await mockedFetch(async () => {
    await expect(previewHTMLTemplate('design', 3, 'a'.repeat(64), {}, new AbortController().signal)).rejects.toThrow();
  }, response);
  let canceled = false; const chunk = new Uint8Array(2 * 1024 * 1024);
  await mockedFetch(async () => {
    await expect(previewHTMLTemplate('design', 3, 'a'.repeat(64), {}, new AbortController().signal)).rejects.toThrow('preview limit');
    expect(canceled).toBe(true);
  }, () => new Response(new ReadableStream({ pull(controller) { controller.enqueue(chunk); }, cancel() { canceled = true; } }), { headers: headers() }));
  await mockedFetch(async () => {
    try { await previewHTMLTemplate('design', 3, 'a'.repeat(64), {}, new AbortController().signal); throw new Error('accepted'); }
    catch (e) { expect(e).toBeInstanceOf(APIError); expect((e as APIError).status).toBe(401); }
  }, () => Response.json({ error: 'expired' }, { status: 401 }));
});
