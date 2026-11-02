import { expect, test } from 'bun:test';
import { fetchVerifiedTemplatePDF, getTemplate } from './api/client';

const id = '3a28a91a-60c8-42c8-a2f5-b133f236387a';
const bytes = new TextEncoder().encode('%PDF synthetic preview transport fixture');
const sha = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
function response(change: Record<string, string> = {}, body: Uint8Array = bytes) {
  return new Response(body, { headers: { 'Content-Type': 'application/pdf', 'X-Hash-Template-Id': id, 'X-Hash-Template-Version': '2', 'X-Hash-PDF-SHA256': sha, ...change } });
}

test('template thumbnails request authenticated immutable pins and verify the actual bytes', async () => {
  const original = globalThis.fetch, controller = new AbortController();
  let request: { input: string; init?: RequestInit } | null = null;
  globalThis.fetch = (async (input, init) => { request = { input: String(input), init }; return response(); }) as typeof fetch;
  try {
    expect(await fetchVerifiedTemplatePDF(id, 2, sha, controller.signal)).toEqual(bytes);
    const captured = request as unknown as { input: string; init: RequestInit };
    expect(captured.input).toBe(`/api/v1/templates/${id}/pdf?version=2&sha256=${sha}`);
    expect(captured.init.credentials).toBe('include'); expect(captured.init.cache).toBe('no-store'); expect(captured.init.signal).toBe(controller.signal);
  } finally { globalThis.fetch = original; }
});

test('changed version, identity, digest or body refuses before PDF parsing', async () => {
  const original = globalThis.fetch;
  try {
    for (const changed of [{ 'X-Hash-Template-Version': '3' }, { 'X-Hash-Template-Id': 'other' }, { 'X-Hash-PDF-SHA256': '0'.repeat(64) }]) {
      globalThis.fetch = (async () => response(changed)) as typeof fetch;
      await expect(fetchVerifiedTemplatePDF(id, 2, sha, new AbortController().signal)).rejects.toThrow('The template changed.');
    }
    globalThis.fetch = (async () => response({}, new TextEncoder().encode('changed'))) as typeof fetch;
    await expect(fetchVerifiedTemplatePDF(id, 2, sha, new AbortController().signal)).rejects.toThrow('The PDF changed.');
    globalThis.fetch = (async () => response({ 'Content-Type': 'text/html' })) as typeof fetch;
    await expect(fetchVerifiedTemplatePDF(id, 2, sha, new AbortController().signal)).rejects.toThrow('The server did not return a PDF.');
  } finally { globalThis.fetch = original; }
});

test('template metadata reads receive the card owner abort signal', async () => {
  const original = globalThis.fetch, controller = new AbortController();
  globalThis.fetch = (async (_input, init) => { expect(init?.signal).toBe(controller.signal); return Response.json({ id }); }) as typeof fetch;
  try { expect((await getTemplate(id, controller.signal)).id).toBe(id); }
  finally { globalThis.fetch = original; }
});
