import { expect, test } from 'bun:test';
import { documentDownloadURL, documentDownloadName, fetchDocumentDownload, type DownloadDocument } from './documentDownload';
const document: DownloadDocument = { id: '10101010-1010-4010-8010-101010101010', name: 'Presentation', source_kind: 'pdf', status: 'draft', updated_at: '2026-11-03T12:00:00.000001Z', pdf_sha256: 'a'.repeat(64) };
test('visual download pins the saved PDF without a recipient or signature request', () => {
  const url = new URL(documentDownloadURL(document), 'https://hash.example');
  expect(url.pathname).toBe(`/api/v1/documents/${document.id}/pdf`);
  expect(url.searchParams.get('expected_updated_at')).toBe(document.updated_at);
  expect(url.searchParams.get('expected_pdf_sha256')).toBe(document.pdf_sha256);
  expect(url.searchParams.get('download')).toBe('1');
  const blockURL = new URL(documentDownloadURL({ ...document, source_kind: 'blocks', pdf_sha256: undefined }), 'https://hash.example');
  expect(blockURL.searchParams.has('expected_pdf_sha256')).toBe(false);
});
test('completed documents select the existing signed artifact, never the unsigned source', () => {
  expect(documentDownloadURL({ ...document, status: 'completed' })).toBe(`/api/v1/documents/${document.id}/final-pdf`);
  expect(documentDownloadName({ ...document, name: '../Offer\\test:\n.pdf' })).toBe('..Offertest.pdf');
  expect(documentDownloadName({ ...document, name: '.pdf' })).toBe('document.pdf');
});
test('the completed evidence download uses its own artifact and never requests the contract', async () => {
  const completed = { ...document, status: 'completed', requires_signature: true };
  expect(documentDownloadURL(completed, 'evidence')).toBe(`/api/v1/documents/${document.id}/audit-cert`);
  expect(documentDownloadName(completed, 'evidence')).toBe('Presentation-audit.pdf');
  expect(() => documentDownloadURL(document, 'evidence')).toThrow('after completion');
  const calls: string[] = [];
  const send = (async input => { calls.push(String(input)); return new Response('', { status: 404 }); }) as typeof fetch;
  await expect(fetchDocumentDownload(completed, new AbortController().signal, send, 'evidence')).rejects.toThrow('evidence report is still being prepared');
  expect(calls).toEqual([`/api/v1/documents/${document.id}/audit-cert`]);
});
test('download uses the authenticated same-origin GET and validates a streamed PDF', async () => {
  const controller = new AbortController(); let options: RequestInit | undefined;
  const send = (async (input, init) => { expect(input).toBe(documentDownloadURL(document)); options = init; return new Response('%PDF-1.7\nsynthetic', { headers: { 'Content-Type': 'application/pdf' } }); }) as typeof fetch;
  const blob = await fetchDocumentDownload(document, controller.signal, send);
  expect(await blob.text()).toBe('%PDF-1.7\nsynthetic');
  expect(options).toEqual({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal, headers: { Accept: 'application/pdf' } });
});
test('errors cannot be downloaded as PDF and private server bodies are not shown', async () => {
  for (const [status, message] of [[401, 'Your session'], [409, 'document changed'], [503, 'Could not download']] as const) {
    const send = (async () => new Response('PRIVATE failure', { status })) as typeof fetch;
    await expect(fetchDocumentDownload(document, new AbortController().signal, send)).rejects.toThrow(message);
  }
  for (const response of [new Response('<html>login</html>', { headers: { 'Content-Type': 'text/html' } }), new Response('wrong', { headers: { 'Content-Type': 'application/pdf' } }), new Response('%PDF-1.7', { headers: { 'Content-Type': 'application/pdf', 'Content-Length': String(101 * 1024 * 1024) } })]) {
    await expect(fetchDocumentDownload(document, new AbortController().signal, (async () => response) as typeof fetch)).rejects.toThrow('valid PDF');
  }
});
test('an aborted read and an unfinished completed artifact never save the unsigned source', async () => {
  const controller = new AbortController(); controller.abort();
  await expect(fetchDocumentDownload(document, controller.signal, (async () => new Response('%PDF-1.7', { headers: { 'Content-Type': 'application/pdf' } })) as typeof fetch)).rejects.toThrow('cancelled');
  await expect(fetchDocumentDownload({ ...document, status: 'completed' }, new AbortController().signal, (async () => new Response('', { status: 404 })) as typeof fetch)).rejects.toThrow('still being prepared');
});
