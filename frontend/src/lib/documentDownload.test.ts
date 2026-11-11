import { expect, test } from 'bun:test';
import { canExportEvidencePackage, documentDownloadURL, documentDownloadName, fetchDocumentDownload, type DownloadDocument } from './documentDownload';
const document: DownloadDocument = { id: '10101010-1010-4010-8010-101010101010', name: 'Presentation', source_kind: 'pdf', status: 'draft', updated_at: '2026-11-03T12:00:00.000001Z', pdf_sha256: 'a'.repeat(64) };
test('N3: the document id is encoded exactly once', () => {
  const odd = { ...document, id: 'a b/c', status: 'completed' };
  for (const kind of ['pdf', 'evidence'] as const) {
    const url = documentDownloadURL(odd, kind);
    expect(url).toContain('/api/v1/documents/a%20b%2Fc/');
    expect(url).not.toContain('%25');
  }
  expect(documentDownloadURL({ ...odd, status: 'draft' })).toContain('/api/v1/documents/a%20b%2Fc/pdf?');
});

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

const completed: DownloadDocument = { ...document, status: 'completed', requires_signature: true };
const zip = Uint8Array.of(0x50, 0x4b, 0x03, 0x04, 0x01);
test('evidence package export permits only completed roots before issuing any request', async () => {
  for (const parent_envelope_id of [undefined, null]) {
    const root = { ...completed, parent_envelope_id };
    expect(canExportEvidencePackage(root)).toBe(true);
    expect(documentDownloadURL(root, 'package')).toBe(`/api/v1/documents/${document.id}/evidence-bundle`);
  }
  let requests = 0;
  for (const blocked of [{ ...completed, parent_envelope_id: 'parent' }, ...['draft', 'sent', 'finalizing', 'voided', 'declined', 'unknown'].map(status => ({ ...completed, status }))]) {
    expect(canExportEvidencePackage(blocked)).toBe(false);
    await expect(fetchDocumentDownload(blocked, new AbortController().signal, (async () => { requests++; throw Error('Must not fetch'); }) as typeof fetch, 'package')).rejects.toThrow('completed main document');
  }
  expect(requests).toBe(0);
  expect(documentDownloadURL({ ...completed, id: 'a b/c' }, 'package')).toContain('/a%20b%2Fc/evidence-bundle');
});
test('evidence package PDF and ZIP retain same-origin request fences and use the validated type for their filename', async () => {
  for (const [type, bytes, extension] of [['application/pdf', '%PDF-1.7\nfixture', '.pdf'], ['application/zip', zip, '.zip']] as const) {
    const signal = new AbortController().signal; let requests = 0;
    const send = (async (input, options) => {
      requests++; expect(input).toBe(`/api/v1/documents/${document.id}/evidence-bundle`);
      expect(options).toEqual({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal, headers: { Accept: 'application/pdf, application/zip' } });
      return new Response(bytes, { headers: { 'Content-Type': type + '; charset=binary', 'Content-Disposition': 'attachment; filename="untrusted.exe"' } });
    }) as typeof fetch;
    const blob = await fetchDocumentDownload(completed, signal, send, 'package');
    expect(blob.type).toBe(type); expect(blob.size).toBeGreaterThan(0); expect(requests).toBe(1);
    expect(documentDownloadName({ ...completed, name: '../Contract\\test:\n.pdf' }, 'package', blob.type)).toBe('..Contracttest-evidence' + extension);
  }
  expect(() => documentDownloadName(completed, 'package')).toThrow('valid evidence package');
  expect(() => documentDownloadName(completed, 'package', 'text/html')).toThrow('valid evidence package');
  expect(documentDownloadName(completed, 'evidence', 'application/zip')).toBe('Presentation-audit.pdf');
});
test('evidence package failures explain plan access without exposing bodies or falling back to another artifact', async () => {
  for (const [status, message] of [[401, 'Your session'], [402, 'Your plan does not include evidence package export'], [403, 'permission'], [404, 'unavailable for this document or installation'], [409, 'Reload it'], [503, 'Could not export']] as const) {
    let cancelled = 0; const paths: string[] = [];
    const body = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('PRIVATE database/credential details')); }, cancel() { cancelled++; } });
    const send = (async input => { paths.push(String(input)); return new Response(body, { status }); }) as typeof fetch;
    const error = await fetchDocumentDownload(completed, new AbortController().signal, send, 'package').catch(error => error as Error);
    expect(error).toBeInstanceOf(Error); expect((error as Error).message).toContain(message); expect((error as Error).message).not.toContain('PRIVATE');
    expect(paths).toEqual([`/api/v1/documents/${document.id}/evidence-bundle`]); expect(cancelled).toBe(1);
  }
});
test('evidence package MIME and magic must agree and invalid declarations are refused', async () => {
  for (const response of [
    new Response('%PDF-1.7', { headers: { 'Content-Type': 'text/html' } }),
    new Response(zip, { headers: { 'Content-Type': 'application/pdf' } }),
    new Response('%PDF-1.7', { headers: { 'Content-Type': 'application/zip' } }),
    new Response('not a zip', { headers: { 'Content-Type': 'application/zip' } }),
    new Response(zip, { headers: { 'Content-Type': 'application/zip-extra' } }),
    new Response(zip, { headers: { 'Content-Type': 'application/zip', 'Content-Length': String(160 * 1024 * 1024 + 1) } }),
    new Response(zip, { headers: { 'Content-Type': 'application/zip', 'Content-Length': 'invalid' } }),
  ]) await expect(fetchDocumentDownload(completed, new AbortController().signal, (async () => response) as typeof fetch, 'package')).rejects.toThrow('valid evidence package');
  // The existing PDF/certificate ceiling remains 100MiB; only packages get 160MiB.
  const send = (async () => new Response('%PDF-1.7', { headers: { 'Content-Type': 'application/pdf', 'Content-Length': String(101 * 1024 * 1024) } })) as typeof fetch;
  expect((await fetchDocumentDownload(completed, new AbortController().signal, send, 'package')).type).toBe('application/pdf');
  await expect(fetchDocumentDownload(completed, new AbortController().signal, send, 'pdf')).rejects.toThrow('valid PDF');
});
test('package streaming enforces its byte ceiling even with no trustworthy length and cancels the reader', async () => {
  const chunk = new Uint8Array(8 * 1024 * 1024); chunk.set(zip); let cancelled = 0;
  const body = new ReadableStream({ pull(controller) { controller.enqueue(chunk); }, cancel() { cancelled++; } });
  const send = (async () => new Response(body, { headers: { 'Content-Type': 'application/zip', 'Content-Length': '5' } })) as typeof fetch;
  await expect(fetchDocumentDownload(completed, new AbortController().signal, send, 'package')).rejects.toThrow('too large');
  expect(cancelled).toBe(1); expect(body.locked).toBe(false);
});
test('an aborted package stream is cancelled and cannot yield a downloadable blob', async () => {
  const controller = new AbortController(); let cancelled = 0;
  const body = new ReadableStream({ pull(stream) { controller.abort(); stream.enqueue(zip); }, cancel() { cancelled++; } });
  await expect(fetchDocumentDownload(completed, controller.signal, (async () => new Response(body, { headers: { 'Content-Type': 'application/zip' } })) as typeof fetch, 'package')).rejects.toThrow('cancelled');
  expect(cancelled).toBe(1); expect(body.locked).toBe(false);
});
