import type { DocumentResponse } from './api/client';

const maxPDFBytes = 100 * 1024 * 1024;
export type DownloadDocument = Pick<DocumentResponse, 'id' | 'name' | 'status' | 'source_kind' | 'updated_at' | 'pdf_sha256' | 'requires_signature'>;
export type DocumentDownloadKind = 'pdf' | 'evidence';

export function documentDownloadURL(document: DownloadDocument, kind: DocumentDownloadKind = 'pdf'): string {
  const id = encodeURIComponent(document.id);
  if (kind === 'evidence') {
    if (document.status !== 'completed') throw new Error('The evidence report is available after completion.');
    return `/api/v1/documents/${id}/audit-cert`;
  }
  if (document.status === 'completed') return `/api/v1/documents/${id}/final-pdf`;
  const query = new URLSearchParams({ download: '1', expected_updated_at: document.updated_at });
  if (document.pdf_sha256) query.set('expected_pdf_sha256', document.pdf_sha256);
  return `/api/v1/documents/${id}/pdf?${query}`;
}

export function documentDownloadName(document: DownloadDocument, kind: DocumentDownloadKind = 'pdf'): string {
  const name = document.name.replace(/[\u0000-\u001f\u007f/\\:*?"<>|]/g, '').trim().replace(/\.pdf$/i, '').slice(0, 160);
  return (name || 'document') + (kind === 'evidence' ? '-audit.pdf' : '.pdf');
}

export async function fetchDocumentDownload(document: DownloadDocument, signal: AbortSignal, send: typeof fetch = fetch, kind: DocumentDownloadKind = 'pdf'): Promise<Blob> {
  const response = await send(documentDownloadURL(document, kind), { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal, headers: { Accept: 'application/pdf' } });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Your session has expired. Please sign in again.');
    if (response.status === 409) throw new Error('The document changed. Reload it before downloading.');
    if (response.status === 404 && document.status === 'completed') throw new Error(kind === 'evidence' ? 'The evidence report is still being prepared. Try again shortly.' : 'The completed PDF is still being prepared. Try again shortly.');
    throw new Error('Could not download the PDF. Try again.');
  }
  const length = response.headers.get('Content-Length');
  if (!response.headers.get('Content-Type')?.toLowerCase().startsWith('application/pdf') || (length !== null && (!/^\d+$/.test(length) || Number(length) > maxPDFBytes)) || !response.body) {
    await response.body?.cancel(); throw new Error('Could not download a valid PDF.');
  }
  const reader = response.body.getReader(), chunks: Uint8Array<ArrayBuffer>[] = [];
  let size = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error('Download cancelled.');
      const { value, done } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > maxPDFBytes) throw new Error('The PDF is too large to download here.');
      chunks.push(value as Uint8Array<ArrayBuffer>);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const result = new Blob(chunks, { type: 'application/pdf' });
  if (signal.aborted || await result.slice(0, 5).text() !== '%PDF-') throw new Error('Could not download a valid PDF.');
  return result;
}
