import type { DocumentResponse } from './api/client';

const maxPDFBytes = 100 * 1024 * 1024;
const maxEvidencePackageBytes = 160 * 1024 * 1024;
export type DownloadDocument = Pick<DocumentResponse, 'id' | 'name' | 'status' | 'source_kind' | 'updated_at' | 'pdf_sha256' | 'requires_signature' | 'parent_envelope_id'>;
export type DocumentDownloadKind = 'pdf' | 'evidence' | 'package';

export function canExportEvidencePackage(document: DownloadDocument): boolean {
  return document.status === 'completed' && document.parent_envelope_id == null;
}

export function documentDownloadURL(document: DownloadDocument, kind: DocumentDownloadKind = 'pdf'): string {
  if (kind === 'package') {
    if (!canExportEvidencePackage(document)) throw new Error('The evidence package is available only for a completed main document.');
    return `/api/v1/documents/${encodeURIComponent(document.id)}/evidence-bundle`;
  }
  if (kind === 'evidence') {
    if (document.status !== 'completed') throw new Error('The evidence report is available after completion.');
    return `/api/v1/documents/${encodeURIComponent(document.id)}/audit-cert`;
  }
  if (document.status === 'completed') return `/api/v1/documents/${encodeURIComponent(document.id)}/final-pdf`;
  const query = new URLSearchParams({ download: '1', expected_updated_at: document.updated_at });
  if (document.pdf_sha256) query.set('expected_pdf_sha256', document.pdf_sha256);
  return `/api/v1/documents/${encodeURIComponent(document.id)}/pdf?${query}`;
}

export function documentDownloadName(document: DownloadDocument, kind: DocumentDownloadKind = 'pdf', contentType?: string): string {
  const name = document.name.replace(/[\u0000-\u001f\u007f/\\:*?"<>|]/g, '').trim().replace(/\.pdf$/i, '').slice(0, 160);
  if (kind === 'package') {
    if (contentType !== 'application/pdf' && contentType !== 'application/zip') throw new Error('Could not download a valid evidence package.');
    return (name || 'document') + (contentType === 'application/zip' ? '-evidence.zip' : '-evidence.pdf');
  }
  return (name || 'document') + (kind === 'evidence' ? '-audit.pdf' : '.pdf');
}

export async function fetchDocumentDownload(document: DownloadDocument, signal: AbortSignal, send: typeof fetch = fetch, kind: DocumentDownloadKind = 'pdf'): Promise<Blob> {
  const packageDownload = kind === 'package';
  const response = await send(documentDownloadURL(document, kind), { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal, headers: { Accept: packageDownload ? 'application/pdf, application/zip' : 'application/pdf' } });
  if (!response.ok) {
    if (packageDownload) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 401) throw new Error('Your session has expired. Please sign in again.');
      if (response.status === 402) throw new Error('Your plan does not include evidence package export.');
      if (response.status === 403) throw new Error('You do not have permission to export this evidence package.');
      if (response.status === 404) throw new Error('The evidence package is unavailable for this document or installation.');
      if (response.status === 409) throw new Error('The evidence package is not available for this document. Reload it before trying again.');
      throw new Error('Could not export the evidence package. Try again.');
    }
    if (response.status === 401) throw new Error('Your session has expired. Please sign in again.');
    if (response.status === 409) throw new Error('The document changed. Reload it before downloading.');
    if (response.status === 404 && document.status === 'completed') throw new Error(kind === 'evidence' ? 'The evidence report is still being prepared. Try again shortly.' : 'The completed PDF is still being prepared. Try again shortly.');
    throw new Error('Could not download the PDF. Try again.');
  }
  const maxBytes = packageDownload ? maxEvidencePackageBytes : maxPDFBytes;
  const contentType = packageDownload ? (response.headers.get('Content-Type') ?? '').split(';', 1)[0].trim().toLowerCase() : 'application/pdf';
  const validContentType = packageDownload ? contentType === 'application/pdf' || contentType === 'application/zip' : response.headers.get('Content-Type')?.toLowerCase().startsWith('application/pdf');
  const invalidMessage = packageDownload ? 'Could not download a valid evidence package.' : 'Could not download a valid PDF.';
  const length = response.headers.get('Content-Length');
  if (!validContentType || (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) || !response.body) {
    await response.body?.cancel(); throw new Error(invalidMessage);
  }
  const reader = response.body.getReader(), chunks: Uint8Array<ArrayBuffer>[] = [];
  let size = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error('Download cancelled.');
      const { value, done } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error(packageDownload ? 'The evidence package is too large to download here.' : 'The PDF is too large to download here.');
      chunks.push(value as Uint8Array<ArrayBuffer>);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const result = new Blob(chunks, { type: contentType });
  const magic = new Uint8Array(await result.slice(0, 5).arrayBuffer());
  const validMagic = contentType === 'application/zip'
    ? magic[0] === 0x50 && magic[1] === 0x4b && magic[2] === 0x03 && magic[3] === 0x04
    : await result.slice(0, 5).text() === '%PDF-';
  if (signal.aborted || !validMagic) throw new Error(invalidMessage);
  return result;
}
