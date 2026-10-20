import { APIError, type DocumentResponse } from './client';
import { attachmentExpected, attachmentMemberKey, attachmentInvalid, attachmentUUID, checkedAttachmentActor, checkedAttachmentDocument, checkedAttachmentInventory, checkedAttachmentLayout, checkedAttachmentOutcome, checkedAttachmentSelection,
 type AttachmentInventory, type AttachmentMember, type AttachmentSelection, type AttachmentLayout, type AttachmentPage } from '../documentAttachments';

async function jsonBody(response: Response, signal: AbortSignal, cap: number): Promise<unknown> {
 if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) { await response.body?.cancel().catch(() => {}); throw new Error(attachmentInvalid); }
 const size = response.headers.get('Content-Length'); if (size !== null && (!/^[0-9]+$/.test(size) || Number(size) > cap)) { await response.body?.cancel().catch(() => {}); throw new Error(attachmentInvalid); }
 const reader = response.body?.getReader(); if (!reader) throw new Error(attachmentInvalid);
 const chunks: Uint8Array[] = []; let length = 0;
 try { while (true) { if (signal.aborted) throw new Error(attachmentInvalid); const r = await reader.read(); if (signal.aborted) throw new Error(attachmentInvalid); if (r.done) break; length += r.value.byteLength; if (length > cap) throw new Error(attachmentInvalid); chunks.push(r.value); }
  const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; } return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
 } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function request(path: string, signal: AbortSignal, method = 'GET', input?: unknown, cap = 8 * 1024 * 1024): Promise<unknown> {
 if (signal.aborted) throw new Error(attachmentInvalid);
 const body = input === undefined ? undefined : JSON.stringify(input); if (body && new TextEncoder().encode(body).length > (method === 'PATCH' ? 16384 : 4096)) throw new Error('Attachment labels exceed the request size limit. Shorten them before saving.');
 const response = await fetch(path, { method, credentials: 'include', cache: 'no-store', signal, headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body }) });
 if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, response.status === 409 ? 'The agreement or attachment source changed. Inspect saved attachments and review the source before another save.' : response.status === 401 ? 'Your session expired. Sign in again.' : response.status === 403 ? 'You no longer have permission to manage these attachments.' : response.status === 422 ? 'The exact PDF could not be verified. Review the source document.' : response.status === 429 ? 'Too many attachment requests. Wait before refreshing.' : 'The attachment request was refused. Refresh and inspect the saved state.'); }
 return jsonBody(response, signal, cap);
}
function route(id: string): string { if (!attachmentUUID(id)) throw new Error(attachmentInvalid); return '/api/v1/documents/' + id; }
export async function getDocumentAttachments(id: string, signal: AbortSignal) { const v = checkedAttachmentInventory(await request(route(id) + '/attachments', signal, 'GET', undefined, 65536)); if (v.document_id !== id) throw new Error(attachmentInvalid); return v; }
export async function selectDocumentAttachment(id: string, input: AttachmentSelection, signal: AbortSignal) { return checkedAttachmentOutcome(await request(route(id) + '/attachments', signal, 'POST', checkedAttachmentSelection(input), 65536), 'select'); }
export async function saveDocumentAttachments(id: string, input: AttachmentLayout, signal: AbortSignal) { return checkedAttachmentOutcome(await request(route(id) + '/attachments', signal, 'PATCH', checkedAttachmentLayout(input), 65536), 'layout'); }
export async function attachmentDocument(id: string, signal: AbortSignal): Promise<DocumentResponse> { const d = checkedAttachmentDocument(await request(route(id), signal)); if (d.id !== id) throw new Error(attachmentInvalid); return d; }
export async function attachmentChoices(offset: number, signal: AbortSignal): Promise<AttachmentPage> {
 if (!Number.isSafeInteger(offset) || offset < 0 || offset > 2147483627) throw new Error(attachmentInvalid);
 const value = await request('/api/v1/documents?status=draft&limit=20&offset=' + offset, signal) as AttachmentPage;
 if (!value || !Array.isArray(value.documents) || value.documents.length > 20 || value.limit !== 20 || value.offset !== offset || !Number.isSafeInteger(value.total) || value.total < 0) throw new Error(attachmentInvalid);
 return { documents: structuredClone(value.documents), limit: 20, offset, total: value.total };
}
function versionHeader(version: string): string { let binary = ''; for (const b of new TextEncoder().encode(version)) binary += String.fromCharCode(b); return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
export async function fetchSelectedAttachmentPDF(value: AttachmentInventory, member: AttachmentMember, signal: AbortSignal): Promise<Uint8Array> {
 const v = checkedAttachmentInventory(value), m = v.members.find(x => x.document_id === member.document_id);
 if (!m || attachmentMemberKey(m) !== attachmentMemberKey(member) || !v.package_id || signal.aborted) throw new Error(attachmentInvalid);
 const query = new URLSearchParams(attachmentExpected(v));
 const response = await fetch(route(v.document_id) + '/attachments/' + m.document_id + '/pdf?' + query, { credentials: 'include', cache: 'no-store', signal, headers: { Accept: 'application/pdf' } });
 if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'The selected PDF preview was refused. Refresh and inspect the saved attachments.'); }
 const headers: Record<string, string> = { 'X-Hash-Document-Id': v.document_id, 'X-Hash-Document-Updated-At': v.updated_at, 'X-Hash-Package-Id': v.package_id, 'X-Hash-Package-Generation': v.generation, 'X-Hash-Member-Document-Id': m.document_id, 'X-Hash-PDF-Version': versionHeader(m.pdf_version_id), 'X-Hash-PDF-SHA256': m.pdf_sha256, 'X-Hash-PDF-Bytes': String(m.pdf_bytes), 'X-Hash-PDF-Pages': String(m.pdf_pages), 'Content-Length': String(m.pdf_bytes) };
 if (response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/pdf' || Object.entries(headers).some(([k, expected]) => response.headers.get(k) !== expected)) { await response.body?.cancel().catch(() => {}); throw new Error(attachmentInvalid); }
 const reader = response.body?.getReader(); if (!reader) throw new Error(attachmentInvalid);
 const bytes = new Uint8Array(m.pdf_bytes); let length = 0, verified = false;
 try { while (true) { if (signal.aborted) throw new Error(attachmentInvalid); const r = await reader.read(); if (signal.aborted) throw new Error(attachmentInvalid); if (r.done) break; if (r.value.length > bytes.length - length) throw new Error(attachmentInvalid); bytes.set(r.value, length); length += r.value.length; }
  if (length !== bytes.length) throw new Error(attachmentInvalid);
  const sha = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
  if (signal.aborted || sha !== m.pdf_sha256) throw new Error(attachmentInvalid); verified = true; return bytes;
 } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); if (!verified) bytes.fill(0); }
}
export const attachmentTransport = { identity: async (signal: AbortSignal) => checkedAttachmentActor(await request('/api/v1/me', signal)), document: attachmentDocument, inventory: getDocumentAttachments, choices: attachmentChoices, select: selectDocumentAttachment, layout: saveDocumentAttachments };
