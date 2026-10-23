import { APIError, type DocumentResponse } from './client';
import { attachmentUUID } from '../documentAttachments';
import { amendmentInvalid, amendmentText, checkedAmendmentActor, checkedAmendmentCreate, checkedAmendmentIssue, checkedAmendmentInventory, checkedAmendmentLink, checkedAmendmentOutcome, checkedAmendmentRevoke, type AmendmentCreate, type AmendmentIssue } from '../amendments';

async function json(response: Response, signal: AbortSignal, cap: number): Promise<unknown> {
 if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) { await response.body?.cancel().catch(() => {}); throw new Error(amendmentInvalid); }
 const size = response.headers.get('Content-Length'); if (size !== null && (!/^[0-9]+$/.test(size) || Number(size) > cap)) { await response.body?.cancel().catch(() => {}); throw new Error(amendmentInvalid); }
 const reader = response.body?.getReader(); if (!reader) throw new Error(amendmentInvalid); const chunks: Uint8Array[] = []; let length = 0;
 const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
 try { while (true) { if (signal.aborted) throw new Error(amendmentInvalid); const part = await reader.read(); if (signal.aborted) throw new Error(amendmentInvalid); if (part.done) break; length += part.value.length; if (length > cap) throw new Error(amendmentInvalid); chunks.push(part.value); }
  const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; } return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
 } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function request(path: string, signal: AbortSignal, method = 'GET', input?: unknown, missing = false): Promise<unknown> {
 if (signal.aborted) throw new Error(amendmentInvalid); const body = input === undefined ? undefined : JSON.stringify(input);
 if (body !== undefined && new TextEncoder().encode(body).length > 65536) throw new Error('Shorten the amendment information before continuing.');
 const response = await fetch(path, { method, signal, credentials: 'include', cache: 'no-store', redirect: 'error', headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body }) });
 if (missing && response.status === 404) { await response.body?.cancel().catch(() => {}); return null; }
 if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, response.status === 401 ? 'Your session expired. Sign in again.' : response.status === 403 ? 'You no longer have permission to manage this amendment.' : response.status === 409 ? 'The agreement, amendment or saved files changed. Inspect the saved amendments before continuing.' : response.status === 429 ? 'Too many amendment requests. Wait before checking again.' : 'The amendment request was refused. Check the saved agreement before continuing.'); }
 return json(response, signal, 4 * 1024 * 1024);
}
function route(id: string): string { if (!attachmentUUID(id)) throw new Error(amendmentInvalid); return '/api/v1/documents/' + id; }
export async function getDocumentAmendments(originalID: string, signal: AbortSignal) { return checkedAmendmentInventory(await request(route(originalID) + '/amendments', signal), originalID); }
export async function getDocumentAmendment(documentID: string, signal: AbortSignal) { const value = await request(route(documentID) + '/amendment', signal, 'GET', undefined, true); return value === null ? null : checkedAmendmentLink(value, documentID); }
export async function createDocumentAmendment(originalID: string, input: AmendmentCreate, signal: AbortSignal) { return checkedAmendmentOutcome(await request(route(originalID) + '/amendments', signal, 'POST', checkedAmendmentCreate(input)), input.request_id); }
export async function issueAmendmentNotice(originalID: string, amendmentID: string, input: AmendmentIssue, signal: AbortSignal) { if (!attachmentUUID(amendmentID)) throw new Error(amendmentInvalid); return checkedAmendmentOutcome(await request(route(originalID) + '/amendments/' + amendmentID + '/notice', signal, 'POST', checkedAmendmentIssue(input)), input.request_id); }
export async function amendmentDocument(id: string, signal: AbortSignal): Promise<DocumentResponse> { const d = await request(route(id), signal) as DocumentResponse; if (!d || d.id !== id) throw new Error(amendmentInvalid); return d; }
export async function amendmentChoices(offset: number, signal: AbortSignal): Promise<{ documents: DocumentResponse[]; offset: number; total: number }> {
 if (!Number.isSafeInteger(offset) || offset < 0 || offset > 2147483627) throw new Error(amendmentInvalid);
 const v = await request('/api/v1/documents?status=draft&limit=20&offset=' + offset, signal) as { documents: DocumentResponse[]; limit: number; offset: number; total: number };
 if (!v || !Array.isArray(v.documents) || v.documents.length > 20 || v.limit !== 20 || v.offset !== offset || !Number.isSafeInteger(v.total) || v.total < 0 || v.documents.some(d => !d || !attachmentUUID(d.id) || !attachmentUUID(d.org_id) || !amendmentText(d.name, 4096) || d.status !== 'draft' || !['blocks', 'pdf'].includes(d.source_kind))) throw new Error(amendmentInvalid);
 return structuredClone(v);
}
export async function revokeAmendmentAccess(originalID: string, amendmentID: string, accessID: string, signal: AbortSignal) { if (!attachmentUUID(amendmentID) || !attachmentUUID(accessID)) throw new Error(amendmentInvalid); return checkedAmendmentRevoke(await request(route(originalID) + '/amendments/' + amendmentID + '/notice/access/' + accessID + '/revoke', signal, 'POST', {}), accessID); }
export const amendmentTransport = { identity: async (signal: AbortSignal) => checkedAmendmentActor(await request('/api/v1/me', signal)), link: getDocumentAmendment, inventory: getDocumentAmendments, choices: amendmentChoices, document: amendmentDocument, create: createDocumentAmendment, issue: issueAmendmentNotice, revoke: revokeAmendmentAccess };
