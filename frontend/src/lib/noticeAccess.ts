import { attachmentTime, attachmentUUID } from './documentAttachments';
import { amendmentText } from './amendments';
import { htmlSHA256 } from './htmlRevision';

export type NoticeFile = { position: number; title: string; pdf_sha256: string; pdf_bytes: number; pdf_pages: number; file_version_sha256: string };
export type PublicNotice = { schema: 'hash-amendment-notice-access-v1'; notice_id: string; original_document_id: string; document_id: string; subject: string; text: string; issued_at: string; expires_at: string; file_commitment_sha256: string; files: NoticeFile[] };
export const noticeUnavailable = 'This notice could not be opened. Open the original email link again or ask the sender for access.';
function object(value: unknown, keys: string[]): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value) || !keys.every(k => Object.hasOwn(value, k)) || Object.keys(value).some(k => !keys.includes(k))) throw new Error(noticeUnavailable); return value as Record<string, unknown>; }
export function checkedPublicNotice(value: unknown, noticeID: string): PublicNotice {
 const n = object(value, ['schema', 'notice_id', 'original_document_id', 'document_id', 'subject', 'text', 'issued_at', 'expires_at', 'file_commitment_sha256', 'files']);
 if (!attachmentUUID(noticeID) || n.schema !== 'hash-amendment-notice-access-v1' || n.notice_id !== noticeID || !attachmentUUID(n.original_document_id) || !attachmentUUID(n.document_id) || n.original_document_id === n.document_id || !amendmentText(n.subject, 256) || !amendmentText(n.text, 16384) || !attachmentTime(n.issued_at) || !attachmentTime(n.expires_at) || Date.parse(n.expires_at) <= Date.parse(n.issued_at) || !htmlSHA256(n.file_commitment_sha256) || !Array.isArray(n.files) || !n.files.length || n.files.length > 17) throw new Error(noticeUnavailable);
 const files = n.files.map((value, position) => { const f = object(value, ['position', 'title', 'pdf_sha256', 'pdf_bytes', 'pdf_pages', 'file_version_sha256']); if (f.position !== position || !amendmentText(f.title, 512) || !htmlSHA256(f.pdf_sha256) || !Number.isSafeInteger(f.pdf_bytes) || (f.pdf_bytes as number) < 1 || (f.pdf_bytes as number) > 50 * 1024 * 1024 || !Number.isInteger(f.pdf_pages) || (f.pdf_pages as number) < 1 || (f.pdf_pages as number) > 500 || !htmlSHA256(f.file_version_sha256)) throw new Error(noticeUnavailable); return { ...f } as NoticeFile; });
 if (files.reduce((sum, file) => sum + file.pdf_bytes, 0) > 50 * 1024 * 1024 || files.reduce((sum, file) => sum + file.pdf_pages, 0) > 500) throw new Error(noticeUnavailable);
 return { ...structuredClone(n), files } as PublicNotice;
}
// The entrypoint is fragment-only. Consume once before any request; never store
// this value in a URL, browser storage, UI state, error message or telemetry.
export function takeNoticeFragment(fragment: string): string | null {
 if (!fragment || fragment === '#') return null; const query = new URLSearchParams(fragment.startsWith('#') ? fragment.slice(1) : fragment);
 const values = query.getAll('access'); if (values.length !== 1 || [...query.keys()].some(k => k !== 'access') || !/^hn1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(values[0])) throw new Error(noticeUnavailable); return values[0];
}
function route(id: string) { if (!attachmentUUID(id)) throw new Error(noticeUnavailable); return '/api/v1/notices/' + id; }
async function json(response: Response, signal: AbortSignal): Promise<unknown> {
 if (!response.ok || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) { await response.body?.cancel().catch(() => {}); throw new Error(noticeUnavailable); }
 const length = response.headers.get('Content-Length'); if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > 131072)) { await response.body?.cancel().catch(() => {}); throw new Error(noticeUnavailable); }
 const reader = response.body?.getReader(); if (!reader) throw new Error(noticeUnavailable); const chunks: Uint8Array[] = []; let size = 0;
 const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
 try { while (true) { if (signal.aborted) throw new Error(noticeUnavailable); const part = await reader.read(); if (signal.aborted) throw new Error(noticeUnavailable); if (part.done) break; size += part.value.length; if (size > 131072) throw new Error(noticeUnavailable); chunks.push(part.value); }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; } return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
 } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export async function exchangeNoticeAccess(id: string, capability: string, signal: AbortSignal, fetcher: typeof fetch = fetch): Promise<void> {
 if (signal.aborted || !/^hn1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(capability)) throw new Error(noticeUnavailable);
 const body = JSON.stringify({ token: capability }); if (new TextEncoder().encode(body).length > 128) throw new Error(noticeUnavailable);
 const response = await fetcher(route(id) + '/access', { method: 'POST', signal, credentials: 'include', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body });
 await response.body?.cancel().catch(() => {}); if (!response.ok || signal.aborted) throw new Error(noticeUnavailable);
}
export async function getPublicNotice(id: string, signal: AbortSignal, fetcher: typeof fetch = fetch): Promise<PublicNotice> {
 const response = await fetcher(route(id), { signal, credentials: 'include', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' } }); return checkedPublicNotice(await json(response, signal), id);
}
export function noticeFileKey(notice: PublicNotice, file: NoticeFile): string { return [notice.notice_id, notice.file_commitment_sha256, file.position, file.pdf_sha256, file.file_version_sha256, file.pdf_bytes, file.pdf_pages].join(':'); }
export async function fetchNoticePDF(value: PublicNotice, selected: NoticeFile, signal: AbortSignal, fetcher: typeof fetch = fetch): Promise<Uint8Array<ArrayBuffer>> {
 const notice = checkedPublicNotice(value, value.notice_id), file = notice.files[selected.position]; if (!file || noticeFileKey(notice, file) !== noticeFileKey(notice, selected) || signal.aborted) throw new Error(noticeUnavailable);
 const etag = '"' + notice.file_commitment_sha256 + '.' + file.pdf_sha256 + '"'; const response = await fetcher(route(notice.notice_id) + '/files/' + file.position, { signal, credentials: 'include', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', headers: { Accept: 'application/pdf', 'If-Match': etag } });
 const expected: Record<string, string> = { ETag: etag, 'X-Hash-Notice-Id': notice.notice_id, 'X-Hash-Notice-File-Commitment-SHA256': notice.file_commitment_sha256, 'X-Hash-PDF-SHA256': file.pdf_sha256, 'X-Hash-PDF-Bytes': String(file.pdf_bytes), 'X-Hash-PDF-Pages': String(file.pdf_pages), 'X-Hash-Notice-File-Position': String(file.position), 'X-Hash-Notice-File-Version-SHA256': file.file_version_sha256, 'Content-Length': String(file.pdf_bytes) };
 if (!response.ok || response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/pdf' || Object.entries(expected).some(([name, value]) => response.headers.get(name) !== value)) { await response.body?.cancel().catch(() => {}); throw new Error(noticeUnavailable); }
 const reader = response.body?.getReader(); if (!reader) throw new Error(noticeUnavailable); const bytes = new Uint8Array(file.pdf_bytes); let used = 0, verified = false;
 const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
 try { while (true) { if (signal.aborted) throw new Error(noticeUnavailable); const part = await reader.read(); if (signal.aborted) throw new Error(noticeUnavailable); if (part.done) break; if (part.value.length > bytes.length - used) throw new Error(noticeUnavailable); bytes.set(part.value, used); used += part.value.length; }
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(x => x.toString(16).padStart(2, '0')).join(''); if (signal.aborted || used !== bytes.length || digest !== file.pdf_sha256) throw new Error(noticeUnavailable); verified = true; return bytes;
 } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); if (!verified) bytes.fill(0); }
}
