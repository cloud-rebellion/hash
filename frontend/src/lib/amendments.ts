import type { DocumentResponse } from './api/client';
import { attachmentGeneration, attachmentTime, attachmentUUID, checkedAttachmentDocument } from './documentAttachments';
import { htmlSHA256 } from './htmlRevision';

export const AMENDMENT_MODES = ['signature', 'acknowledgement', 'agreed_notice'] as const;
export type AmendmentMode = typeof AMENDMENT_MODES[number];
export const amendmentCopy: Record<AmendmentMode, { title: string; action: string; description: string }> = {
 signature: { title: 'New signature', action: 'Review and send for signature', description: 'The new amendment document needs fresh signatures.' },
 acknowledgement: { title: 'Explicit acknowledgement', action: 'Review and send for acknowledgement', description: 'Recipients must open the new amendment and choose Accept. No signature is collected.' },
 agreed_notice: { title: 'Agreed notice', action: 'Review an email notice', description: 'Issue the notice using the process recorded in the agreement. Email progress is recorded separately from recipient acceptance.' },
};
export const amendmentLimits = { history: 64, reference: 512, clause: 8192, condition: 2048, subject: 256, text: 16384, recipients: 32 } as const;
export type AmendmentBasis = { kind: 'reviewed_legacy_clause' | 'frozen_agreement_policy'; frozen_policy_id?: string; clause_reference?: string; reviewed_clause?: string; allowed_modes?: AmendmentMode[]; allowed_channels?: string[]; effective_condition?: string };
export type AmendmentBasisRecord = AmendmentBasis & { sha256: string; reviewed_by: string; reviewed_at: string; attribution: string };
export type AmendmentDelivery = { access_id: string; revoked_at?: string; email_delivery_id: string; recipient_email: string; state: 'queued' | 'retrying' | 'provider_accepted' | 'failed'; attempts: number; provider_accepted_at?: string };
export type AmendmentReceipt = { id: string; email_delivery_id: string; kind: string; observed_at: string };
export type AmendmentNotice = { id: string; request_id: string; subject: string; text: string; sha256: string; file_commitment_sha256: string; issued_at: string; issued_by: string; deliveries: AmendmentDelivery[]; verified_receipts: AmendmentReceipt[] };
export type AmendmentRecord = { id: string; request_id: string; revision: string; predecessor_id: string | null; document_id: string; document_name: string; document_status: string; mode: AmendmentMode; basis: AmendmentBasisRecord; file_commitment_sha256: string; created_at: string; created_by: string; notice?: AmendmentNotice };
export type AmendmentInventory = { schema: 'hash-later-amendments-v1'; original_document_id: string; head_id: string | null; head_revision: string; original: { document_id: string; name: string; completed_at: string; final_pdf_sha256: string; report_sha256: string; package_commitment_sha256?: string }; can_create: boolean; frozen_policies: AmendmentBasisRecord[]; amendments: AmendmentRecord[] };
export type AmendmentLink = { schema: 'hash-later-amendments-v1'; original_document_id: string; amendment: AmendmentRecord };
export type AmendmentCreate = { request_id: string; expected_head_id: string | null; expected_head_revision: string; amendment_document_id: string; expected_document_updated_at: string; mode: AmendmentMode; basis: AmendmentBasis; cover_reviewed: boolean };
export type AmendmentIssue = { request_id: string; expected_head_revision: string; expected_document_updated_at: string; subject: string; text: string; recipient_emails: string[]; reviewed: boolean };
export type AmendmentOutcome = { state: 'committed' | 'unchanged' | 'unknown'; request_id: string; reconciliation_required?: boolean; amendment?: AmendmentRecord; notice?: AmendmentNotice };
export type AmendmentActor = { user_id: string; org_id: string; role: string };
export const amendmentInvalid = 'The saved amendment could not be verified. Refresh the agreement before continuing.';
const clone = <T>(value: T): T => structuredClone(value);
function object(value: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
 if (!value || typeof value !== 'object' || Array.isArray(value) || !required.every(key => Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw new Error(amendmentInvalid);
 return value as Record<string, unknown>;
}
export function amendmentText(value: unknown, max: number, empty = false): value is string { return typeof value === 'string' && (empty || value.trim().length > 0) && new TextEncoder().encode(value).length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\p{Cs}]/u.test(value); }
export function amendmentEmail(value: unknown): value is string { return typeof value === 'string' && value.length <= 254 && value.trim() === value && /^[^\s<>@,;]+@[^\s<>@,;]+$/.test(value); }
export function amendmentMode(value: unknown): value is AmendmentMode { return AMENDMENT_MODES.includes(value as AmendmentMode); }
function uuidOrNull(value: unknown) { return value === null || attachmentUUID(value); }
export function checkedAmendmentActor(value: unknown): AmendmentActor { const a = value as AmendmentActor; if (!a || !attachmentUUID(a.user_id) || !attachmentUUID(a.org_id) || !amendmentText(a.role, 64)) throw new Error(amendmentInvalid); return { user_id: a.user_id, org_id: a.org_id, role: a.role }; }
export function checkedAmendmentBasis(value: unknown, recorded = false): AmendmentBasis | AmendmentBasisRecord {
 const b = object(value, ['kind', ...(recorded ? ['sha256', 'reviewed_by', 'reviewed_at', 'attribution'] : [])], ['frozen_policy_id', 'clause_reference', 'reviewed_clause', 'allowed_modes', 'allowed_channels', 'effective_condition']);
 if (!['reviewed_legacy_clause', 'frozen_agreement_policy'].includes(b.kind as string) || (b.frozen_policy_id !== undefined && !attachmentUUID(b.frozen_policy_id))) throw new Error(amendmentInvalid);
 if (b.kind === 'frozen_agreement_policy' && !attachmentUUID(b.frozen_policy_id)) throw new Error(amendmentInvalid);
 if (b.kind === 'reviewed_legacy_clause' && (b.frozen_policy_id !== undefined || !amendmentText(b.clause_reference, amendmentLimits.reference) || !amendmentText(b.reviewed_clause, amendmentLimits.clause) || !amendmentText(b.effective_condition, amendmentLimits.condition))) throw new Error(amendmentInvalid);
 if (b.allowed_modes !== undefined && (!Array.isArray(b.allowed_modes) || !b.allowed_modes.length || b.allowed_modes.length > 3 || !b.allowed_modes.every(amendmentMode) || new Set(b.allowed_modes).size !== b.allowed_modes.length)) throw new Error(amendmentInvalid);
 if (b.allowed_channels !== undefined && (!Array.isArray(b.allowed_channels) || b.allowed_channels.length > 1 || b.allowed_channels.some(channel => channel !== 'email'))) throw new Error(amendmentInvalid);
 if (b.kind === 'reviewed_legacy_clause' && (!Array.isArray(b.allowed_modes) || (b.allowed_modes.includes('agreed_notice') && !(b.allowed_channels as string[] | undefined)?.includes('email')))) throw new Error(amendmentInvalid);
 if (!recorded && b.kind === 'frozen_agreement_policy' && Object.keys(b).some(key => !['kind', 'frozen_policy_id'].includes(key))) throw new Error(amendmentInvalid);
 if (recorded && (!htmlSHA256(b.sha256) || !attachmentUUID(b.reviewed_by) || !attachmentTime(b.reviewed_at) || !amendmentText(b.attribution, 4096))) throw new Error(amendmentInvalid);
 return clone(b) as AmendmentBasis | AmendmentBasisRecord;
}
export function checkedAmendmentNotice(value: unknown): AmendmentNotice {
 const n = object(value, ['id', 'request_id', 'subject', 'text', 'sha256', 'file_commitment_sha256', 'issued_at', 'issued_by', 'deliveries', 'verified_receipts']);
 if (!attachmentUUID(n.id) || !attachmentUUID(n.request_id) || !amendmentText(n.subject, amendmentLimits.subject) || !amendmentText(n.text, amendmentLimits.text) || !htmlSHA256(n.sha256) || !htmlSHA256(n.file_commitment_sha256) || !attachmentTime(n.issued_at) || !attachmentUUID(n.issued_by) || !Array.isArray(n.deliveries) || n.deliveries.length < 1 || n.deliveries.length > amendmentLimits.recipients || !Array.isArray(n.verified_receipts) || n.verified_receipts.length > 256) throw new Error(amendmentInvalid);
 const ids = new Set<string>(), accessIDs = new Set<string>(), addresses = new Set<string>();
 for (const value of n.deliveries) { const d = object(value, ['access_id', 'email_delivery_id', 'recipient_email', 'state', 'attempts'], ['provider_accepted_at', 'revoked_at']); if (!attachmentUUID(d.access_id) || accessIDs.has(d.access_id) || (d.revoked_at !== undefined && !attachmentTime(d.revoked_at)) || !attachmentUUID(d.email_delivery_id) || ids.has(d.email_delivery_id) || !amendmentEmail(d.recipient_email) || addresses.has((d.recipient_email as string).toLowerCase()) || !['queued', 'retrying', 'provider_accepted', 'failed'].includes(d.state as string) || !Number.isInteger(d.attempts) || (d.attempts as number) < 0 || (d.attempts as number) > 2147483647 || (d.provider_accepted_at !== undefined && !attachmentTime(d.provider_accepted_at))) throw new Error(amendmentInvalid); ids.add(d.email_delivery_id); accessIDs.add(d.access_id); addresses.add((d.recipient_email as string).toLowerCase()); }
 const receiptIDs = new Set<string>(); for (const value of n.verified_receipts) { const r = object(value, ['id', 'email_delivery_id', 'kind', 'observed_at']); if (!attachmentUUID(r.id) || receiptIDs.has(r.id) || !ids.has(r.email_delivery_id as string) || !amendmentText(r.kind, 128) || !attachmentTime(r.observed_at)) throw new Error(amendmentInvalid); receiptIDs.add(r.id); }
 return clone(n) as AmendmentNotice;
}
export function checkedAmendmentRecord(value: unknown): AmendmentRecord {
 const r = object(value, ['id', 'request_id', 'revision', 'predecessor_id', 'document_id', 'document_name', 'document_status', 'mode', 'basis', 'file_commitment_sha256', 'created_at', 'created_by'], ['notice']);
 if (!attachmentUUID(r.id) || !attachmentUUID(r.request_id) || !attachmentGeneration(r.revision) || !uuidOrNull(r.predecessor_id) || r.predecessor_id === r.id || !attachmentUUID(r.document_id) || !amendmentText(r.document_name, 4096) || !amendmentText(r.document_status, 64) || !amendmentMode(r.mode) || !htmlSHA256(r.file_commitment_sha256) || !attachmentTime(r.created_at) || !attachmentUUID(r.created_by)) throw new Error(amendmentInvalid);
 const basis = checkedAmendmentBasis(r.basis, true) as AmendmentBasisRecord; if (!basis.allowed_modes?.includes(r.mode)) throw new Error(amendmentInvalid);
 const notice = r.notice === undefined ? undefined : checkedAmendmentNotice(r.notice); if (notice && (r.mode !== 'agreed_notice' || notice.file_commitment_sha256 !== r.file_commitment_sha256)) throw new Error(amendmentInvalid);
 return { ...clone(r), basis, ...(notice ? { notice } : {}) } as AmendmentRecord;
}
export function checkedAmendmentInventory(value: unknown, expectedOriginal: string): AmendmentInventory {
 const v = object(value, ['schema', 'original_document_id', 'head_id', 'head_revision', 'original', 'can_create', 'frozen_policies', 'amendments']);
 const original = object(v.original, ['document_id', 'name', 'completed_at', 'final_pdf_sha256', 'report_sha256'], ['package_commitment_sha256']);
 if (v.schema !== 'hash-later-amendments-v1' || v.original_document_id !== expectedOriginal || !attachmentUUID(expectedOriginal) || original.document_id !== expectedOriginal || !amendmentText(original.name, 4096) || !attachmentTime(original.completed_at) || !htmlSHA256(original.final_pdf_sha256) || !htmlSHA256(original.report_sha256) || (original.package_commitment_sha256 !== undefined && !htmlSHA256(original.package_commitment_sha256)) || !uuidOrNull(v.head_id) || !attachmentGeneration(v.head_revision, true) || typeof v.can_create !== 'boolean' || !Array.isArray(v.frozen_policies) || v.frozen_policies.length > 64 || !Array.isArray(v.amendments) || v.amendments.length > amendmentLimits.history) throw new Error(amendmentInvalid);
 const policies = v.frozen_policies.map(p => checkedAmendmentBasis(p, true) as AmendmentBasisRecord); if (policies.some(p => p.kind !== 'frozen_agreement_policy')) throw new Error(amendmentInvalid);
 const rows = v.amendments.map(checkedAmendmentRecord), ids = new Set<string>(), requests = new Set<string>(), documents = new Set<string>(); let previous: AmendmentRecord | undefined;
 for (const row of rows) { if (ids.has(row.id) || requests.has(row.request_id) || documents.has(row.document_id) || row.document_id === expectedOriginal || row.predecessor_id !== (previous?.id ?? null) || BigInt(row.revision) !== (previous ? BigInt(previous.revision) + 1n : 1n)) throw new Error(amendmentInvalid); ids.add(row.id); requests.add(row.request_id); documents.add(row.document_id); previous = row; }
 if (v.head_id !== (previous?.id ?? null) || v.head_revision !== (previous?.revision ?? '0')) throw new Error(amendmentInvalid);
 return { ...clone(v), original: clone(original), frozen_policies: policies, amendments: rows } as AmendmentInventory;
}
export function checkedAmendmentLink(value: unknown, documentID: string): AmendmentLink { const l = object(value, ['schema', 'original_document_id', 'amendment']); const r = checkedAmendmentRecord(l.amendment); if (l.schema !== 'hash-later-amendments-v1' || !attachmentUUID(l.original_document_id) || l.original_document_id === documentID || r.document_id !== documentID) throw new Error(amendmentInvalid); return { schema: 'hash-later-amendments-v1', original_document_id: l.original_document_id, amendment: r }; }
export function checkedAmendmentOutcome(value: unknown, requestID: string): AmendmentOutcome { const o = object(value, ['state', 'request_id'], ['reconciliation_required', 'amendment', 'notice']); if (!['committed', 'unchanged', 'unknown'].includes(o.state as string) || o.request_id !== requestID || (o.reconciliation_required !== undefined && typeof o.reconciliation_required !== 'boolean')) throw new Error(amendmentInvalid); return { ...clone(o), ...(o.amendment === undefined ? {} : { amendment: checkedAmendmentRecord(o.amendment) }), ...(o.notice === undefined ? {} : { notice: checkedAmendmentNotice(o.notice) }) } as AmendmentOutcome; }
export function amendmentCandidate(value: unknown, orgID: string, originalID: string): DocumentResponse { const d = checkedAttachmentDocument(value); if (!amendmentText(d.name, 512) || d.org_id !== orgID || d.id === originalID || d.html_review_required || typeof d.requires_signature !== 'boolean') throw new Error('Choose a separate reviewed amendment PDF from this organisation.'); return d; }
export function amendmentAllows(candidate: DocumentResponse, mode: AmendmentMode): boolean { return mode === 'signature' ? candidate.requires_signature === true : candidate.requires_signature === false; }
export function basisRequest(record: AmendmentBasisRecord): AmendmentBasis { if (record.kind !== 'frozen_agreement_policy' || !attachmentUUID(record.frozen_policy_id)) throw new Error(amendmentInvalid); return { kind: record.kind, frozen_policy_id: record.frozen_policy_id }; }
export function deliveryCopy(state: AmendmentDelivery['state']): string { return ({ queued: 'Queued', retrying: 'Retrying email', provider_accepted: 'Accepted by email provider', failed: 'Email failed' })[state]; }
export function amendmentDocumentHref(originalID: string, record: AmendmentRecord): string { if (!attachmentUUID(originalID) || !attachmentUUID(record.document_id)) throw new Error(amendmentInvalid); return '/documents/' + record.document_id; }

export function checkedAmendmentCreate(value: unknown): AmendmentCreate {
 const c = object(value, ['request_id', 'expected_head_id', 'expected_head_revision', 'amendment_document_id', 'expected_document_updated_at', 'mode', 'basis', 'cover_reviewed']);
 if (!attachmentUUID(c.request_id) || !uuidOrNull(c.expected_head_id) || !attachmentGeneration(c.expected_head_revision, true) || (c.expected_head_id === null) !== (c.expected_head_revision === '0') || !attachmentUUID(c.amendment_document_id) || !attachmentTime(c.expected_document_updated_at) || !amendmentMode(c.mode) || c.cover_reviewed !== true) throw new Error('Review the amendment document, agreed process and original agreement before continuing.');
 const basis = checkedAmendmentBasis(c.basis) as AmendmentBasis; if (basis.kind === 'reviewed_legacy_clause' && !basis.allowed_modes?.includes(c.mode)) throw new Error('Choose a process permitted by the reviewed agreement clause.');
 return { ...clone(c), basis } as AmendmentCreate;
}
export function checkedAmendmentIssue(value: unknown): AmendmentIssue {
 const i = object(value, ['request_id', 'expected_head_revision', 'expected_document_updated_at', 'subject', 'text', 'recipient_emails', 'reviewed']);
 if (!attachmentUUID(i.request_id) || !attachmentGeneration(i.expected_head_revision) || !attachmentTime(i.expected_document_updated_at) || !amendmentText(i.subject, amendmentLimits.subject) || !amendmentText(i.text, amendmentLimits.text) || /[\r\n]/.test(i.subject as string) || !Array.isArray(i.recipient_emails) || i.recipient_emails.length < 1 || i.recipient_emails.length > amendmentLimits.recipients || !i.recipient_emails.every(amendmentEmail) || new Set((i.recipient_emails as string[]).map(email => email.toLocaleLowerCase('en-US'))).size !== i.recipient_emails.length || i.reviewed !== true) throw new Error('Review the exact notice, subject and recipient email addresses before issuing it.');
 return clone(i) as AmendmentIssue;
}

export type AmendmentRevokeOutcome = { schema: 'hash-later-amendments-v1'; state: 'committed' | 'unchanged' | 'unknown'; access_id: string; revoked_at?: string; reconciliation_required?: boolean };
export function checkedAmendmentRevoke(value: unknown, accessID: string): AmendmentRevokeOutcome {
 const result = object(value, ['schema', 'state', 'access_id'], ['revoked_at', 'reconciliation_required']);
 if (result.schema !== 'hash-later-amendments-v1' || !attachmentUUID(accessID) || result.access_id !== accessID || !['committed', 'unchanged', 'unknown'].includes(result.state as string) || (result.reconciliation_required !== undefined && typeof result.reconciliation_required !== 'boolean') || (result.state === 'unknown' ? result.revoked_at !== undefined || result.reconciliation_required !== true : !attachmentTime(result.revoked_at))) throw new Error(amendmentInvalid);
 return clone(result) as AmendmentRevokeOutcome;
}
