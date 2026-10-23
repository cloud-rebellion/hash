import type { DocumentResponse } from './api/client';
import { attachmentUUID } from './documentAttachments';
import { amendmentAllows, amendmentCandidate, amendmentInvalid, checkedAmendmentActor, checkedAmendmentCreate, checkedAmendmentInventory, checkedAmendmentIssue, checkedAmendmentLink, checkedAmendmentOutcome, checkedAmendmentRevoke, type AmendmentActor, type AmendmentCreate, type AmendmentInventory, type AmendmentIssue, type AmendmentLink, type AmendmentOutcome, type AmendmentNotice, type AmendmentRevokeOutcome, type AmendmentRecord } from './amendments';

export type AmendmentTransport = {
 identity(signal: AbortSignal): Promise<AmendmentActor>;
 link(id: string, signal: AbortSignal): Promise<AmendmentLink | null>;
 inventory(id: string, signal: AbortSignal): Promise<AmendmentInventory>;
 choices(offset: number, signal: AbortSignal): Promise<{ documents: DocumentResponse[]; offset: number; total: number }>;
 document(id: string, signal: AbortSignal): Promise<DocumentResponse>;
 create(id: string, input: AmendmentCreate, signal: AbortSignal): Promise<AmendmentOutcome>;
 revoke(id: string, amendmentID: string, accessID: string, signal: AbortSignal): Promise<AmendmentRevokeOutcome>;
 issue(id: string, amendmentID: string, input: AmendmentIssue, signal: AbortSignal): Promise<AmendmentOutcome>;
};
type Pending = { kind: 'create'; originalID: string; input: AmendmentCreate } | { kind: 'notice'; originalID: string; amendmentID: string; input: AmendmentIssue };
export type AmendmentState = { busy: 'load' | 'choices' | 'candidate' | 'create' | 'notice' | 'revoke' | null; fresh: boolean; link: AmendmentLink | null; inventory: AmendmentInventory | null; choices: DocumentResponse[]; offset: number; total: number; candidate: DocumentResponse | null; noticeDocument: DocumentResponse | null; noticeReview: AmendmentIssue | null; noticeAmendmentID: string | null; pending: Pending | null; error: string | null; message: string | null };
export const initialAmendmentState = (): AmendmentState => ({ busy: null, fresh: false, link: null, inventory: null, choices: [], offset: 0, total: 0, candidate: null, noticeDocument: null, noticeReview: null, noticeAmendmentID: null, pending: null, error: null, message: null });
const copy = <T>(value: T): T => structuredClone(value);
function createMatches(row: AmendmentRecord, input: AmendmentCreate): boolean {
 const basis = row.basis;
 return row.request_id === input.request_id && row.document_id === input.amendment_document_id && row.mode === input.mode && row.predecessor_id === input.expected_head_id && BigInt(row.revision) === BigInt(input.expected_head_revision) + 1n && basis.kind === input.basis.kind && (basis.kind === 'frozen_agreement_policy' ? basis.frozen_policy_id === input.basis.frozen_policy_id : basis.clause_reference === input.basis.clause_reference && basis.reviewed_clause === input.basis.reviewed_clause && basis.effective_condition === input.basis.effective_condition && JSON.stringify(basis.allowed_modes) === JSON.stringify(input.basis.allowed_modes) && JSON.stringify(basis.allowed_channels ?? []) === JSON.stringify(input.basis.allowed_channels ?? []));
}
function noticeMatches(notice: AmendmentNotice, input: AmendmentIssue): boolean {
 return notice.request_id === input.request_id && notice.subject === input.subject && notice.text === input.text && JSON.stringify(notice.deliveries.map(row => row.recipient_email)) === JSON.stringify(input.recipient_emails);
}

export class AmendmentWorkflow {
 state = initialAmendmentState(); private epoch = 0; private abort: AbortController | null = null; private disposed = false;
 constructor(private doc: DocumentResponse, private actor: AmendmentActor, private transport: AmendmentTransport, private changed: (state: AmendmentState) => void, private available: () => boolean = () => true) {
  this.doc = copy(doc); this.actor = checkedAmendmentActor(actor); if (!attachmentUUID(doc.id) || doc.org_id !== actor.org_id) throw new Error(amendmentInvalid);
 }
 private update(patch: Partial<AmendmentState>) { if (!this.disposed) { this.state = { ...this.state, ...patch }; this.changed(this.state); } }
 private start(busy: NonNullable<AmendmentState['busy']>) { this.abort?.abort(); this.abort = new AbortController(); const epoch = ++this.epoch; const signal = this.abort.signal; this.update({ busy, error: null, message: null }); return { epoch, signal }; }
 private current(epoch: number) { return !this.disposed && epoch === this.epoch && !this.abort?.signal.aborted; }
 private async identity(signal: AbortSignal) { const actor = checkedAmendmentActor(await this.transport.identity(signal)); if (JSON.stringify(actor) !== JSON.stringify(this.actor)) throw new Error('The account or permissions changed. Reload this agreement.'); return actor; }
 canWrite() { return this.state.fresh && !this.state.busy && !this.state.pending && !!this.state.inventory?.can_create && this.actor.role === 'owner' && this.available(); }
 ordinarySendBlocked() { return !this.state.fresh || this.state.link?.amendment.mode === 'agreed_notice'; }
 mutating() { return this.state.busy === 'create' || this.state.busy === 'notice' || this.state.busy === 'revoke'; }
 private async inventory(signal: AbortSignal, originalID: string) { const value = checkedAmendmentInventory(await this.transport.inventory(originalID, signal), originalID); if (this.doc.id !== originalID && !value.amendments.some(row => row.document_id === this.doc.id)) throw new Error(amendmentInvalid); return value; }
 async refresh() {
  if (this.state.busy) return; const op = this.start('load'); this.update({ fresh: false });
  try { await this.identity(op.signal); const raw = await this.transport.link(this.doc.id, op.signal); const link = raw === null ? null : checkedAmendmentLink(raw, this.doc.id);
   const originalID = link?.original_document_id ?? (this.doc.status === 'completed' ? this.doc.id : null); const inventory = originalID ? await this.inventory(op.signal, originalID) : null; await this.identity(op.signal);
   if (!this.current(op.epoch)) return; let pending = this.state.pending, message: string | null = null;
   if (pending && inventory && pending.originalID === inventory.original_document_id) { const reviewed = pending; const found = reviewed.kind === 'create' ? inventory.amendments.find(row => createMatches(row, reviewed.input)) : inventory.amendments.find(row => row.id === reviewed.amendmentID && row.notice !== undefined && noticeMatches(row.notice, reviewed.input) && row.notice.file_commitment_sha256 === row.file_commitment_sha256);
    if (found) { pending = null; message = 'The original reviewed request is saved. Its linked document and communication history are shown below.'; }
    else message = 'No matching saved result was returned. Keep the earlier reviewed request; check again or retry that same request.';
   }
   const noticeStillCurrent = inventory?.head_id === this.state.noticeAmendmentID && inventory?.head_revision === this.state.noticeReview?.expected_head_revision && !inventory?.amendments.find(row => row.id === inventory.head_id)?.notice;
   this.update({ ...(!noticeStillCurrent ? { noticeReview: null, noticeDocument: null, noticeAmendmentID: null } : {}), fresh: true, link: link && inventory ? { ...link, amendment: inventory.amendments.find(row => row.document_id === this.doc.id)! } : link, inventory, pending, message });
  } catch (error) { if (this.current(op.epoch)) this.update({ error: (error as Error).message, fresh: false }); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 async loadChoices(offset = 0) { if (!this.canWrite()) return; const op = this.start('choices'); try { await this.identity(op.signal); const page = await this.transport.choices(offset, op.signal); if (this.current(op.epoch)) this.update({ choices: page.documents.filter(d => d.org_id === this.actor.org_id && d.id !== this.state.inventory!.original_document_id && d.status === 'draft' && d.source_kind === 'pdf' && !d.is_envelope && !d.parent_envelope_id && !this.state.inventory!.amendments.some(row => row.document_id === d.id)), offset: page.offset, total: page.total }); } catch (error) { if (this.current(op.epoch)) this.update({ error: (error as Error).message }); } finally { if (this.current(op.epoch)) this.update({ busy: null }); } }
 async choose(id: string) { if (!this.canWrite() || !this.state.choices.some(row => row.id === id)) return; const op = this.start('candidate'); this.update({ candidate: null }); try { await this.identity(op.signal); const candidate = amendmentCandidate(await this.transport.document(id, op.signal), this.actor.org_id, this.state.inventory!.original_document_id); if (candidate.id !== id) throw new Error(amendmentInvalid); if (this.current(op.epoch)) this.update({ candidate }); } catch (error) { if (this.current(op.epoch)) this.update({ error: (error as Error).message }); } finally { if (this.current(op.epoch)) this.update({ busy: null }); } }
 async create(input: AmendmentCreate) {
  if (!this.canWrite() || !this.state.inventory || !this.state.candidate) return; const value = checkedAmendmentCreate(input), inventory = this.state.inventory, candidate = this.state.candidate;
  if (value.expected_head_id !== inventory.head_id || value.expected_head_revision !== inventory.head_revision || value.amendment_document_id !== candidate.id || value.expected_document_updated_at !== candidate.updated_at || !amendmentAllows(candidate, value.mode)) throw new Error('The selected document or agreed process changed. Review it again.');
  const pending: Pending = { kind: 'create', originalID: inventory.original_document_id, input: copy(value) }; await this.write(pending);
 }
 async reviewNotice(record: AmendmentRecord, subject: string, text: string, emails: string[]) {
  if (!this.canWrite() || !this.state.inventory || record.mode !== 'agreed_notice' || record.notice || record.id !== this.state.inventory.head_id || !record.basis.allowed_channels?.includes('email')) return;
  const op = this.start('candidate'); this.update({ noticeReview: null, noticeDocument: null, noticeAmendmentID: null });
  try { await this.identity(op.signal); const document = amendmentCandidate(await this.transport.document(record.document_id, op.signal), this.actor.org_id, this.state.inventory.original_document_id); if (document.id !== record.document_id || !amendmentAllows(document, 'agreed_notice')) throw new Error(amendmentInvalid);
   const review = checkedAmendmentIssue({ request_id: crypto.randomUUID(), expected_head_revision: this.state.inventory.head_revision, expected_document_updated_at: document.updated_at, subject, text, recipient_emails: emails, reviewed: true });
   if (this.current(op.epoch)) this.update({ noticeReview: review, noticeDocument: document, noticeAmendmentID: record.id });
  } catch (error) { if (this.current(op.epoch)) this.update({ error: (error as Error).message }); } finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 discardNoticeReview() { if (!this.state.busy && !this.state.pending) this.update({ noticeReview: null, noticeDocument: null, noticeAmendmentID: null }); }
 async issueNotice() { if (!this.canWrite() || !this.state.inventory || !this.state.noticeReview || !this.state.noticeAmendmentID) return; const record = this.state.inventory.amendments.find(row => row.id === this.state.noticeAmendmentID); if (!record || record.notice || record.mode !== 'agreed_notice' || record.id !== this.state.inventory.head_id || record.revision !== this.state.noticeReview.expected_head_revision) throw new Error(amendmentInvalid); await this.write({ kind: 'notice', originalID: this.state.inventory.original_document_id, amendmentID: record.id, input: copy(this.state.noticeReview) }); }
 async revokeAccess(record: AmendmentRecord, accessID: string) {
  if (!this.canWrite() || !this.state.inventory) return; const saved = this.state.inventory.amendments.find(row => row.id === record.id), delivery = saved?.notice?.deliveries.find(row => row.access_id === accessID);
  if (!saved || !delivery || delivery.revoked_at) return;
  const originalID = this.state.inventory.original_document_id, op = this.start('revoke'); let failure: string | null = null;
  try { await this.identity(op.signal); const result = checkedAmendmentRevoke(await this.transport.revoke(originalID, saved.id, accessID, op.signal), accessID); if (!this.current(op.epoch)) return;
   if (result.state === 'unknown' || result.reconciliation_required) failure = 'Link revocation was not confirmed. Check its saved access status before retrying the same action.';
   else this.update({ message: 'The saved link revocation is being checked. Email progress remains separate.' });
  } catch { if (this.current(op.epoch)) failure = 'Link revocation was not confirmed. Check its saved access status before retrying the same action.'; }
  finally { if (this.current(op.epoch)) { this.update({ busy: null }); const readback = this.refresh(), readbackEpoch = this.epoch; await readback; if (!this.current(readbackEpoch)) return; const revoked = this.state.fresh && this.state.inventory?.amendments.find(row => row.id === saved.id)?.notice?.deliveries.find(row => row.access_id === accessID)?.revoked_at; if (revoked) this.update({ message: 'Further access using this email link is revoked. Previously downloaded files remain with the recipient.', error: null }); else if (failure) this.update({ error: failure }); } }
 }
 async retryReviewedRequest() { if (!this.state.pending || this.state.busy || !this.state.fresh || this.actor.role !== 'owner' || !this.available()) return; await this.write(copy(this.state.pending)); }
 private async write(pending: Pending) {
  const op = this.start(pending.kind === 'create' ? 'create' : 'notice'); let dispatched = false; this.update({ pending: copy(pending) });
  try { await this.identity(op.signal); const documentID = pending.kind === 'create' ? pending.input.amendment_document_id : this.state.inventory?.amendments.find(row => row.id === pending.amendmentID)?.document_id; if (!documentID) throw new Error(amendmentInvalid);
   const fresh = amendmentCandidate(await this.transport.document(documentID, op.signal), this.actor.org_id, pending.originalID); if (fresh.id !== documentID || fresh.updated_at !== pending.input.expected_document_updated_at) throw new Error('The amendment PDF changed after review. Inspect the saved amendments.');
   dispatched = true; const raw = pending.kind === 'create' ? await this.transport.create(pending.originalID, copy(pending.input), op.signal) : await this.transport.issue(pending.originalID, pending.amendmentID, copy(pending.input), op.signal); const outcome = checkedAmendmentOutcome(raw, pending.input.request_id);
   if (!this.current(op.epoch)) return;
   if (outcome.state === 'unknown' || outcome.reconciliation_required) { this.update({ error: 'The saved result needs checking. Do not create a second request.' }); return; }
   const record = pending.kind === 'create' ? outcome.amendment : undefined, notice = pending.kind === 'notice' ? outcome.notice : undefined;
   if (pending.kind === 'create' ? !record || !createMatches(record, pending.input) : !notice || !noticeMatches(notice, pending.input) || notice.file_commitment_sha256 !== this.state.inventory?.amendments.find(row => row.id === pending.amendmentID)?.file_commitment_sha256) throw new Error(amendmentInvalid);
   this.update({ candidate: pending.kind === 'create' ? null : this.state.candidate, message: pending.kind === 'create' ? 'The amendment is linked. Review its separate document and send it using the selected process.' : 'The notice is recorded. Email progress and any verified receipts are shown separately.', noticeReview: null, noticeDocument: null, noticeAmendmentID: null });
  } catch (error) { if (this.current(op.epoch)) this.update({ ...(!dispatched ? { pending: null } : {}), error: (error as Error).message }); }
  finally { if (this.current(op.epoch)) { const failure = this.state.error; this.update({ busy: null }); const readback = this.refresh(), readbackEpoch = this.epoch; await readback; if (failure && this.current(readbackEpoch)) this.update({ error: failure }); } }
 }
 interrupt() { this.epoch++; this.abort?.abort(); this.update({ fresh: false, busy: null, noticeReview: null, noticeDocument: null, noticeAmendmentID: null, ...(this.state.pending ? { error: 'An interrupted request may still finish. Inspect the saved amendments before another action.' } : {}) }); }
 dispose() { this.interrupt(); this.disposed = true; }
}
