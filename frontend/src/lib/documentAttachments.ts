import type { DocumentResponse } from './api/client';
import type { PackageSendObservation } from './packageSend';
import { htmlSHA256 } from './htmlRevision';

export type AttachmentActor = { org_id: string; user_id: string; role: 'owner' | 'sender' };
export type AttachmentMember = { document_id: string; ordinal: number; title: string; category: string; pdf_version_id: string; pdf_sha256: string; pdf_bytes: number; pdf_pages: number };
export type AttachmentInventory = { schema: 'hash-document-attachments-v1'; document_id: string; updated_at: string; package_id: string; generation: string; requires_reselection: boolean; members: AttachmentMember[] };
export type AttachmentLabel = Pick<AttachmentMember, 'document_id' | 'title' | 'category'>;
export type AttachmentExpected = { expected_updated_at: string; expected_package_id: string; expected_generation: string };
export type AttachmentSelection = AttachmentExpected & { member_document_id: string; expected_member_updated_at: string; ordinal: number; title: string; category: string };
export type AttachmentLayout = AttachmentExpected & { members: AttachmentLabel[] };
export type AttachmentOutcome = { state: 'committed' | 'unchanged' | 'unknown'; reconciliation_required: boolean; message?: string; attachment?: { package_id: string; member_document_id: string; ordinal: number; generation: string; updated_at: string; event_id: string }; layout?: { package_id: string; generation: string; updated_at: string; changed_rows: number; event_id: string } };
export type AttachmentPage = { documents: DocumentResponse[]; total: number; limit: number; offset: number };
export const attachmentInvalid = 'The saved attachments could not be verified. Refresh and inspect the saved state before continuing.';
const zeroUUID = '00000000-0000-0000-0000-000000000000';
export const attachmentUUID = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v) && v !== zeroUUID;
export const attachmentTime = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0, 19) === v.slice(0, 19);
export function attachmentGeneration(v: unknown, empty = false): v is string { return typeof v === 'string' && (empty && v === '0' || /^[1-9][0-9]{0,18}$/.test(v) && BigInt(v) <= 9223372036854775807n); }
function record(v: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
 if (!v || typeof v !== 'object' || Array.isArray(v) || !required.every(k => Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) throw new Error(attachmentInvalid);
 return v as Record<string, unknown>;
}
export function attachmentLabel(v: unknown, optional = false): v is string { return typeof v === 'string' && new TextEncoder().encode(v).length <= (optional ? 128 : 512) && (optional && v === '' || v.length > 0 && v.trim() === v) && !/[\p{Cc}\p{Cs}\u2028\u2029]/u.test(v); }
export function checkedAttachmentActor(v: unknown): AttachmentActor { const a = v as AttachmentActor; if (!a || !attachmentUUID(a.org_id) || !attachmentUUID(a.user_id) || !['owner', 'sender'].includes(a.role)) throw new Error(attachmentInvalid); return { org_id: a.org_id, user_id: a.user_id, role: a.role }; }
export function checkedAttachmentDocument(v: unknown): DocumentResponse {
 const d = v as DocumentResponse;
 if (!d || !attachmentUUID(d.id) || !attachmentUUID(d.org_id) || !attachmentUUID(d.sender_id) || !attachmentTime(d.updated_at) || typeof d.name !== 'string' || new TextEncoder().encode(d.name).length > 4096 || d.source_kind !== 'pdf' || d.status !== 'draft' || d.is_envelope || d.parent_envelope_id || !htmlSHA256(d.pdf_sha256) || (d.has_html_source !== undefined && typeof d.has_html_source !== 'boolean') || (d.has_html_source && (!htmlSHA256(d.html_source_commitment) || !Number.isSafeInteger(d.html_materialization_revision) || d.html_materialization_revision! < 1))) throw new Error(attachmentInvalid);
 return JSON.parse(JSON.stringify(d)) as DocumentResponse;
}
export function checkedAttachmentInventory(v: unknown): AttachmentInventory {
 const a = record(v, ['schema', 'document_id', 'updated_at', 'package_id', 'generation', 'requires_reselection', 'members']);
 if (a.schema !== 'hash-document-attachments-v1' || !attachmentUUID(a.document_id) || !attachmentTime(a.updated_at) || !attachmentGeneration(a.generation, true) || typeof a.requires_reselection !== 'boolean' || !Array.isArray(a.members) || a.members.length > 16 || (a.package_id === '' ? a.generation !== '0' || a.members.length !== 0 || a.requires_reselection : !attachmentUUID(a.package_id) || a.generation === '0')) throw new Error(attachmentInvalid);
 const ids = new Set<string>(); let previous = 0;
 const members = a.members.map(value => { const m = record(value, ['document_id', 'ordinal', 'title', 'category', 'pdf_version_id', 'pdf_sha256', 'pdf_bytes', 'pdf_pages']);
  if (!attachmentUUID(m.document_id) || m.document_id === a.document_id || ids.has(m.document_id) || !Number.isInteger(m.ordinal) || (m.ordinal as number) <= previous || (m.ordinal as number) > 16 || !attachmentLabel(m.title) || !attachmentLabel(m.category, true) || typeof m.pdf_version_id !== 'string' || !m.pdf_version_id || new TextEncoder().encode(m.pdf_version_id).length > 1024 || /[\p{Cc}\p{Cs}]/u.test(m.pdf_version_id) || ['null', 'hash:unversioned-development'].includes(m.pdf_version_id.trim()) || !htmlSHA256(m.pdf_sha256) || !Number.isSafeInteger(m.pdf_bytes) || (m.pdf_bytes as number) < 1 || (m.pdf_bytes as number) > 50 * 1024 * 1024 || !Number.isInteger(m.pdf_pages) || (m.pdf_pages as number) < 1 || (m.pdf_pages as number) > 500) throw new Error(attachmentInvalid);
  ids.add(m.document_id); previous = m.ordinal as number; return { ...m } as AttachmentMember;
 });
 return { ...a, members } as AttachmentInventory;
}
export const attachmentExpected = (v: AttachmentInventory): AttachmentExpected => { const a = checkedAttachmentInventory(v); return { expected_updated_at: a.updated_at, expected_package_id: a.package_id, expected_generation: a.generation }; };
export function checkedAttachmentLayout(v: AttachmentLayout): AttachmentLayout {
 if (!attachmentTime(v.expected_updated_at) || !attachmentUUID(v.expected_package_id) || !attachmentGeneration(v.expected_generation) || !Array.isArray(v.members) || v.members.length > 16) throw new Error(attachmentInvalid);
 const ids = new Set<string>(); const members = v.members.map(m => { if (!attachmentUUID(m.document_id) || ids.has(m.document_id) || !attachmentLabel(m.title) || !attachmentLabel(m.category, true)) throw new Error(attachmentInvalid); ids.add(m.document_id); return { document_id: m.document_id, title: m.title, category: m.category }; });
 return { expected_updated_at: v.expected_updated_at, expected_package_id: v.expected_package_id, expected_generation: v.expected_generation, members };
}
export function checkedAttachmentSelection(v: AttachmentSelection): AttachmentSelection {
 if (!attachmentTime(v.expected_updated_at) || !(v.expected_package_id === '' ? v.expected_generation === '0' : attachmentUUID(v.expected_package_id) && attachmentGeneration(v.expected_generation)) || !attachmentUUID(v.member_document_id) || !attachmentTime(v.expected_member_updated_at) || !Number.isInteger(v.ordinal) || v.ordinal < 1 || v.ordinal > 16 || !attachmentLabel(v.title) || !attachmentLabel(v.category, true)) throw new Error(attachmentInvalid);
 return { expected_updated_at: v.expected_updated_at, expected_package_id: v.expected_package_id, expected_generation: v.expected_generation, member_document_id: v.member_document_id, expected_member_updated_at: v.expected_member_updated_at, ordinal: v.ordinal, title: v.title, category: v.category };
}
export function checkedAttachmentOutcome(v: unknown, kind: 'select' | 'layout'): AttachmentOutcome {
 const a = record(v, ['state', 'reconciliation_required'], ['message', 'attachment', 'layout']);
 if (!['committed', 'unchanged', 'unknown'].includes(a.state as string) || typeof a.reconciliation_required !== 'boolean' || (a.message !== undefined && (typeof a.message !== 'string' || a.message.length > 2048))) throw new Error(attachmentInvalid);
 if (a.state === 'unknown') { if (!a.reconciliation_required || a.attachment !== undefined || a.layout !== undefined) throw new Error(attachmentInvalid); return a as AttachmentOutcome; }
 if (kind === 'select') { const r = record(a.attachment, ['package_id', 'member_document_id', 'ordinal', 'generation', 'updated_at', 'event_id']);
  if (a.state !== 'committed' || a.layout !== undefined || !attachmentUUID(r.package_id) || !attachmentUUID(r.member_document_id) || !attachmentUUID(r.event_id) || !attachmentGeneration(r.generation) || !attachmentTime(r.updated_at) || !Number.isInteger(r.ordinal) || (r.ordinal as number) < 1 || (r.ordinal as number) > 16) throw new Error(attachmentInvalid);
 } else { const r = record(a.layout, ['package_id', 'generation', 'updated_at', 'changed_rows', 'event_id']);
  if (a.attachment !== undefined || !attachmentUUID(r.package_id) || !attachmentGeneration(r.generation) || !attachmentTime(r.updated_at) || !Number.isSafeInteger(r.changed_rows) || (r.changed_rows as number) < 0 || (r.changed_rows as number) > 16 || (a.state === 'unchanged' ? r.changed_rows !== 0 || r.event_id !== zeroUUID : r.changed_rows === 0 || !attachmentUUID(r.event_id))) throw new Error(attachmentInvalid);
 }
 return structuredClone(a) as AttachmentOutcome;
}
export const attachmentMemberKey = (m: AttachmentMember) => JSON.stringify([m.document_id,m.ordinal,m.title,m.category,m.pdf_version_id,m.pdf_sha256,m.pdf_bytes,m.pdf_pages]);
export const attachmentLabels = (v: AttachmentInventory): AttachmentLabel[] => v.members.map(({ document_id, title, category }) => ({ document_id, title, category }));
export const attachmentLabelsKey = (v: AttachmentLabel[]) => JSON.stringify(v.map(m => [m.document_id, m.title, m.category]));
export const attachmentRootKey = (d: DocumentResponse) => JSON.stringify([d.id,d.org_id,d.sender_id,d.template_id,d.status,d.source_kind,d.has_html_source,d.html_review_required,d.pdf_sha256,d.html_source_commitment,d.html_materialization_revision,d.variables_json,d.blocks_json,d.metadata,d.requires_signature,d.routing_mode,d.default_locale,d.name,d.expires_at,d.is_envelope,d.parent_envelope_id,d.routing_tier,d.created_at,d.sent_at,d.completed_at]);
export const attachmentDocumentKey = (d: DocumentResponse) => JSON.stringify([attachmentRootKey(d), d.updated_at]);
export const attachmentPreviewKey = (org: string, v: AttachmentInventory, m: AttachmentMember) => JSON.stringify([org,v.document_id,v.updated_at,v.package_id,v.generation,m.document_id,m.pdf_version_id,m.pdf_sha256,m.pdf_bytes,m.pdf_pages]);


export type AttachmentTransport = { identity(signal: AbortSignal): Promise<unknown>; document(id: string, signal: AbortSignal): Promise<DocumentResponse>; inventory(id: string, signal: AbortSignal): Promise<AttachmentInventory>; choices(offset: number, signal: AbortSignal): Promise<AttachmentPage>; select(id: string, input: AttachmentSelection, signal: AbortSignal): Promise<AttachmentOutcome>; layout(id: string, input: AttachmentLayout, signal: AbortSignal): Promise<AttachmentOutcome> };
export type AttachmentReadback = { document: DocumentResponse; inventory: AttachmentInventory };
export type AttachmentState = { baseline: AttachmentInventory | null; draft: AttachmentLabel[]; candidate: DocumentResponse | null; choices: AttachmentPage | null; busy: 'refresh' | 'choices' | 'candidate' | 'select' | 'layout' | 'readback' | null; fresh: boolean; needsReadback: boolean; readback: AttachmentReadback | null; error: string | null; notice: string | null };
export const initialAttachmentState = (): AttachmentState => ({ baseline: null, draft: [], candidate: null, choices: null, busy: null, fresh: false, needsReadback: false, readback: null, error: null, notice: null });
function status(error: unknown): number { return error && typeof error === 'object' && 'status' in error && typeof error.status === 'number' ? error.status : 0; }
export class DocumentAttachmentsController {
 state = initialAttachmentState(); private epoch = 0; private abort: AbortController | null = null; private disposed = false;
 constructor(private doc: DocumentResponse, private actor: AttachmentActor, private transport: AttachmentTransport, private changed: (value: AttachmentState) => void, private clean: () => boolean, private adopt: (next: DocumentResponse, expectedUpdatedAt: string) => boolean) { this.doc = checkedAttachmentDocument(doc); this.actor = checkedAttachmentActor(actor); }
 private update(value: Partial<AttachmentState>) { if (!this.disposed) { this.state = { ...this.state, ...value }; this.changed(this.state); } }
 private current(epoch: number) { return !this.disposed && this.epoch === epoch && !this.abort?.signal.aborted; }
 private start(busy: AttachmentState['busy']) { this.abort?.abort(); this.abort = new AbortController(); const epoch = ++this.epoch; this.update({ busy, error: null, notice: null }); return { epoch, signal: this.abort.signal }; }
 private async identity(signal: AbortSignal) { const a = checkedAttachmentActor(await this.transport.identity(signal)); if (a.org_id !== this.actor.org_id || a.user_id !== this.actor.user_id || a.role !== this.actor.role || (a.role !== 'owner' && this.doc.sender_id !== a.user_id)) throw new Error(attachmentInvalid); }
 private eligible(d: DocumentResponse) { return d.id !== this.doc.id && d.org_id === this.doc.org_id && d.status === 'draft' && d.source_kind === 'pdf' && !d.is_envelope && !d.parent_envelope_id && (this.actor.role === 'owner' || d.sender_id === this.actor.user_id) && !this.state.baseline?.members.some(m => m.document_id === d.id); }
 private async read(signal: AbortSignal): Promise<AttachmentReadback> { await this.identity(signal); const d = checkedAttachmentDocument(await this.transport.document(this.doc.id, signal)); if (d.id !== this.doc.id || d.org_id !== this.actor.org_id || d.sender_id !== this.doc.sender_id) throw new Error(attachmentInvalid); const inventory = checkedAttachmentInventory(await this.transport.inventory(d.id, signal)); if (inventory.document_id !== d.id || inventory.updated_at !== d.updated_at) throw new Error(attachmentInvalid); await this.identity(signal); return { document: d, inventory }; }
 dirty() { return !!this.state.baseline && attachmentLabelsKey(this.state.draft) !== attachmentLabelsKey(attachmentLabels(this.state.baseline)); }
 barrier() { return this.dirty() || this.state.needsReadback || this.mutating(); }
 mutating() { return this.state.busy === 'select' || this.state.busy === 'layout'; }
 sendBlocked() { return !this.state.fresh || !!this.state.busy || this.state.needsReadback || this.dirty() || !this.state.baseline || this.state.baseline.requires_reselection; }
 sendObservation(): PackageSendObservation | undefined { if (this.sendBlocked() || !this.state.baseline?.members.length) return undefined; const v=this.state.baseline; return {expected_updated_at:v.updated_at,package_id:v.package_id,generation:v.generation}; }
 canEdit() { return !this.disposed && this.clean() && this.state.fresh && !this.state.needsReadback && !this.state.busy && !!this.state.baseline; }
 vacantOrdinal() { return Array.from({ length: 16 }, (_, i) => i + 1).find(n => !this.state.baseline?.members.some(m => m.ordinal === n)) ?? 0; }
 canSelect() { return this.canEdit() && !this.dirty() && !!this.state.candidate && this.eligible(this.state.candidate) && !this.doc.html_review_required && !this.state.candidate.html_review_required && this.vacantOrdinal() > 0; }
 syncDocument(d: DocumentResponse, actor: AttachmentActor) {
  if (attachmentDocumentKey(d) === attachmentDocumentKey(this.doc) && JSON.stringify(actor) === JSON.stringify(this.actor)) return;
  this.interrupt();
  if (d.id !== this.doc.id || d.org_id !== this.doc.org_id || actor.org_id !== this.actor.org_id || actor.user_id !== this.actor.user_id) { this.update({ error: 'The document or account changed. Reload this page.' }); return; }
  this.doc = checkedAttachmentDocument(d); this.actor = checkedAttachmentActor(actor); this.update({ needsReadback: !!this.state.baseline, readback: null, error: 'The displayed agreement changed. Inspect saved attachments; local attachment edits are retained.' });
 }
 interrupt() { this.epoch++; this.abort?.abort(); this.abort = null; this.update({ busy: null, fresh: false, needsReadback: this.state.needsReadback || this.mutating(), readback: null }); }
 requireSendReadback() {
  if (this.disposed) return;
  this.interrupt();
  this.update({ fresh: false, needsReadback: true, readback: null, error: 'Send refused the earlier document or attachment selection. Inspect the saved agreement and explicitly use the reviewed selection before sending again.' });
 }
 dispose() { this.interrupt(); this.disposed = true; }
 private baseline(r: AttachmentReadback) { return { baseline: r.inventory, draft: attachmentLabels(r.inventory), candidate: null, fresh: true, needsReadback: false, readback: null }; }
 async refresh() {
  if (this.disposed || this.state.busy || this.state.needsReadback || this.dirty()) return;
  const op = this.start('refresh'); this.update({ fresh: false });
  try { const r = await this.read(op.signal); if (!this.current(op.epoch)) return;
   if (attachmentDocumentKey(r.document) !== attachmentDocumentKey(this.doc)) { this.update({ needsReadback: true, readback: r, error: 'A newer agreement is saved. Inspect it before loading attachments.' }); return; }
   this.update(this.baseline(r));
  } catch { if (this.current(op.epoch)) this.update({ fresh: false, error: attachmentInvalid }); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 async list(offset = 0) {
  if (!this.canEdit()) return; const op = this.start('choices');
  try { await this.identity(op.signal); const r = await this.transport.choices(offset, op.signal); if (!this.current(op.epoch)) return; await this.identity(op.signal); if (!this.current(op.epoch)) return;
   this.update({ choices: { ...r, documents: r.documents.filter(d => this.eligible(d)).map(d => checkedAttachmentDocument(d)) } });
  } catch { if (this.current(op.epoch)) this.update({ choices: null, error: 'Document choices could not be verified. Refresh attachments before trying again.' }); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 async choose(id: string) {
  if (!this.canEdit() || this.dirty() || !this.state.choices?.documents.some(d => d.id === id)) return;
  const op = this.start('candidate');
  try { await this.identity(op.signal); const d = checkedAttachmentDocument(await this.transport.document(id, op.signal)); if (!this.current(op.epoch)) return; if (!this.eligible(d)) throw new Error(attachmentInvalid); await this.identity(op.signal); if (!this.current(op.epoch)) return; this.update({ candidate: d }); }
  catch { if (this.current(op.epoch)) this.update({ candidate: null, error: 'This source is unavailable or changed. Open and review the source document before adding it.' }); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 labels(id: string, title: string, category: string) { if (!this.canEdit()) return; this.update({ draft: this.state.draft.map(m => m.document_id === id ? { ...m, title, category } : m) }); }
 move(id: string, delta: -1 | 1) { if (!this.canEdit()) return; const draft = this.state.draft.slice(), index = draft.findIndex(m => m.document_id === id), next = index + delta; if (index < 0 || next < 0 || next >= draft.length) return; [draft[index], draft[next]] = [draft[next], draft[index]]; this.update({ draft }); }
 remove(id: string) { if (this.canEdit()) this.update({ draft: this.state.draft.filter(m => m.document_id !== id) }); }
 clearCandidate() { if (!this.state.busy) this.update({ candidate: null }); }
 undo() { if (this.state.busy || !this.state.baseline) return; this.update({ draft: attachmentLabels(this.state.baseline), candidate: null, notice: 'Unsaved attachment edits were discarded. Saved files are unchanged.' }); }
 private fail(error: unknown, dispatched: boolean) { const code = status(error), reconcile = dispatched && (!code || code >= 500 || code === 409 || code === 401 || code === 403);
  this.update({ fresh: false, needsReadback: reconcile, readback: null, error: reconcile ? 'The save was interrupted, refused as stale, or could not be confirmed. Inspect saved attachments before another write. Local attachment edits are retained.' : error instanceof Error ? error.message : attachmentInvalid }); }
 async select(title: string, category: string) {
  if (!this.canSelect() || !attachmentLabel(title) || !attachmentLabel(category, true)) return;
  const v = this.state.baseline!, candidate = this.state.candidate!, before = this.doc;
  const input = checkedAttachmentSelection({ ...attachmentExpected(v), member_document_id: candidate.id, expected_member_updated_at: candidate.updated_at, ordinal: this.vacantOrdinal(), title, category });
  const op = this.start('select'); let dispatched = false;
  try { await this.identity(op.signal); if (!this.current(op.epoch) || !this.clean()) return; dispatched = true;
   const out = checkedAttachmentOutcome(await this.transport.select(before.id, input, op.signal), 'select'); if (!this.current(op.epoch)) return;
   if (out.state === 'unknown' || out.reconciliation_required) { this.update({ fresh: false, needsReadback: true, error: 'Selection may be saved. Inspect saved attachments before another write; do not add it again.' }); return; }
   const saved = out.attachment!; if (saved.member_document_id !== input.member_document_id || saved.ordinal !== input.ordinal || (v.package_id && saved.package_id !== v.package_id)) throw new Error(attachmentInvalid);
   const r = await this.read(op.signal); if (!this.current(op.epoch)) return; const m = r.inventory.members.find(m => m.document_id === input.member_document_id);
   if (r.inventory.package_id !== saved.package_id || r.inventory.generation !== saved.generation || r.inventory.updated_at !== saved.updated_at || !m || m.title !== title || m.category !== category || m.ordinal !== input.ordinal || m.pdf_sha256 !== candidate.pdf_sha256 || r.inventory.members.length !== v.members.length + 1 || v.members.some(old => !r.inventory.members.some(next => attachmentMemberKey(next) === attachmentMemberKey(old))) || attachmentRootKey(r.document) !== attachmentRootKey(before)) throw new Error(attachmentInvalid);
   if (!this.clean() || !this.adopt(r.document, before.updated_at)) throw new Error(attachmentInvalid); this.doc = r.document; this.update({ ...this.baseline(r), notice: 'The exact attachment was saved. Open its selected PDF below to inspect it.' });
  } catch (e) { if (this.current(op.epoch)) this.fail(e, dispatched); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 async saveLayout(confirmedRemovals: boolean) {
  if (!this.canEdit() || !this.dirty() || !this.state.baseline?.package_id) return;
  const v = this.state.baseline, before = this.doc; const removed = v.members.filter(m => !this.state.draft.some(next => next.document_id === m.document_id)); if (removed.length && !confirmedRemovals) return;
  let input: AttachmentLayout; try { input = checkedAttachmentLayout({ ...attachmentExpected(v), members: this.state.draft }); } catch { this.update({ error: 'Use nonempty titles of at most512 UTF8 bytes and categories of at most128, without surrounding spaces or control characters.' }); return; }
  if (new TextEncoder().encode(JSON.stringify(input)).length > 16384) { this.update({ error: 'Attachment labels exceed16KiB. Shorten them before saving.' }); return; }
  const op = this.start('layout'); let dispatched = false;
  try { await this.identity(op.signal); if (!this.current(op.epoch) || !this.clean()) return; dispatched = true; const out = checkedAttachmentOutcome(await this.transport.layout(before.id, input, op.signal), 'layout'); if (!this.current(op.epoch)) return;
   if (out.state === 'unknown' || out.reconciliation_required) { this.update({ fresh: false, needsReadback: true, error: 'The layout may be saved. Inspect saved attachments before another write; do not repeat this save.' }); return; }
   const saved = out.layout!, r = await this.read(op.signal); if (!this.current(op.epoch)) return;
   if (r.inventory.package_id !== v.package_id || saved.package_id !== v.package_id || r.inventory.generation !== saved.generation || r.inventory.updated_at !== saved.updated_at || attachmentLabelsKey(attachmentLabels(r.inventory)) !== attachmentLabelsKey(input.members) || r.inventory.members.some((m, i) => { const old = v.members.find(x => x.document_id === m.document_id); return !old || m.ordinal !== i + 1 || m.pdf_version_id !== old.pdf_version_id || m.pdf_sha256 !== old.pdf_sha256 || m.pdf_bytes !== old.pdf_bytes || m.pdf_pages !== old.pdf_pages; }) || attachmentRootKey(r.document) !== attachmentRootKey(before)) throw new Error(attachmentInvalid);
   if (!this.clean() || !this.adopt(r.document, before.updated_at)) throw new Error(attachmentInvalid); this.doc = r.document; this.update({ ...this.baseline(r), candidate:this.state.candidate, notice: 'Attachment order, labels and removals are saved. The selected PDF versions are unchanged.' });
  } catch (e) { if (this.current(op.epoch)) this.fail(e, dispatched); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 async inspectReadback() {
  if (this.disposed || this.state.busy || !this.state.needsReadback) return; const op = this.start('readback');
  try { const r = await this.read(op.signal); if (this.current(op.epoch)) this.update({ readback: r }); }
  catch { if (this.current(op.epoch)) this.update({ readback: null, error: attachmentInvalid }); }
  finally { if (this.current(op.epoch)) this.update({ busy: null }); }
 }
 acceptReadback() { const r = this.state.readback; if (!r || !this.state.needsReadback || this.state.busy || !this.clean()) return; if (!this.adopt(r.document, this.doc.updated_at)) { this.update({ error: 'The displayed document changed again. Inspect the saved result again.' }); return; } this.doc = r.document; this.update({ ...this.baseline(r), notice: 'The inspected saved agreement and attachments are loaded. Earlier uncertain requests may still complete; every later save checks the exact clocks again.' }); }
}
