import { htmlSHA256, htmlUUID } from './htmlRevision';
import { checkedSigningActor, checkedSigningCollection, checkedSigningContext, checkedSigningGrant, checkedSigningReference, checkedSigningWorkflow, signingKey,
  type SigningActor, type SigningContext, type SigningGrantView, type SigningReference, type SigningWorkflowView } from './signingRegistry';

export const preSignMarkerKey = 'hash.presign-execution-request.v1';
const invalid = 'The pre-signing response could not be verified. The original request is retained.';
const uuid = (v: unknown): v is string => htmlUUID(v) && v === v.toLowerCase() && v !== '00000000-0000-0000-0000-000000000000';
const integer = (v: unknown, zero = false): v is number => Number.isSafeInteger(v) && (v as number) >= (zero ? 0 : 1);
const text = (v: unknown, max = 4096): v is string => typeof v === 'string' && !!v.trim() && new TextEncoder().encode(v).length <= max && !/[\u0000-\u001f\u007f]/u.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && v.length <= 40 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(Date.parse(`${v.slice(0, 19)}Z`)).toISOString().slice(0, 19) === v.slice(0, 19);
const disclosureText = (v: unknown): v is string => typeof v === 'string' && !!v.trim() && new TextEncoder().encode(v).length <= 32768 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(v);
function object(v: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v) || required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) throw new Error(invalid);
  return v as Record<string, unknown>;
}
function actor(v: Record<string, unknown>) { if (!uuid(v.org_id) || !uuid(v.user_id)) throw new Error(invalid); }
export interface PreSignSource { document_updated_at: string; materialization_id: string; materialization_revision: number; source_commitment: string }
export type PreSignEligibility = { schema_version: 1; org_id: string; user_id: string; document_id: string } & ({ eligible: false } | { eligible: true; source: PreSignSource });
export interface PreSignIntent extends PreSignSource { request_id: string; expected_org_id: string; expected_user_id: string; document_id: string; policy: SigningReference; grant: SigningReference; lawful_basis: 'contract' }
export interface PreSignPreview { schema_version: 1; org_id: string; user_id: string; intent: PreSignIntent; receipt: string; expires_at: string; provider_name: string; provider_email: string; customer_name: string; customer_email: string; disclosure: string; remaining_uses: number }
export interface PreSignResult { command_sha256: string; execution: { id: string; sha256: string }; document_id: string; materialization_id: string; materialization_revision: number; source_commitment: string; visible_pdf_sha256: string; page_count: number; use_number: number; publication: 'sealing' | 'published' | 'expired' | 'completed' }
export interface PreSignDocumentView { schema_version: 1; execution: { id: string; sha256: string }; publication: PreSignResult['publication']; visible_pdf_sha256: string; page_count: number }
export type PreSignView = { schema_version: 1; org_id: string; user_id: string; request_id: string } & ({ state: 'closed' } | { state: 'committed'; result: PreSignResult });
// Recovery storage contains only original actor/request/source identifiers and
// commitments. It never stores a receipt, recipients, signature, source or PDF.
export interface PreSignMarker { version: 1; org_id: string; user_id: string; request_id: string; document_id: string; materialization_id: string; materialization_revision: number; source_commitment: string; command_sha256?: string }
function source(v: unknown): PreSignSource {
  const r = object(v, ['document_updated_at', 'materialization_id', 'materialization_revision', 'source_commitment']);
  if (!timestamp(r.document_updated_at) || !uuid(r.materialization_id) || !integer(r.materialization_revision) || !htmlSHA256(r.source_commitment)) throw new Error(invalid);
  return { ...r } as unknown as PreSignSource;
}
export function checkedPreSignEligibility(v: unknown): PreSignEligibility {
  const r = object(v, ['schema_version', 'org_id', 'user_id', 'document_id', 'eligible'], ['source']); actor(r);
  if (r.schema_version !== 1 || !uuid(r.document_id) || typeof r.eligible !== 'boolean' || (r.eligible ? !Object.hasOwn(r, 'source') : Object.hasOwn(r, 'source'))) throw new Error(invalid);
  return r.eligible ? { ...r, source: source(r.source) } as PreSignEligibility : { ...r } as PreSignEligibility;
}
export function checkedPreSignIntent(v: unknown): PreSignIntent {
  const r = object(v, ['request_id', 'expected_org_id', 'expected_user_id', 'document_id', 'document_updated_at', 'materialization_id', 'materialization_revision', 'source_commitment', 'policy', 'grant', 'lawful_basis']);
  if (![r.request_id, r.expected_org_id, r.expected_user_id, r.document_id].every(uuid) || r.lawful_basis !== 'contract') throw new Error(invalid);
  source({ document_updated_at: r.document_updated_at, materialization_id: r.materialization_id, materialization_revision: r.materialization_revision, source_commitment: r.source_commitment });
  return { ...r, policy: checkedSigningReference(r.policy), grant: checkedSigningReference(r.grant) } as unknown as PreSignIntent;
}
export function checkedPreSignPreview(v: unknown): PreSignPreview {
  const r = object(v, ['schema_version', 'org_id', 'user_id', 'intent', 'receipt', 'expires_at', 'provider_name', 'provider_email', 'customer_name', 'customer_email', 'disclosure', 'remaining_uses']); actor(r);
  const intent = checkedPreSignIntent(r.intent);
  if (r.schema_version !== 1 || intent.expected_org_id !== r.org_id || intent.expected_user_id !== r.user_id || !text(r.receipt, 16384) || /\s/u.test(r.receipt) || !timestamp(r.expires_at)
      || ![r.provider_name, r.provider_email, r.customer_name, r.customer_email].every(v => text(v)) || !disclosureText(r.disclosure) || !integer(r.remaining_uses)) throw new Error(invalid);
  return { ...r, intent } as unknown as PreSignPreview;
}
export function checkedPreSignView(v: unknown): PreSignView {
  const r = object(v, ['schema_version', 'org_id', 'user_id', 'request_id', 'state'], ['result']); actor(r);
  if (r.schema_version !== 1 || !uuid(r.request_id)) throw new Error(invalid);
  if (r.state === 'closed') { if (Object.hasOwn(r, 'result')) throw new Error(invalid); return { ...r } as PreSignView; }
  if (r.state !== 'committed') throw new Error(invalid);
  const x = object(r.result, ['command_sha256', 'execution', 'document_id', 'materialization_id', 'materialization_revision', 'source_commitment', 'visible_pdf_sha256', 'page_count', 'use_number', 'publication']);
  const execution = object(x.execution, ['id', 'sha256']);
  if (!htmlSHA256(x.command_sha256) || !uuid(execution.id) || !htmlSHA256(execution.sha256) || !uuid(x.document_id) || !uuid(x.materialization_id) || !integer(x.materialization_revision)
      || !htmlSHA256(x.source_commitment) || !htmlSHA256(x.visible_pdf_sha256) || !integer(x.page_count) || x.page_count > 500 || !integer(x.use_number) || !['sealing', 'published', 'expired', 'completed'].includes(x.publication as string)) throw new Error(invalid);
  return { ...r, result: { ...x, execution: { ...execution } } } as PreSignView;
}
export function checkedPreSignDocumentView(v: unknown): PreSignDocumentView {
  const r = object(v, ['schema_version', 'execution', 'publication', 'visible_pdf_sha256', 'page_count']);
  const execution = object(r.execution, ['id', 'sha256']);
  if (r.schema_version !== 1 || !uuid(execution.id) || !htmlSHA256(execution.sha256) || !htmlSHA256(r.visible_pdf_sha256) || !integer(r.page_count) || r.page_count > 500 || !['sealing', 'published', 'expired', 'completed'].includes(r.publication as string)) throw new Error(invalid);
  return { ...r, execution: { ...execution } } as PreSignDocumentView;
}
export function preSignDocumentMatchesResult(view: PreSignDocumentView, result: PreSignResult): boolean {
  const allowed: Record<PreSignResult['publication'], PreSignResult['publication'][]> = { sealing: ['sealing', 'published', 'expired', 'completed'], published: ['published', 'expired', 'completed'], expired: ['expired'], completed: ['completed'] };
  return view.execution.id === result.execution.id && view.execution.sha256 === result.execution.sha256 && view.visible_pdf_sha256 === result.visible_pdf_sha256 && view.page_count === result.page_count && allowed[result.publication].includes(view.publication);
}
export function checkedPreSignMarker(v: unknown): PreSignMarker {
  const r = object(v, ['version', 'org_id', 'user_id', 'request_id', 'document_id', 'materialization_id', 'materialization_revision', 'source_commitment'], ['command_sha256']); actor(r);
  if (r.version !== 1 || ![r.request_id, r.document_id, r.materialization_id].every(uuid) || !integer(r.materialization_revision) || !htmlSHA256(r.source_commitment) || (Object.hasOwn(r, 'command_sha256') && !htmlSHA256(r.command_sha256))) throw new Error(invalid);
  return { ...r } as unknown as PreSignMarker;
}
export function readPreSignMarker(storage: Pick<Storage, 'getItem'>): { marker: PreSignMarker | null; invalid: boolean } {
  try { const raw = storage.getItem(preSignMarkerKey); if (raw === null) return { marker: null, invalid: false }; if (raw.length > 4096) throw new Error(invalid); return { marker: checkedPreSignMarker(JSON.parse(raw)), invalid: false }; }
  catch { return { marker: null, invalid: true }; }
}
export function savePreSignMarker(storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>, marker: PreSignMarker | null) {
  const raw = marker ? JSON.stringify(checkedPreSignMarker(marker)) : null;
  if (raw === null) storage.removeItem(preSignMarkerKey); else storage.setItem(preSignMarkerKey, raw);
  if (storage.getItem(preSignMarkerKey) !== raw) throw new Error('The original request could not be saved safely. No new request may be sent.');
}
export interface PreSignTransport {
  identity(signal: AbortSignal): Promise<unknown>; context(signal: AbortSignal): Promise<unknown>;
  grants(signal: AbortSignal): Promise<unknown>; workflows(signal: AbortSignal): Promise<unknown>;
  eligibility(document: string, signal: AbortSignal): Promise<unknown>;
  preview(intent: PreSignIntent, signal: AbortSignal): Promise<unknown>;
  execute(input: { intent: PreSignIntent; receipt: string; confirmed: true }, signal: AbortSignal): Promise<unknown>;
  inspect(marker: PreSignMarker, signal: AbortSignal): Promise<unknown>; close(marker: PreSignMarker, signal: AbortSignal): Promise<unknown>;
}
export interface PreSignChoice { grant: SigningGrantView; workflow: SigningWorkflowView }
export interface PreSignState { context: SigningContext | null; eligibility: PreSignEligibility | null; choices: PreSignChoice[]; fresh: boolean; busy: string | null; preview: PreSignPreview | null; confirmed: boolean; marker: PreSignMarker | null; markerError: boolean; outcome: PreSignView | null; error: string | null }
export const initialPreSignState = (): PreSignState => ({ context: null, eligibility: null, choices: [], fresh: false, busy: null, preview: null, confirmed: false, marker: null, markerError: false, outcome: null, error: null });
function safeError(error: unknown) {
  const status = error && typeof error === 'object' && 'status' in error ? (error as { status: unknown }).status : null;
  return status === 401 ? 'Sign in again as the original member, then inspect the same request.' : status === 403 ? 'The original authority is no longer available. The original request is retained.'
    : status === 404 ? 'No outcome is confirmed. Inspect or explicitly close the original request; do not send again.'
      : status === 409 ? 'The document, authority or original request changed. Resolve the original request and review again.'
        : status === 503 ? 'Pre-signing is temporarily unavailable. The original request is retained; do not send again.' : invalid;
}
export class PreSignController {
  state = initialPreSignState(); private epoch = 0; private abort: AbortController | null = null; private disposed = false;
  constructor(private transport: PreSignTransport, private changed: (state: PreSignState) => void, private persist: (marker: PreSignMarker | null) => void, private now = () => Date.now()) {}
  private update(patch: Partial<PreSignState>) { this.state = { ...this.state, ...patch }; this.changed(this.state); }
  private start(busy: string) { this.abort?.abort(); this.abort = new AbortController(); const epoch = ++this.epoch; this.update({ busy, error: null }); return { epoch, signal: this.abort.signal }; }
  private current(epoch: number) { return !this.disposed && epoch === this.epoch; }
  private sameActor(actual: { org_id: string; user_id: string }, expected: { org_id: string; user_id: string }) { if (actual.org_id !== expected.org_id || actual.user_id !== expected.user_id) throw new Error(invalid); }
  private async identity(signal: AbortSignal, expected?: { org_id: string; user_id: string; role?: SigningActor['role'] }) { const value = checkedSigningActor(await this.transport.identity(signal)); if (expected) { this.sameActor(value, expected); if (expected.role && value.role !== expected.role) throw new Error(invalid); } return value; }
  private marker(value: PreSignMarker | null) { try { this.persist(value); this.update({ marker: value }); } catch (error) { this.update({ markerError: true }); throw error; } }
  restore(marker: PreSignMarker | null, markerError = false) { this.update({ marker: marker ? checkedPreSignMarker(marker) : null, markerError }); }
  draftChanged() { if (!this.state.marker) { this.abort?.abort(); this.epoch++; this.update({ busy: null, preview: null, confirmed: false }); } }
  invalidate() { this.abort?.abort(); this.epoch++; this.update({ busy: null, fresh: false, preview: null, confirmed: false, eligibility: null, choices: [] }); }
  dispose() { this.invalidate(); this.disposed = true; }
  get canPrepare() { return !this.disposed && this.state.fresh && !this.state.busy && !this.state.marker && !this.state.markerError && this.state.context?.execution_available === true && ['owner', 'sender'].includes(this.state.context.self.role) && this.state.eligibility?.eligible === true && this.state.choices.length > 0; }
  get canConfirm() { return this.canPrepare && !!this.state.preview && this.state.confirmed && Date.parse(this.state.preview.expires_at) > this.now(); }
  confirm(value: boolean) { this.update({ confirmed: value === true && !!this.state.preview }); }
  async refresh(documentID: string) {
    if (this.disposed || this.state.busy) return;
    const { epoch, signal } = this.start('refresh'); this.update({ fresh: false, preview: null, confirmed: false, choices: [], eligibility: null });
    try {
      const who = await this.identity(signal, this.state.marker ?? undefined); if (!this.current(epoch)) return;
      const context = checkedSigningContext(await this.transport.context(signal)); this.sameActor(context, who); if (context.self.role !== who.role) throw new Error(invalid);
      const eligibility = checkedPreSignEligibility(await this.transport.eligibility(documentID, signal)); this.sameActor(eligibility, who);
      if (eligibility.document_id !== documentID) throw new Error(invalid);
      const grants = checkedSigningCollection(await this.transport.grants(signal), checkedSigningGrant), workflows = checkedSigningCollection(await this.transport.workflows(signal), checkedSigningWorkflow);
      this.sameActor(grants, who); this.sameActor(workflows, who);
      const choices: PreSignChoice[] = [];
      for (const grant of grants.items) {
        if (!grant.execution_available || grant.revoked || grant.expired || grant.current_revision !== grant.grant.revision || grant.grant.grantor.user_id !== who.user_id || grant.consumed_uses >= grant.grant.max_uses) continue;
        const workflow = workflows.items.find(w => !w.archived && !w.retired && w.current_revision === w.definition.revision && signingKey(w.policy_reference) === signingKey(grant.grant.policy)
          && w.definition.executor.kind === 'member' && w.definition.executor.user_id === who.user_id);
        if (workflow) choices.push({ grant, workflow });
      }
      await this.identity(signal, who); if (!this.current(epoch)) return;
      this.update({ context, eligibility, choices, fresh: true });
    } catch (error) { if (this.current(epoch)) this.update({ error: safeError(error), fresh: false }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async preview(grantKey: string, lawfulBasis: 'contract', expectedSourceCommitment: string) {
    if (!this.canPrepare || lawfulBasis !== 'contract') return;
    const eligibility = this.state.eligibility!, context = this.state.context!, choice = this.state.choices.find(c => signingKey(c.grant.reference) === grantKey);
    if (!eligibility.eligible || !choice || eligibility.source.source_commitment !== expectedSourceCommitment) { this.invalidate(); return; }
    const intent = checkedPreSignIntent({ request_id: crypto.randomUUID(), expected_org_id: context.org_id, expected_user_id: context.user_id, document_id: eligibility.document_id, ...eligibility.source, policy: choice.workflow.policy_reference, grant: choice.grant.reference, lawful_basis: lawfulBasis });
    const { epoch, signal } = this.start('preview'); this.update({ preview: null, confirmed: false });
    try {
      const expected = { org_id: context.org_id, user_id: context.user_id, role: context.self.role };
      await this.identity(signal, expected); if (!this.current(epoch)) return;
      const currentSource = checkedPreSignEligibility(await this.transport.eligibility(eligibility.document_id, signal));
      if (!this.current(epoch)) return;
      if (signingKey(currentSource) !== signingKey(eligibility)) throw new Error(invalid);
      const preview = checkedPreSignPreview(await this.transport.preview(intent, signal)); this.sameActor(preview, context);
      if (signingKey(preview.intent) !== signingKey(intent)) throw new Error(invalid);
      await this.identity(signal, expected); if (!this.current(epoch)) return;
      if (Date.parse(preview.expires_at) <= this.now()) throw new Error(invalid);
      this.update({ preview });
    } catch (error) { if (this.current(epoch)) this.update({ error: safeError(error), fresh: false }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  private checkedOutcome(raw: unknown, marker: PreSignMarker) {
    const outcome = checkedPreSignView(raw); this.sameActor(outcome, marker);
    if (outcome.request_id !== marker.request_id) throw new Error(invalid);
    if (outcome.state === 'committed') {
      const x = outcome.result;
      if (x.document_id !== marker.document_id || x.materialization_id !== marker.materialization_id || x.materialization_revision !== marker.materialization_revision || x.source_commitment !== marker.source_commitment || (marker.command_sha256 && x.command_sha256 !== marker.command_sha256)) throw new Error(invalid);
    }
    return outcome;
  }
  async execute() {
    if (!this.canConfirm) return;
    const preview = this.state.preview!, expected = { org_id: preview.org_id, user_id: preview.user_id, role: this.state.context!.self.role }, { epoch, signal } = this.start('execute');
    try {
      await this.identity(signal, expected); if (!this.current(epoch)) return;
      const eligible = checkedPreSignEligibility(await this.transport.eligibility(preview.intent.document_id, signal)); this.sameActor(eligible, expected);
      if (!this.current(epoch)) return;
      if (!eligible.eligible || signingKey(eligible.source) !== signingKey({ document_updated_at: preview.intent.document_updated_at, materialization_id: preview.intent.materialization_id, materialization_revision: preview.intent.materialization_revision, source_commitment: preview.intent.source_commitment }) || eligible.document_id !== preview.intent.document_id || Date.parse(preview.expires_at) <= this.now()) throw new Error(invalid);
      await this.identity(signal, expected); if (!this.current(epoch)) return;
      const marker: PreSignMarker = { version: 1, org_id: expected.org_id, user_id: expected.user_id, request_id: preview.intent.request_id, document_id: preview.intent.document_id, materialization_id: preview.intent.materialization_id, materialization_revision: preview.intent.materialization_revision, source_commitment: preview.intent.source_commitment };
      this.marker(marker); // Must succeed durably before the first effectful request.
      const outcome = this.checkedOutcome(await this.transport.execute({ intent: preview.intent, receipt: preview.receipt, confirmed: true }, signal), marker);
      await this.identity(signal, expected); if (!this.current(epoch)) return;
      if (outcome.state === 'committed') this.marker({ ...marker, command_sha256: outcome.result.command_sha256 });
      this.update({ outcome, preview: null, confirmed: false, fresh: false });
    } catch (error) { if (this.current(epoch)) this.update({ error: safeError(error), preview: null, confirmed: false, fresh: false }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async inspect() { await this.resolve(false); }
  async close(confirmed: boolean) { if (confirmed) await this.resolve(true); }
  private async resolve(close: boolean) {
    if (this.disposed || this.state.busy || !this.state.marker || this.state.markerError || (close && (this.state.marker.command_sha256 || this.state.outcome?.state === 'committed'))) return;
    const marker = this.state.marker, { epoch, signal } = this.start(close ? 'close' : 'inspect');
    try {
      await this.identity(signal, marker);
      if (!this.current(epoch)) return;
      const outcome = this.checkedOutcome(await (close ? this.transport.close(marker, signal) : this.transport.inspect(marker, signal)), marker);
      await this.identity(signal, marker); if (!this.current(epoch)) return;
      if (outcome.state === 'committed') this.marker({ ...marker, command_sha256: outcome.result.command_sha256 });
      this.update({ outcome, fresh: false, preview: null, confirmed: false });
    } catch (error) { if (this.current(epoch)) this.update({ error: safeError(error) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async acknowledge() {
    if (this.disposed || this.state.busy || !this.state.marker || !this.state.outcome || (this.state.outcome.state === 'committed' && this.state.outcome.result.publication === 'sealing')) return;
    const marker = this.state.marker, { epoch, signal } = this.start('acknowledge');
    try {
      await this.identity(signal, marker); if (!this.current(epoch)) return;
      this.checkedOutcome(this.state.outcome, marker); this.marker(null); this.update({ outcome: null, fresh: false, preview: null, confirmed: false });
    } catch (error) { if (this.current(epoch)) this.update({ error: safeError(error) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
}
