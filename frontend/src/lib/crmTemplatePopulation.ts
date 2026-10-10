import type { DocumentResponse, HTMLDocumentInput, HTMLDocumentSource, TemplateResponse } from './api/client';
import { htmlSHA256, htmlUUID, currentHTMLSource } from './htmlRevision';
import { htmlContractProfile, htmlProfileIssues, htmlProfileSectionValues, htmlSigningPageIssues, htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate } from './htmlTemplate';
import { crmGeneration, crmOpaqueID } from './crmConnection';
import { CRM_KINDS, checkedCRMDocumentActor, crmMappings, crmMappingKey, validCRMSearch,
  type CRMDocumentActor, type CRMDocumentConnection, type CRMKind, type CRMMapping, type CRMField, type CRMChoice, type CRMValueObservation } from './crmDocument';

export { CRM_KINDS, validCRMSearch };
export type { CRMKind, CRMMapping, CRMChoice };
export interface CRMTemplateCandidate { name: string; values: Record<string, string>; sections?: Record<string, string>; expires_at?: string }
export interface CRMTemplateWitness {
  org_id: string; user_id: string; template_id: string; template_version: number; template_content_sha256: string;
  template_approved_by: string; template_approved_at: string; connection: CRMDocumentConnection | null;
}
export interface CRMTemplateExpected {
  expected_org_id: string; expected_user_id: string; expected_template_version: number; expected_template_content_sha256: string;
  expected_template_approved_by: string; expected_template_approved_at: string; expected_connection_id: string; expected_connection_generation: string;
}
export interface CRMTemplateVariable { name: string; required: boolean; max_chars: number; current_present: boolean; current_value: string }
export interface CRMTemplateContext extends CRMTemplateWitness { available: boolean; variables: CRMTemplateVariable[]; catalog: Record<CRMKind, CRMField[]> }
export interface CRMTemplateSearch extends CRMTemplateWitness { kind: CRMKind; query: string; offset: number; choices: CRMChoice[]; has_more: boolean; next_offset: number }
export interface CRMTemplateItem extends CRMMapping { current_present: boolean; current_value: string; available: boolean; value?: string; unavailable_reason?: string; crm_observation?: CRMValueObservation }
export interface CRMTemplateObservation extends CRMTemplateWitness {
  mappings: CRMMapping[]; items: CRMTemplateItem[]; review_digest: string; can_create: boolean; observed_at: string; expires_at: string;
  review_receipt?: string; contract_issues?: { code: string; path: string; message: string }[];
}
export interface CRMTemplatePopulationInput extends CRMTemplateExpected { mappings: CRMMapping[]; reviewed_digest: string; review_receipt: string; confirmed: true }
export interface HTMLCreationPins { document_id: string; html_materialization_id: string; html_source_commitment: string; pdf_sha256: string; page_count: number; created_at: string }
export interface HTMLCreationReadback { state: 'committed'; org_id: string; user_id: string; request_id: string; input_digest: string; template_id: string; document: DocumentResponse | null; creation: HTMLCreationPins }
export interface HTMLCreationClosed { state: 'closed'; org_id: string; user_id: string; template_id: string; request_id: string; closed_at: string }
export type HTMLCreationOutcome = HTMLCreationReadback | HTMLCreationClosed;
export interface HTMLCreationResult { org_id: string; user_id: string; document: DocumentResponse | null; page_count: number; review_required: boolean; request_id: string; input_digest: string; replayed: boolean; creation: HTMLCreationPins }
export interface HTMLCreationMarker { version: 1; org_id: string; user_id: string; template_id: string; request_id: string; input_digest?: string }
export const htmlCreationMarkerKey = 'hash.html-creation-request.v1';
const invalid = 'The template CRM or creation response could not be verified. Your entered information is retained.';
const text = (v: unknown, max = 65536): v is string => typeof v === 'string' && new TextEncoder().encode(v).length <= max;
const time = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && v.length <= 40 && Number.isFinite(Date.parse(v));
const name = (v: unknown): v is string => typeof v === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(v);
function record(v: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v) || !required.every(k => Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) throw new Error(invalid);
  return v as Record<string, unknown>;
}
function list(v: unknown, max: number): unknown[] { if (!Array.isArray(v) || v.length > max) throw new Error(invalid); return v; }
function unique<T>(v: T[], key: (v: T) => string): T[] { if (new Set(v.map(key)).size !== v.length) throw new Error(invalid); return v; }
function strings(v: unknown): Record<string, string> {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length > 64 || Object.entries(v).some(([k, v]) => !name(k) || !text(v, 131072))) throw new Error(invalid);
  return { ...v } as Record<string, string>;
}
export function checkedTemplateCandidate(v: unknown): CRMTemplateCandidate {
  const c = record(v, ['name', 'values'], ['sections', 'expires_at']);
  if (!text(c.name, 800) || !c.name.trim() || Array.from(c.name).length > 200 || c.name.includes('\0') || (Object.hasOwn(c, 'expires_at') && (!text(c.expires_at, 40) || !Number.isFinite(Date.parse(c.expires_at))))) throw new Error(invalid);
  return { name: c.name, values: strings(c.values), ...(Object.hasOwn(c, 'sections') ? { sections: strings(c.sections) } : {}), ...(Object.hasOwn(c, 'expires_at') ? { expires_at: c.expires_at as string } : {}) };
}
export function templateCandidateKey(v: CRMTemplateCandidate): string {
  const c = checkedTemplateCandidate(v);
  return JSON.stringify([c.name, Object.entries(c.values).sort(([a], [b]) => a.localeCompare(b)),
    c.sections === undefined ? null : Object.entries(c.sections).sort(([a], [b]) => a.localeCompare(b)), c.expires_at ?? null]);
}
const witnessKeys = ['org_id', 'user_id', 'template_id', 'template_version', 'template_content_sha256', 'template_approved_by', 'template_approved_at', 'connection'];
function witness(r: Record<string, unknown>): CRMTemplateWitness {
  if (![r.org_id, r.user_id, r.template_id, r.template_approved_by].every(htmlUUID) || !Number.isInteger(r.template_version) || (r.template_version as number) < 1 || !htmlSHA256(r.template_content_sha256) || !time(r.template_approved_at)) throw new Error(invalid);
  let connection: CRMDocumentConnection | null = null;
  if (r.connection !== null) {
    const c = record(r.connection, ['id', 'generation', 'status', 'origin', 'crm_team_id', 'crm_user_id']);
    if (!htmlUUID(c.id) || !crmGeneration(c.generation) || !['candidate', 'active', 'revoked'].includes(c.status as string) || !text(c.origin, 2048) || !crmOpaqueID(c.crm_team_id) || !crmOpaqueID(c.crm_user_id)) throw new Error(invalid);
    const u = new URL(c.origin); if (!['http:', 'https:'].includes(u.protocol) || u.origin !== c.origin || u.username || u.password) throw new Error(invalid);
    connection = c as unknown as CRMDocumentConnection;
  }
  return { org_id: r.org_id, user_id: r.user_id, template_id: r.template_id, template_version: r.template_version, template_content_sha256: r.template_content_sha256,
    template_approved_by: r.template_approved_by, template_approved_at: r.template_approved_at, connection } as CRMTemplateWitness;
}
export const templateWitnessKey = (w: CRMTemplateWitness) => JSON.stringify([w.org_id, w.user_id, w.template_id, w.template_version, w.template_content_sha256, w.template_approved_by, w.template_approved_at,
  w.connection ? [w.connection.id, w.connection.generation, w.connection.status, w.connection.origin, w.connection.crm_team_id, w.connection.crm_user_id] : null]);
export function templateExpected(w: CRMTemplateWitness): CRMTemplateExpected {
  return { expected_org_id: w.org_id, expected_user_id: w.user_id, expected_template_version: w.template_version, expected_template_content_sha256: w.template_content_sha256,
    expected_template_approved_by: w.template_approved_by, expected_template_approved_at: w.template_approved_at,
    expected_connection_id: w.connection?.id ?? '', expected_connection_generation: w.connection?.generation ?? '0' };
}
export function checkedTemplateExpected(e: CRMTemplateExpected): CRMTemplateExpected {
  if (![e.expected_org_id, e.expected_user_id, e.expected_template_approved_by].every(htmlUUID) || !Number.isInteger(e.expected_template_version) || e.expected_template_version < 1
    || !htmlSHA256(e.expected_template_content_sha256) || !time(e.expected_template_approved_at)) throw new Error(invalid);
  if (!crmGeneration(e.expected_connection_generation, true) || (e.expected_connection_generation === '0' ? e.expected_connection_id !== '' : !htmlUUID(e.expected_connection_id))) throw new Error(invalid);
  return { expected_org_id: e.expected_org_id, expected_user_id: e.expected_user_id, expected_template_version: e.expected_template_version, expected_template_content_sha256: e.expected_template_content_sha256,
    expected_template_approved_by: e.expected_template_approved_by, expected_template_approved_at: e.expected_template_approved_at,
    expected_connection_id: e.expected_connection_id, expected_connection_generation: e.expected_connection_generation };
}
export function checkedTemplateContext(v: unknown): CRMTemplateContext {
  const r = record(v, [...witnessKeys, 'available', 'variables', 'catalog']), w = witness(r);
  if (typeof r.available !== 'boolean') throw new Error(invalid);
  const variables = unique(list(r.variables, 64).map(v => {
    const x = record(v, ['name', 'required', 'max_chars', 'current_present', 'current_value']);
    if (!name(x.name) || typeof x.required !== 'boolean' || !Number.isInteger(x.max_chars) || (x.max_chars as number) < 1 || (x.max_chars as number) > 8192
      || typeof x.current_present !== 'boolean' || !text(x.current_value) || (!x.current_present && x.current_value !== '')) throw new Error(invalid);
    return x as unknown as CRMTemplateVariable;
  }), v => v.name);
  const raw = record(r.catalog, [...CRM_KINDS]), catalog = {} as Record<CRMKind, CRMField[]>;
  for (const k of CRM_KINDS) catalog[k] = unique(list(raw[k], 128).map(v => {
    const x = record(v, ['path', 'type', 'nullable', 'derived']);
    if (!text(x.path, 128) || !/^[A-Za-z_][A-Za-z0-9_.]{0,127}$/.test(x.path) || !['string', 'decimal', 'timestamp', 'reference', 'boolean'].includes(x.type as string) || typeof x.nullable !== 'boolean' || typeof x.derived !== 'boolean') throw new Error(invalid);
    return x as unknown as CRMField;
  }), x => x.path);
  return { ...w, available: r.available, variables, catalog };
}
export function checkedTemplateSearch(v: unknown): CRMTemplateSearch {
  const r = record(v, [...witnessKeys, 'kind', 'query', 'offset', 'choices', 'has_more', 'next_offset']), w = witness(r);
  if (!CRM_KINDS.includes(r.kind as CRMKind) || !validCRMSearch(r.query, r.offset) || typeof r.has_more !== 'boolean' || !Number.isInteger(r.next_offset)
    || (r.has_more ? r.next_offset !== (r.offset as number) + 20 || (r.next_offset as number) > 1000 : r.next_offset !== 0)) throw new Error(invalid);
  const choices = unique(list(r.choices, 20).map(v => {
    const x = record(v, ['kind', 'id', 'label', 'secondary', 'record_updated_at']);
    if (x.kind !== r.kind || !crmOpaqueID(x.id) || !text(x.label, 4096) || !text(x.secondary, 4096) || !time(x.record_updated_at)) throw new Error(invalid);
    return x as unknown as CRMChoice;
  }), x => x.id);
  return { ...w, kind: r.kind as CRMKind, query: r.query as string, offset: r.offset as number, choices, has_more: r.has_more, next_offset: r.next_offset as number };
}
export function checkedTemplateObservation(v: unknown): CRMTemplateObservation {
  const r = record(v, [...witnessKeys, 'mappings', 'items', 'review_digest', 'can_create', 'observed_at', 'expires_at'], ['review_receipt', 'contract_issues']), w = witness(r);
  if (!htmlSHA256(r.review_digest) || typeof r.can_create !== 'boolean' || !time(r.observed_at) || !time(r.expires_at) || Date.parse(r.expires_at) <= Date.parse(r.observed_at)
    || Date.parse(r.expires_at) - Date.parse(r.observed_at) > 45000 || (r.can_create ? !text(r.review_receipt, 8192) || !r.review_receipt || /[\s\x00-\x1f\x7f]/.test(r.review_receipt) : Object.hasOwn(r, 'review_receipt'))) throw new Error(invalid);
  const observedAt = r.observed_at;
  const mappings = crmMappings(r.mappings); if (mappings.length > 64) throw new Error(invalid);
  const items = unique(list(r.items, 64).map(v => {
    const x = record(v, ['variable', 'source_kind', 'source_ref', 'source_path', 'current_present', 'current_value', 'available'], ['value', 'unavailable_reason', 'crm_observation']);
    crmMappings([{ variable: x.variable, source_kind: x.source_kind, source_ref: x.source_ref, source_path: x.source_path }]);
    if (typeof x.current_present !== 'boolean' || !text(x.current_value) || (!x.current_present && x.current_value !== '') || typeof x.available !== 'boolean') throw new Error(invalid);
    if (x.available) {
      if (!text(x.value) || Object.hasOwn(x, 'unavailable_reason')) throw new Error(invalid);
      const q = record(x.crm_observation, ['connection_id', 'generation', 'origin', 'crm_team_id', 'crm_user_id', 'record_updated_at', 'observed_at', 'body_sha256', 'value_sha256'], ['transformation']);
      if (!w.connection || q.connection_id !== w.connection.id || q.generation !== w.connection.generation || q.origin !== w.connection.origin || q.crm_team_id !== w.connection.crm_team_id || q.crm_user_id !== w.connection.crm_user_id
        || !time(q.record_updated_at) || !time(q.observed_at) || Date.parse(q.observed_at) > Date.parse(observedAt) || Date.parse(observedAt) - Date.parse(q.observed_at) > 45000 || !htmlSHA256(q.body_sha256) || !htmlSHA256(q.value_sha256)
        || (Object.hasOwn(q, 'transformation') && !(q.transformation === 'trim-first-and-last-name-v1' && x.source_kind === 'crm.contact' && x.source_path === 'full_name'))) throw new Error(invalid);
    } else if (Object.hasOwn(x, 'value') || Object.hasOwn(x, 'crm_observation') || !['field_unavailable', 'exceeds_contract_field_limit', 'required_value_missing'].includes(x.unavailable_reason as string)) throw new Error(invalid);
    return x as unknown as CRMTemplateItem;
  }), x => x.variable);
  if (crmMappingKey(items.map(({ variable, source_kind, source_ref, source_path }) => ({ variable, source_kind, source_ref, source_path }))) !== crmMappingKey(mappings) || (r.can_create && items.some(i => !i.available))) throw new Error(invalid);
  const issues = Object.hasOwn(r, 'contract_issues') ? list(r.contract_issues, 64).map(v => { const x = record(v, ['code', 'path', 'message']); if (!text(x.code, 128) || !x.code || !text(x.path, 512) || !text(x.message, 2048) || !x.message) throw new Error(invalid); return x as unknown as { code: string; path: string; message: string }; }) : undefined;
  if (r.can_create && issues?.length) throw new Error(invalid);
  return { ...w, mappings, items, review_digest: r.review_digest, can_create: r.can_create, observed_at: r.observed_at, expires_at: r.expires_at,
    ...(r.can_create ? { review_receipt: r.review_receipt as string } : {}), ...(issues === undefined ? {} : { contract_issues: issues }) };
}
export function checkedCreationMarker(v: unknown): HTMLCreationMarker {
  const m = record(v, ['version', 'org_id', 'user_id', 'template_id', 'request_id'], ['input_digest']);
  if (m.version !== 1 || ![m.org_id, m.user_id, m.template_id, m.request_id].every(htmlUUID) || (Object.hasOwn(m, 'input_digest') && !htmlSHA256(m.input_digest))) throw new Error(invalid);
  return { ...m } as unknown as HTMLCreationMarker;
}
export function readCreationMarker(storage: Pick<Storage, 'getItem'>): HTMLCreationMarker | null {
  const raw = storage.getItem(htmlCreationMarkerKey); if (raw === null) return null;
  if (raw.length > 1024) throw new Error('The pending creation marker is invalid. Another creation remains blocked.');
  return checkedCreationMarker(JSON.parse(raw));
}
export function storeCreationMarker(storage: Pick<Storage, 'setItem' | 'removeItem'>, marker: HTMLCreationMarker | null) {
  if (marker) storage.setItem(htmlCreationMarkerKey, JSON.stringify(checkedCreationMarker(marker))); else storage.removeItem(htmlCreationMarkerKey);
}
function checkedPins(v: unknown): HTMLCreationPins {
  const p = record(v, ['document_id', 'html_materialization_id', 'html_source_commitment', 'pdf_sha256', 'page_count', 'created_at']);
  if (!htmlUUID(p.document_id) || !htmlUUID(p.html_materialization_id) || !htmlSHA256(p.html_source_commitment) || !htmlSHA256(p.pdf_sha256) || !Number.isInteger(p.page_count) || (p.page_count as number) < 1 || (p.page_count as number) > 500 || !time(p.created_at)) throw new Error(invalid);
  return p as unknown as HTMLCreationPins;
}
function checkedCurrentDocument(v: unknown, marker: HTMLCreationMarker, pins: HTMLCreationPins): DocumentResponse | null {
  if (v === null) return null;
  const d = v as DocumentResponse;
  if (!d || d.id !== pins.document_id || d.org_id !== marker.org_id || d.template_id !== marker.template_id || !htmlUUID(d.sender_id) || !time(d.created_at) || !time(d.updated_at)
    || !text(d.name, 4096) || !text(d.status, 64) || !d.status || !text(d.routing_mode, 64) || !text(d.default_locale, 32) || d.source_kind !== 'pdf' || d.has_html_source !== true || !htmlSHA256(d.pdf_sha256) || !htmlSHA256(d.html_source_commitment)
    || !Number.isInteger(d.html_materialization_revision) || d.html_materialization_revision! < 1 || (d.html_review_required !== undefined && typeof d.html_review_required !== 'boolean')
    || !d.metadata || typeof d.metadata !== 'object' || Array.isArray(d.metadata)) throw new Error(invalid);
  strings(d.variables_json); return d;
}
export function checkedCreationReadback(v: unknown, marker: HTMLCreationMarker): HTMLCreationReadback {
  const r = record(v, ['state', 'org_id', 'user_id', 'request_id', 'input_digest', 'template_id', 'document', 'creation']);
  if (r.state !== 'committed' || r.org_id !== marker.org_id || r.user_id !== marker.user_id || r.request_id !== marker.request_id || r.template_id !== marker.template_id || !htmlSHA256(r.input_digest) || (marker.input_digest && marker.input_digest !== r.input_digest)) throw new Error(invalid);
  const creation = checkedPins(r.creation), document = checkedCurrentDocument(r.document, marker, creation);
  return { state: 'committed', org_id: r.org_id, user_id: r.user_id, request_id: r.request_id, input_digest: r.input_digest, template_id: r.template_id, document, creation } as HTMLCreationReadback;
}
export function checkedCreationOutcome(v: unknown, marker: HTMLCreationMarker): HTMLCreationOutcome {
  if (!v || typeof v !== 'object' || (v as { state?: unknown }).state !== 'closed') return checkedCreationReadback(v, marker);
  const r = record(v, ['state', 'org_id', 'user_id', 'template_id', 'request_id', 'closed_at']);
  if (marker.input_digest !== undefined || r.org_id !== marker.org_id || r.user_id !== marker.user_id || r.template_id !== marker.template_id || r.request_id !== marker.request_id || !time(r.closed_at)) throw new Error(invalid);
  return r as unknown as HTMLCreationClosed;
}
export function checkedCreationResult(v: unknown, marker: HTMLCreationMarker): HTMLCreationResult {
  const r = record(v, ['org_id', 'user_id', 'document', 'page_count', 'review_required', 'request_id', 'input_digest', 'replayed', 'creation']);
  const read = checkedCreationReadback({ state: 'committed', org_id: r.org_id, user_id: r.user_id, request_id: r.request_id, input_digest: r.input_digest, template_id: marker.template_id, document: r.document, creation: r.creation }, marker);
  if (typeof r.replayed !== 'boolean' || typeof r.review_required !== 'boolean' || r.page_count !== read.creation.page_count || (!r.replayed && (!read.document || read.document.status !== 'draft' || read.document.sender_id !== marker.user_id || read.document.html_review_required !== true || r.review_required !== true
    || read.document.html_source_commitment !== read.creation.html_source_commitment || read.document.pdf_sha256 !== read.creation.pdf_sha256 || read.document.html_materialization_revision !== 1))) throw new Error(invalid);
  return { org_id: read.org_id, user_id: read.user_id, document: read.document, page_count: r.page_count as number, review_required: r.review_required, request_id: read.request_id, input_digest: read.input_digest, replayed: r.replayed, creation: read.creation };
}
export interface CRMTemplateTransport {
  identity(signal: AbortSignal): Promise<unknown>;
  context(template: TemplateResponse, signal: AbortSignal): Promise<unknown>;
  search(id: string, input: CRMTemplateExpected & { kind: CRMKind; query: string; offset: number }, signal: AbortSignal): Promise<unknown>;
  observe(id: string, input: CRMTemplateExpected & { candidate: CRMTemplateCandidate; mappings: CRMMapping[] }, signal: AbortSignal): Promise<unknown>;
  create(id: string, input: HTMLDocumentInput, signal: AbortSignal): Promise<unknown>;
  readback(marker: HTMLCreationMarker, signal: AbortSignal): Promise<unknown>;
  stop(marker: HTMLCreationMarker, signal: AbortSignal): Promise<unknown>;
  source(id: string, signal: AbortSignal): Promise<HTMLDocumentSource>;
}
export interface CRMTemplateState {
  actor: CRMDocumentActor | null; context: CRMTemplateContext | null; selected: Partial<Record<CRMKind, CRMChoice>>; mappings: CRMMapping[];
  search: CRMTemplateSearch | null; observation: CRMTemplateObservation | null; confirmation: string;
  busy: 'load' | 'search' | 'observe' | 'create' | 'readback' | 'stop' | null; pending: HTMLCreationMarker | null;
  readback: HTMLCreationOutcome | null; created: DocumentResponse | null; error: string | null; notice: string | null; requires_refresh: boolean;
}
export const initialCRMTemplateState = (): CRMTemplateState => ({ actor: null, context: null, selected: {}, mappings: [], search: null, observation: null, confirmation: '', busy: null, pending: null, readback: null, created: null, error: null, notice: null, requires_refresh: false });
const sameValues = (a: Record<string, string>, b: Record<string, string>) => Object.keys(a).length === Object.keys(b).length && Object.entries(b).every(([k, v]) => Object.hasOwn(a, k) && a[k] === v);
function structuralKey(value: unknown): string {
  const canonical = (v: unknown): unknown => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
    ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)).map(([k, value]) => [k, canonical(value)])) : v;
  return JSON.stringify(canonical(value));
}
export class CRMTemplatePopulationController {
  state = initialCRMTemplateState();
  private epoch = 0; private abort: AbortController | null = null; private disposed = false; private observedCandidate = '';
  private retryCommand: HTMLDocumentInput | null = null;
  private submittedValues: Record<string, string> | null = null;
  constructor(private template: TemplateResponse | null, private transport: CRMTemplateTransport, private candidate: () => CRMTemplateCandidate,
    private changed: (s: CRMTemplateState) => void, private persist: (marker: HTMLCreationMarker | null) => void,
    private opened: (doc: DocumentResponse) => Promise<void> | void, marker: HTMLCreationMarker | null = null,
    private now = () => Date.now(), private uuid = () => crypto.randomUUID()) {
    if (marker) this.state = { ...this.state, pending: checkedCreationMarker(marker) };
  }
  private update(p: Partial<CRMTemplateState>) { if (!this.disposed) { this.state = { ...this.state, ...p }; this.changed(this.state); } }
  private current(e: number) { return !this.disposed && this.epoch === e && !this.abort?.signal.aborted; }
  private start(busy: CRMTemplateState['busy']) { this.abort?.abort(); this.abort = new AbortController(); const epoch = ++this.epoch; this.update({ busy, error: null, notice: null }); return { epoch, signal: this.abort.signal }; }
  private async identity(signal: AbortSignal) {
    const a = checkedCRMDocumentActor(await this.transport.identity(signal)), old = this.state.actor ?? this.state.pending;
    if ((old && (a.org_id !== old.org_id || a.user_id !== old.user_id)) || (this.template && a.org_id !== this.template.org_id)) throw new Error('Return to the original account and organisation. Your information and pending request are retained.');
    return a;
  }
  private matches(w: CRMTemplateWitness) {
    const a = this.state.actor, t = this.template;
    if (!a || !t || w.org_id !== a.org_id || w.user_id !== a.user_id || w.template_id !== t.id || w.template_version !== t.version || w.template_content_sha256 !== t.content_sha256
      || w.template_approved_by !== t.html_approval?.approved_by || w.template_approved_at !== t.html_approval?.approved_at) throw new Error(invalid);
  }
  private same(w: CRMTemplateWitness) { this.matches(w); if (!this.state.context || templateWitnessKey(w) !== templateWitnessKey(this.state.context)) throw new Error(invalid); }
  private error(e: unknown) { const status = (e as { status?: number })?.status;
    this.update({ error: status === 404 && this.state.pending ? 'No committed result was found yet. This request remains unconfirmed; another creation is blocked.' : status === 409 ? 'The design, account or confirmed values changed. Refresh and review again. Any pending creation must still be inspected.' : status === 401 || status === 403 ? 'The original session or authoring permission is unavailable. Return with the original account; entered information is retained.' : status === 503 ? 'CRM or creation is temporarily unavailable. Entered information is retained.' : e instanceof Error ? e.message : invalid, confirmation: '' }); }
  invalidate() { this.epoch++; this.abort?.abort(); this.abort = null; this.observedCandidate = ''; this.update({ busy: null, observation: null, confirmation: '', search: null }); }
  dispose() { this.invalidate(); this.disposed = true; }
  restorePending(marker: HTMLCreationMarker) {
    if (this.state.busy) return;
    const checked = checkedCreationMarker(marker);
    if (this.state.pending && (this.state.pending.request_id !== checked.request_id || this.state.pending.org_id !== checked.org_id || this.state.pending.user_id !== checked.user_id || this.state.pending.template_id !== checked.template_id)) throw new Error(invalid);
    this.invalidate(); this.update({ pending: checked });
  }
  setTemplate(t: TemplateResponse) { if (this.state.pending) return; this.invalidate(); this.template = t; this.update({ context: null, selected: {}, mappings: [], actor: this.state.actor, requires_refresh: false }); }
  inputChanged() { if (!this.state.pending) this.invalidate(); }
  canDiscover() { return !!this.state.context?.available && this.state.context.connection?.status === 'active' && !this.state.requires_refresh && !this.state.pending && !this.state.busy; }
  canObserve() { return !!this.state.context && !this.state.requires_refresh && !this.state.pending && !this.state.busy && (!this.state.mappings.length || this.canDiscover()); }
  observationFresh() { const o = this.state.observation; return !!o && this.now() < Date.parse(o.expires_at) && this.now() >= Date.parse(o.observed_at) - 1000; }
  effectiveValues(): Record<string, string> {
    const c = this.candidate(), values = { ...c.values };
    if (this.observationFresh() && this.observedCandidate === templateCandidateKey(c)) for (const i of this.state.observation!.items) if (i.available && i.value !== undefined) values[i.variable] = i.value;
    return values;
  }
  canCreate() { if (!this.template || !isApprovedHTMLTemplate(this.template) || !this.state.actor || this.state.requires_refresh || this.state.pending || this.state.busy || this.state.created) return false;
    try {
      const c = checkedTemplateCandidate(this.candidate()), fields = htmlTemplateFields(this.template), master = this.template.html_master_json!;
      if (Object.keys(c.values).some(k => !fields.some(f => f.name === k)) || Object.keys(c.sections ?? {}).some(k => !(master.sections ?? []).some(s => s.name === k))) return false;
      const effective = { ...(this.template.variables_json as Record<string, string>), ...this.effectiveValues() }, sections = { ...Object.fromEntries((master.sections ?? []).map(s => [s.name, s.default_text])), ...c.sections };
      htmlValuesForSubmission(fields, { ...(this.template.variables_json as Record<string, string>), ...c.values }, true);
      htmlValuesForSubmission(fields, effective); htmlProfileSectionValues(master, sections);
      const profile = htmlContractProfile(master);
      if (profile && (htmlProfileIssues(profile, effective, sections).length || (master.schema_version === 3 && htmlSigningPageIssues(profile, effective).length))) return false;
      return !this.state.mappings.length || (!!this.state.observation?.can_create && this.observationFresh() && this.state.confirmation === this.state.observation.review_digest && this.observedCandidate === templateCandidateKey(c));
    } catch { return false; } }
  confirm(digest: string, checked: boolean) { if (this.state.busy || this.state.pending || !this.observationFresh() || !this.state.observation?.can_create || this.observedCandidate !== templateCandidateKey(this.candidate())) return;
    this.update({ confirmation: checked && digest === this.state.observation.review_digest ? digest : '' }); }
  expire() { if (this.state.busy !== 'create' && this.state.confirmation && !this.observationFresh()) this.update({ confirmation: '', notice: 'This review expired. Read the values again before creating.' }); }
  async load() {
    if (this.state.pending || this.state.requires_refresh || !this.template || this.state.busy) return;
    const op = this.start('load'); this.update({ context: null, observation: null, confirmation: '' });
    try { const actor = await this.identity(op.signal); if (!this.current(op.epoch)) return; this.update({ actor });
      const c = checkedTemplateContext(await this.transport.context(this.template, op.signal)); if (!this.current(op.epoch)) return; this.matches(c);
      const fields = htmlTemplateFields(this.template);
      if (c.variables.length !== fields.length || c.variables.some(v => { const f = fields.find(f => f.name === v.name); return !f || f.required !== v.required || f.max_chars !== v.max_chars || v.current_present !== Object.hasOwn(this.template!.variables_json as object, v.name) || v.current_value !== f.defaultValue; })) throw new Error(invalid);
      await this.identity(op.signal); if (this.current(op.epoch)) this.update({ context: c, selected: {}, mappings: [] });
    } catch (e) { if (this.current(op.epoch)) this.error(e); }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  async search(kind: CRMKind, query: string, offset = 0) {
    if (!this.canDiscover() || !validCRMSearch(query, offset)) return; const c = this.state.context!, op = this.start('search');
    try { await this.identity(op.signal); if (!this.current(op.epoch)) return;
      const r = checkedTemplateSearch(await this.transport.search(c.template_id, { ...templateExpected(c), kind, query, offset }, op.signal)); if (!this.current(op.epoch)) return;
      this.same(r); if (r.kind !== kind || r.query !== query || r.offset !== offset) throw new Error(invalid); await this.identity(op.signal); if (this.current(op.epoch)) this.update({ search: r });
    } catch (e) { if (this.current(op.epoch)) this.error(e); } finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  select(choice: CRMChoice) { if (!this.canDiscover() || !this.state.search?.choices.some(c => c.kind === choice.kind && c.id === choice.id)) return;
    this.invalidate(); this.update({ selected: { ...this.state.selected, [choice.kind]: choice }, mappings: this.state.mappings.filter(m => m.source_kind !== choice.kind) }); }
  map(variable: string, source?: { kind: CRMKind; path: string }) {
    if (!this.canObserve() || !this.state.context?.variables.some(v => v.name === variable)) return;
    let next: CRMMapping | null = null;
    if (source) { const chosen = this.state.selected[source.kind]; if (!CRM_KINDS.includes(source.kind) || !chosen || !this.state.context.catalog[source.kind].some(f => f.path === source.path)) return;
      next = { variable, source_kind: source.kind, source_ref: chosen.id, source_path: source.path }; }
    this.invalidate(); this.update({ mappings: crmMappings([...this.state.mappings.filter(m => m.variable !== variable), ...(next ? [next] : [])]) });
  }
  unlink() { if (!this.state.busy && !this.state.pending) { this.invalidate(); this.update({ mappings: [] }); } }
  async observe() {
    if (!this.canObserve()) return; let candidate: CRMTemplateCandidate;
    try { candidate = checkedTemplateCandidate(this.candidate()); } catch (e) { this.error(e); return; }
    const key = templateCandidateKey(candidate), c = this.state.context!, mappings = crmMappings(this.state.mappings), op = this.start('observe'); this.update({ observation: null, confirmation: '' });
    try { await this.identity(op.signal); if (!this.current(op.epoch)) return;
      const o = checkedTemplateObservation(await this.transport.observe(c.template_id, { ...templateExpected(c), candidate, mappings }, op.signal)); if (!this.current(op.epoch)) return;
      this.same(o); if (crmMappingKey(o.mappings) !== crmMappingKey(mappings) || templateCandidateKey(this.candidate()) !== key) throw new Error(invalid);
      const defaults = this.template!.variables_json as Record<string, string>, manual = { ...defaults, ...candidate.values };
      for (const i of o.items) {
        if (i.current_present !== Object.hasOwn(manual, i.variable) || i.current_value !== (manual[i.variable] ?? '')) throw new Error(invalid);
        if (i.available && i.crm_observation) { const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(i.value!))), b => b.toString(16).padStart(2, '0')).join(''); if (digest !== i.crm_observation.value_sha256) throw new Error(invalid); }
      }
      await this.identity(op.signal); if (!this.current(op.epoch) || templateCandidateKey(this.candidate()) !== key) return;
      this.observedCandidate = key; this.update({ observation: o });
    } catch (e) { if (this.current(op.epoch)) this.error(e); } finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  private pending(marker: HTMLCreationMarker) { this.persist(marker); this.update({ pending: marker }); }
  async create() {
    if (!this.canCreate()) return; let command: HTMLDocumentInput;
    try {
      const c = checkedTemplateCandidate(this.candidate()), t = this.template!, o = this.state.observation;
      command = { ...c, expected_template_version: t.version, expected_template_content_sha256: t.content_sha256!, request_id: this.uuid(),
        expected_org_id: this.state.actor!.org_id, expected_user_id: this.state.actor!.user_id,
        ...(this.state.mappings.length ? { crm_population: { ...templateExpected(this.state.context!), mappings: crmMappings(this.state.mappings), reviewed_digest: o!.review_digest, review_receipt: o!.review_receipt!, confirmed: true } } : {}) };
      this.retryCommand = structuredClone(command);
      this.submittedValues = { ...(t.variables_json as Record<string, string>), ...c.values };
      if (command.crm_population) for (const i of o!.items) if (i.available) this.submittedValues[i.variable] = i.value!;
      this.pending({ version: 1, org_id: this.state.actor!.org_id, user_id: this.state.actor!.user_id, template_id: t.id, request_id: command.request_id! });
    } catch (e) { this.error(e); return; }
    await this.dispatch(command);
  }
  private async dispatch(command: HTMLDocumentInput) {
    const marker = this.state.pending!; const op = this.start('create'); let dispatched = false;
    try {
      await this.identity(op.signal); if (!this.current(op.epoch)) return; dispatched = true;
      const result = checkedCreationResult(await this.transport.create(marker.template_id, structuredClone(command), op.signal), marker); if (!this.current(op.epoch)) return;
      this.pending({ ...marker, input_digest: result.input_digest });
      await this.identity(op.signal); if (!this.current(op.epoch)) return;
      if (result.replayed) { this.update({ readback: { state: 'committed', org_id: result.org_id, user_id: result.user_id, request_id: result.request_id, input_digest: result.input_digest, template_id: marker.template_id, document: result.document, creation: result.creation }, notice: 'This request already created a document. Inspect its current state and choose whether to open it.' }); return; }
      const d = result.document!, source = currentHTMLSource(await this.transport.source(d.id, op.signal), d);
      if (!this.current(op.epoch)) return;
      const expected = this.submittedValues!;
      const master = this.template!.html_master_json!, printedExpected = Object.fromEntries((master.values ?? []).map(f => [f.name, expected[f.name] ?? '']));
      if (d.name !== command.name || (command.expires_at !== undefined && Date.parse(d.expires_at ?? '') !== Date.parse(command.expires_at))
        || !sameValues(d.variables_json, expected) || !sameValues(Object.fromEntries(source.values.map(v => [v.name, v.text])), printedExpected) || source.template_id !== marker.template_id || source.template_version !== command.expected_template_version || source.template_content_sha256 !== command.expected_template_content_sha256
        || source.source_schema_version !== master.schema_version || structuralKey(source.contract_profile ?? null) !== structuralKey(master.contract_profile ?? null)
        || structuralKey(source.signing_page ?? null) !== structuralKey(master.signing_page ?? null)
        || source.page_count !== result.creation.page_count || source.materialization_revision !== 1 || source.html_source_commitment !== result.creation.html_source_commitment || source.pdf_sha256 !== result.creation.pdf_sha256) throw new Error(invalid);
      const expectedSections = Object.fromEntries((this.template!.html_master_json!.sections ?? []).map(s => [s.name, command.sections?.[s.name] ?? s.default_text]));
      if (!sameValues(Object.fromEntries(source.sections.map(s => [s.name, s.text])), expectedSections)) throw new Error(invalid);
      await this.identity(op.signal); if (this.current(op.epoch)) this.update({ created: d, notice: 'The draft was created. Open it to review its exact PDF.' });
    } catch (e) { if (this.current(op.epoch)) { this.error(e); this.update({ notice: dispatched ? 'Creation is unconfirmed. Inspect this exact request before any other creation. Entered information is retained.' : 'Creation has not been confirmed. Its request identity is retained for inspection.' }); } }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
    if (this.current(op.epoch) && this.state.created) await this.openCreated();
  }
  canRetry() { return !!this.state.pending && !!this.retryCommand && !this.state.busy && !this.state.created && !this.state.readback; }
  async retry() { if (this.canRetry()) await this.dispatch(structuredClone(this.retryCommand!)); }
  async inspect() {
    if (!this.state.pending || this.state.busy) return; const marker = this.state.pending, op = this.start('readback'); this.update({ readback: null });
    try { const actor = await this.identity(op.signal); if (!this.current(op.epoch)) return;
      const r = checkedCreationOutcome(await this.transport.readback(marker, op.signal), marker); if (!this.current(op.epoch)) return;
      await this.identity(op.signal); if (!this.current(op.epoch)) return; this.adoptOutcome(r, marker, actor);
    } catch (e) { if (this.current(op.epoch)) this.error(e); } finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  private adoptOutcome(r: HTMLCreationOutcome, marker: HTMLCreationMarker, actor: CRMDocumentActor) {
    if (r.state === 'committed') this.pending({ ...marker, input_digest: r.input_digest });
    this.update({ actor, readback: r, notice: r.state === 'closed' ? 'This request was permanently stopped. Acknowledge that result before refreshing the design and reviewing a new creation.' : r.document ? 'The request committed. The document below is its current saved state; it may differ from the original creation.' : 'The request committed, but its document has been deleted. No replacement was created.' });
  }
  canStop() { return !!this.state.pending && !this.state.created && !this.state.readback && (!this.state.busy || this.state.busy === 'create'); }
  async stop(confirmed: boolean) {
    if (confirmed !== true || !this.canStop()) return; const marker = this.state.pending!; this.observedCandidate = ''; this.retryCommand = null; const op = this.start('stop'); this.update({ observation: null, confirmation: '' });
    try { const actor = await this.identity(op.signal); if (!this.current(op.epoch)) return;
      const r = checkedCreationOutcome(await this.transport.stop(marker, op.signal), marker); if (!this.current(op.epoch)) return;
      await this.identity(op.signal); if (this.current(op.epoch)) this.adoptOutcome(r, marker, actor);
    } catch (e) { if (this.current(op.epoch)) { this.error(e); this.update({ notice: 'Stopping is unconfirmed. Inspect or repeat Stop for this exact request; another creation remains blocked.' }); } }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  acknowledgeClosed() {
    if (this.state.busy || this.state.readback?.state !== 'closed' || !this.state.pending) return;
    try { checkedCreationOutcome(this.state.readback, this.state.pending); this.persist(null); } catch (e) { this.error(e); return; }
    this.invalidate(); this.retryCommand = null; this.submittedValues = null;
    this.update({ pending: null, readback: null, created: null, actor: null, context: null, selected: {}, mappings: [], requires_refresh: true, notice: 'Stopped request acknowledged. Your manual entries remain. Refresh the current design and review fresh CRM information before creating again.' });
  }
  async openCreated() { if (this.state.busy || !this.state.created) return; await this.open(this.state.created); }
  async adoptReadback() { if (this.state.busy || this.state.readback?.state !== 'committed' || !this.state.readback.document) return; await this.open(this.state.readback.document); }
  private async open(doc: DocumentResponse) {
    const op = this.start('readback');
    try { await this.identity(op.signal); if (!this.current(op.epoch)) return; await this.opened(doc); this.persist(null); this.update({ pending: null }); }
    catch (e) { if (this.current(op.epoch)) this.error(e); } finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  acknowledgeDeleted() { if (this.state.busy || this.state.readback?.state !== 'committed' || this.state.readback.document !== null) return;
    this.persist(null); this.retryCommand = null; this.update({ pending: null, readback: null, created: null, confirmation: '', observation: null, notice: 'Deleted committed document acknowledged. Review a fresh candidate before a new creation.' }); }
}
