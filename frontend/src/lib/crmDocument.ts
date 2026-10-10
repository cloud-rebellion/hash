import type { DocumentResponse, HTMLDocumentSource } from './api/client';
import { currentHTMLSource, htmlUUID } from './htmlRevision';
import { crmGeneration, crmOpaqueID } from './crmConnection';

export const CRM_KINDS = ['crm.deal', 'crm.contact', 'crm.company'] as const;
export type CRMKind = typeof CRM_KINDS[number];
export interface CRMDocumentActor { org_id: string; user_id: string; role: 'owner' | 'sender' }
export interface CRMDocumentConnection { id: string; generation: string; status: 'candidate' | 'active' | 'revoked'; origin: string; crm_team_id: string; crm_user_id: string }
export interface CRMDocumentWitness {
  org_id: string; user_id: string; document_id: string; updated_at: string; html_source_commitment: string;
  binding_fingerprint: string; connection: CRMDocumentConnection | null;
}
export interface CRMExpected {
  expected_org_id: string; expected_user_id: string; expected_updated_at: string; expected_html_source_commitment: string;
  expected_binding_fingerprint: string; expected_connection_id: string; expected_connection_generation: string;
}
export interface CRMMapping { variable: string; source_kind: CRMKind; source_ref: string; source_path: string }
export interface CRMVariable { name: string; required: boolean; max_chars: number; current_value: string; current_present: boolean }
export interface CRMField { path: string; type: 'string' | 'decimal' | 'timestamp' | 'reference' | 'boolean'; nullable: boolean; derived: boolean }
export interface CRMBinding { variable: string; source_kind: string; source_ref?: string; source_path?: string; fallback?: string; last_value?: string; last_resolved?: string; last_error?: string; updated_at: string }
export interface CRMDocumentContext extends CRMDocumentWitness {
  supported: boolean; available: boolean; variables: CRMVariable[]; bindings: CRMBinding[];
  catalog: Record<CRMKind, CRMField[]>; mapping_review_required: boolean;
}
export interface CRMChoice { kind: CRMKind; id: string; label: string; secondary: string; record_updated_at: string }
export interface CRMSearch extends CRMDocumentWitness { kind: CRMKind; query: string; offset: number; choices: CRMChoice[]; has_more: boolean; next_offset: number }
export interface CRMValueObservation {
  connection_id: string; generation: string; origin: string; crm_team_id: string; crm_user_id: string;
  record_updated_at: string; observed_at: string; body_sha256: string; value_sha256: string; transformation?: 'trim-first-and-last-name-v1';
}
export interface CRMObservationItem extends CRMMapping {
  current_value: string; current_present: boolean; available: boolean; value?: string; unavailable_reason?: string; crm_observation?: CRMValueObservation;
}
export interface CRMObservation extends CRMDocumentWitness {
  mappings: CRMMapping[]; items: CRMObservationItem[]; review_digest: string; can_apply: boolean; content_changed: boolean; observed_at: string;
  contract_issues?: { code: string; path: string; message: string }[];
}
export interface CRMApply extends CRMDocumentWitness {
  document: DocumentResponse; content_changed: boolean; mapping_review_required: false;
  materialization_revision?: number; page_count?: number; review_required?: boolean; placement_reset?: boolean;
}
const invalid = 'The CRM document response could not be verified. Refresh before continuing.';
const sha = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const text = (v: unknown, max = 65536): v is string => typeof v === 'string' && new TextEncoder().encode(v).length <= max;
const time = (v: unknown): v is string => typeof v === 'string' && v.length <= 40 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v));
const name = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z_][A-Za-z0-9_.]{0,127}$/.test(v);
const kind = (v: unknown): v is CRMKind => CRM_KINDS.includes(v as CRMKind);
function record(v: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v) || !required.every((k) => Object.hasOwn(v, k))
      || Object.keys(v).some((k) => !required.includes(k) && !optional.includes(k))) throw new Error(invalid);
  return v as Record<string, unknown>;
}
function list(v: unknown, max: number): unknown[] { if (!Array.isArray(v) || v.length > max) throw new Error(invalid); return v; }
function unique<T>(items: T[], key: (item: T) => string): T[] { if (new Set(items.map(key)).size !== items.length) throw new Error(invalid); return items; }
function origin(v: unknown): v is string {
  if (!text(v, 2048) || !v) return false;
  try { const u = new URL(v); return ['http:', 'https:'].includes(u.protocol) && u.origin === v && !u.username && !u.password; } catch { return false; }
}
export function checkedCRMDocumentActor(v: unknown): CRMDocumentActor {
  const a = v as CRMDocumentActor;
  if (!a || !htmlUUID(a.org_id) || !htmlUUID(a.user_id) || !['owner', 'sender'].includes(a.role)) throw new Error(invalid);
  return { org_id: a.org_id, user_id: a.user_id, role: a.role };
}
const witnessKeys = ['org_id', 'user_id', 'document_id', 'updated_at', 'html_source_commitment', 'binding_fingerprint', 'connection'];
function witness(v: Record<string, unknown>): CRMDocumentWitness {
  if (!htmlUUID(v.org_id) || !htmlUUID(v.user_id) || !htmlUUID(v.document_id) || !time(v.updated_at)
      || !(v.html_source_commitment === '' || sha(v.html_source_commitment)) || !sha(v.binding_fingerprint)) throw new Error(invalid);
  let connection: CRMDocumentConnection | null = null;
  if (v.connection !== null) {
    const c = record(v.connection, ['id', 'generation', 'status', 'origin', 'crm_team_id', 'crm_user_id']);
    if (!htmlUUID(c.id) || !crmGeneration(c.generation) || !['candidate', 'active', 'revoked'].includes(c.status as string)
        || !origin(c.origin) || !crmOpaqueID(c.crm_team_id) || !crmOpaqueID(c.crm_user_id)) throw new Error(invalid);
    connection = { id: c.id, generation: c.generation, status: c.status, origin: c.origin, crm_team_id: c.crm_team_id, crm_user_id: c.crm_user_id } as CRMDocumentConnection;
  }
  return { org_id: v.org_id, user_id: v.user_id, document_id: v.document_id, updated_at: v.updated_at,
    html_source_commitment: v.html_source_commitment, binding_fingerprint: v.binding_fingerprint, connection };
}
export function crmWitnessKey(w: CRMDocumentWitness): string { return JSON.stringify([w.org_id, w.user_id, w.document_id, w.updated_at, w.html_source_commitment, w.binding_fingerprint, w.connection]); }
export function crmExpected(w: CRMDocumentWitness): CRMExpected { return { expected_org_id: w.org_id, expected_user_id: w.user_id,
  expected_updated_at: w.updated_at, expected_html_source_commitment: w.html_source_commitment, expected_binding_fingerprint: w.binding_fingerprint,
  expected_connection_id: w.connection?.id ?? '', expected_connection_generation: w.connection?.generation ?? '0' }; }
export function checkedCRMExpected(v: CRMExpected): CRMExpected {
  if (!htmlUUID(v.expected_org_id) || !htmlUUID(v.expected_user_id) || !time(v.expected_updated_at)
      || !(v.expected_html_source_commitment === '' || sha(v.expected_html_source_commitment)) || !sha(v.expected_binding_fingerprint)
      || !crmGeneration(v.expected_connection_generation, true) || (v.expected_connection_generation === '0' ? v.expected_connection_id !== '' : !htmlUUID(v.expected_connection_id))) throw new Error(invalid);
  return { expected_org_id: v.expected_org_id, expected_user_id: v.expected_user_id, expected_updated_at: v.expected_updated_at,
    expected_html_source_commitment: v.expected_html_source_commitment, expected_binding_fingerprint: v.expected_binding_fingerprint,
    expected_connection_id: v.expected_connection_id, expected_connection_generation: v.expected_connection_generation };
}
export function checkedCRMMapping(v: unknown): CRMMapping {
  const m = record(v, ['variable', 'source_kind', 'source_ref', 'source_path']);
  if (!name(m.variable) || !kind(m.source_kind) || !crmOpaqueID(m.source_ref) || !name(m.source_path)) throw new Error(invalid);
  return { variable: m.variable, source_kind: m.source_kind, source_ref: m.source_ref, source_path: m.source_path } as CRMMapping;
}
export function crmMappings(v: unknown): CRMMapping[] {
  const out = unique(list(v, 256).map(checkedCRMMapping), (m) => m.variable).sort((a, b) => a.variable < b.variable ? -1 : a.variable > b.variable ? 1 : 0);
  for (const k of CRM_KINDS) if (new Set(out.filter((m) => m.source_kind === k).map((m) => m.source_ref)).size > 1) throw new Error(invalid);
  return out;
}
export const crmMappingKey = (m: CRMMapping[]) => JSON.stringify(crmMappings(m));
export function crmBaseline(c: CRMDocumentContext): CRMMapping[] { return crmMappings(c.bindings.filter((b) => kind(b.source_kind)).map((b) => ({ variable: b.variable, source_kind: b.source_kind, source_ref: b.source_ref, source_path: b.source_path }))); }
export function checkedCRMContext(v: unknown): CRMDocumentContext {
  const r = record(v, [...witnessKeys, 'supported', 'available', 'variables', 'bindings', 'catalog', 'mapping_review_required']);
  const w = witness(r);
  if (typeof r.supported !== 'boolean' || typeof r.available !== 'boolean' || typeof r.mapping_review_required !== 'boolean') throw new Error(invalid);
  const variables = unique(list(r.variables, 256).map((v) => {
    const x = record(v, ['name', 'required', 'max_chars', 'current_value', 'current_present']);
    if (!name(x.name) || typeof x.required !== 'boolean' || !Number.isInteger(x.max_chars) || (x.max_chars as number) < 1 || (x.max_chars as number) > 1000000 || !text(x.current_value) || typeof x.current_present !== 'boolean' || (!x.current_present && x.current_value !== '')) throw new Error(invalid);
    return x as unknown as CRMVariable;
  }), (v) => v.name);
  const bindings = unique(list(r.bindings, 256).map((v) => {
    const b = record(v, ['variable', 'source_kind', 'updated_at'], ['source_ref', 'source_path', 'fallback', 'last_value', 'last_resolved', 'last_error']);
    if (!name(b.variable) || !text(b.source_kind, 64) || !time(b.updated_at)) throw new Error(invalid);
    for (const key of ['source_ref', 'source_path', 'fallback', 'last_value', 'last_resolved', 'last_error']) if (Object.hasOwn(b, key) && !text(b[key])) throw new Error(invalid);
    return b as unknown as CRMBinding;
  }), (b) => b.variable);
  const rawCatalog = record(r.catalog, [...CRM_KINDS]), catalog = {} as Record<CRMKind, CRMField[]>;
  for (const k of CRM_KINDS) catalog[k] = unique(list(rawCatalog[k], 128).map((v) => {
    const f = record(v, ['path', 'type', 'nullable', 'derived']);
    if (!name(f.path) || !['string', 'decimal', 'timestamp', 'reference', 'boolean'].includes(f.type as string)
        || typeof f.nullable !== 'boolean' || typeof f.derived !== 'boolean') throw new Error(invalid);
    return f as unknown as CRMField;
  }), (f) => f.path);
  const result = { ...w, supported: r.supported, available: r.available, mapping_review_required: r.mapping_review_required, variables, bindings, catalog };
  // Undeclared historic CRM mappings may be removed explicitly, but never silently trusted.
  crmBaseline(result); return result;
}
export function validCRMSearch(query: unknown, offset: unknown): boolean {
  return typeof query === 'string' && (query === '' || (Array.from(query).length >= 2 && Array.from(query).length <= 100 && query === query.trim()))
    && new TextEncoder().encode(query as string).length <= 400 && !/\p{Cc}|\p{Cf}/u.test(query as string)
    && Number.isInteger(offset) && (offset as number) >= 0 && (offset as number) <= 1000 && (offset as number) % 20 === 0;
}
export function checkedCRMSearch(v: unknown): CRMSearch {
  const r = record(v, [...witnessKeys, 'kind', 'query', 'offset', 'choices', 'has_more', 'next_offset']);
  const w = witness(r);
  if (!kind(r.kind) || !validCRMSearch(r.query, r.offset) || typeof r.has_more !== 'boolean'
      || !Number.isInteger(r.next_offset) || (r.has_more ? r.next_offset !== (r.offset as number) + 20 || (r.next_offset as number) > 1000 : r.next_offset !== 0)) throw new Error(invalid);
  const choices = unique(list(r.choices, 20).map((v) => {
    const c = record(v, ['kind', 'id', 'label', 'secondary', 'record_updated_at']);
    if (c.kind !== r.kind || !crmOpaqueID(c.id) || !text(c.label, 2048) || !text(c.secondary, 2048) || !time(c.record_updated_at)) throw new Error(invalid);
    return c as unknown as CRMChoice;
  }), (c) => c.id);
  return { ...w, kind: r.kind, query: r.query as string, offset: r.offset as number, choices, has_more: r.has_more, next_offset: r.next_offset as number };
}
export function checkedCRMObservation(v: unknown): CRMObservation {
  const r = record(v, [...witnessKeys, 'mappings', 'items', 'review_digest', 'can_apply', 'content_changed', 'observed_at'], ['contract_issues']), w = witness(r), mappings = crmMappings(r.mappings);
  if (!sha(r.review_digest) || typeof r.can_apply !== 'boolean' || typeof r.content_changed !== 'boolean'
      || !(mappings.length ? time(r.observed_at) : r.observed_at === '')) throw new Error(invalid);
  const items = unique(list(r.items, 256).map((v) => {
    const i = record(v, ['variable', 'source_kind', 'source_ref', 'source_path', 'current_value', 'current_present', 'available'], ['value', 'unavailable_reason', 'crm_observation']);
    const m = checkedCRMMapping({ variable: i.variable, source_kind: i.source_kind, source_ref: i.source_ref, source_path: i.source_path });
    if (!text(i.current_value) || typeof i.current_present !== 'boolean' || (!i.current_present && i.current_value !== '') || typeof i.available !== 'boolean') throw new Error(invalid);
    if (i.available) {
      if (!text(i.value) || Object.hasOwn(i, 'unavailable_reason')) throw new Error(invalid);
      const p = record(i.crm_observation, ['connection_id', 'generation', 'origin', 'crm_team_id', 'crm_user_id', 'record_updated_at', 'observed_at', 'body_sha256', 'value_sha256'], ['transformation']);
      if (!w.connection || p.connection_id !== w.connection.id || p.generation !== w.connection.generation || p.origin !== w.connection.origin
          || p.crm_team_id !== w.connection.crm_team_id || p.crm_user_id !== w.connection.crm_user_id || !time(p.record_updated_at) || !time(p.observed_at)
          || !sha(p.body_sha256) || !sha(p.value_sha256) || (Object.hasOwn(p, 'transformation') && !(p.transformation === 'trim-first-and-last-name-v1' && m.source_kind === 'crm.contact' && m.source_path === 'full_name'))) throw new Error(invalid);
    } else if (Object.hasOwn(i, 'value') || Object.hasOwn(i, 'crm_observation') || !text(i.unavailable_reason, 1000)) throw new Error(invalid);
    return i as unknown as CRMObservationItem;
  }), (i) => i.variable);
  if (crmMappingKey(items.map(({ variable, source_kind, source_ref, source_path }) => ({ variable, source_kind, source_ref, source_path }))) !== crmMappingKey(mappings)
      || (r.can_apply && items.some((i) => !i.available))) throw new Error(invalid);
  const contract_issues = Object.hasOwn(r, 'contract_issues') ? list(r.contract_issues, 64).map((v) => {
    const issue = record(v, ['code', 'path', 'message']);
    if (!text(issue.code, 128) || !text(issue.path, 512) || !text(issue.message, 2048) || !issue.code || !issue.message) throw new Error(invalid);
    return issue as unknown as { code: string; path: string; message: string };
  }) : undefined;
  if (contract_issues?.length && r.can_apply) throw new Error(invalid);
  return { ...w, mappings, items, review_digest: r.review_digest, can_apply: r.can_apply, content_changed: r.content_changed, observed_at: r.observed_at as string,
    ...(contract_issues === undefined ? {} : { contract_issues }) };
}
export function checkedCRMDocument(v: unknown): DocumentResponse {
  const d = v as DocumentResponse;
  if (!d || !htmlUUID(d.id) || !htmlUUID(d.org_id) || !htmlUUID(d.sender_id) || !time(d.updated_at) || !time(d.created_at)
      || !text(d.name, 4096) || !text(d.routing_mode, 64) || !text(d.default_locale, 32) || d.status !== 'draft' || !['pdf', 'blocks'].includes(d.source_kind)
      || !d.variables_json || typeof d.variables_json !== 'object' || Array.isArray(d.variables_json) || Object.keys(d.variables_json).length > 256
      || Object.entries(d.variables_json).some(([key, value]) => !name(key) || !text(value))
      || !d.metadata || typeof d.metadata !== 'object' || Array.isArray(d.metadata)
      || (d.source_kind === 'blocks' && (!d.blocks_json || d.blocks_json.version !== 1 || !Array.isArray(d.blocks_json.blocks) || d.blocks_json.blocks.length > 10000))
      || (d.has_html_source !== undefined && typeof d.has_html_source !== 'boolean')) throw new Error(invalid);
  if (d.has_html_source ? d.source_kind !== 'pdf' || !sha(d.pdf_sha256) || !sha(d.html_source_commitment)
      || !Number.isInteger(d.html_materialization_revision) || d.html_materialization_revision! < 1
      || (d.html_review_required !== undefined && typeof d.html_review_required !== 'boolean')
    : d.source_kind !== 'blocks' || !!d.html_source_commitment) throw new Error(invalid);
  return d;
}
function sameValues(actual: Record<string, string>, expected: Record<string, string>): boolean {
  return Object.keys(actual).length === Object.keys(expected).length
    && Object.entries(expected).every(([key, value]) => Object.hasOwn(actual, key) && actual[key] === value);
}
function contextValuesMatch(c: CRMDocumentContext, d: DocumentResponse): boolean {
  return c.variables.every((v) => v.current_present === Object.hasOwn(d.variables_json, v.name)
    && v.current_value === (Object.hasOwn(d.variables_json, v.name) ? d.variables_json[v.name] : ''));
}
export function checkedCRMApply(v: unknown): CRMApply {
  const r = record(v, [...witnessKeys, 'document', 'content_changed', 'mapping_review_required'], ['materialization_revision', 'page_count', 'review_required', 'placement_reset']), w = witness(r);
  const d = checkedCRMDocument(r.document);
  if (d.id !== w.document_id || d.org_id !== w.org_id || d.updated_at !== w.updated_at
      || (d.html_source_commitment ?? '') !== w.html_source_commitment || typeof r.content_changed !== 'boolean' || r.mapping_review_required !== false) throw new Error(invalid);
  if (d.has_html_source) {
    if (!sha(d.pdf_sha256) || !sha(d.html_source_commitment)) throw new Error(invalid);
    if (r.content_changed && (!Number.isInteger(r.materialization_revision) || (r.materialization_revision as number) < 1 || r.materialization_revision !== d.html_materialization_revision
        || !Number.isInteger(r.page_count) || (r.page_count as number) < 1 || (r.page_count as number) > 500
        || r.review_required !== true || r.placement_reset !== true || d.html_review_required !== true)) throw new Error(invalid);
  } else if (d.source_kind !== 'blocks' || w.html_source_commitment !== '') throw new Error(invalid);
  return { ...w, document: d, content_changed: r.content_changed, mapping_review_required: false,
    ...(Object.hasOwn(r, 'materialization_revision') ? { materialization_revision: r.materialization_revision as number, page_count: r.page_count as number, review_required: r.review_required as boolean, placement_reset: r.placement_reset as boolean } : {}) };
}
export function crmDocumentPin(d: DocumentResponse): string { return JSON.stringify([d.id, d.org_id, d.status, d.sender_id, d.updated_at, d.source_kind, d.has_html_source, d.pdf_sha256, d.html_source_commitment, d.html_materialization_revision]); }
export interface CRMDocumentTransport {
  identity(signal: AbortSignal): Promise<unknown>;
  context(id: string, signal: AbortSignal): Promise<unknown>;
  search(id: string, input: CRMExpected & { kind: CRMKind; query: string; offset: number }, signal: AbortSignal): Promise<unknown>;
  observe(id: string, input: CRMExpected & { mappings: CRMMapping[] }, signal: AbortSignal): Promise<unknown>;
  apply(id: string, input: CRMExpected & { mappings: CRMMapping[]; reviewed_digest: string; confirmed: true }, signal: AbortSignal): Promise<unknown>;
  document(id: string, signal: AbortSignal): Promise<DocumentResponse>;
  source(id: string, signal: AbortSignal): Promise<HTMLDocumentSource>;
}
export interface CRMDocumentState {
  context: CRMDocumentContext | null; mappings: CRMMapping[]; selected: Partial<Record<CRMKind, CRMChoice>>;
  search: CRMSearch | null; observation: CRMObservation | null; confirmation: string; fresh: boolean; needsReadback: boolean;
  readbackReason: 'uncertain' | 'stale' | null;
  readback: { document: DocumentResponse; context: CRMDocumentContext } | null;
  busy: 'refresh' | 'search' | 'observe' | 'apply' | 'readback' | null; error: string | null; notice: string | null;
}
export const initialCRMDocumentState = (): CRMDocumentState => ({ context: null, mappings: [], selected: {}, search: null, observation: null, confirmation: '', fresh: false, needsReadback: false, readbackReason: null, readback: null, busy: null, error: null, notice: null });
export function crmDocumentError(e: unknown): string {
  const status = e && typeof e === 'object' && 'status' in e ? e.status : 0;
  if (status === 401) return 'Your original session expired. Sign in again before reviewing CRM information.';
  if (status === 403) return 'Your current session cannot change this document. Return with the original sender or an owner.';
  if (status === 409) return 'The document, mappings, CRM account or observed values changed. Refresh and review again.';
  if (status === 400) return 'The CRM selection or mapping was refused. Refresh and check the declared fields.';
  if (status === 503) return 'CRM information is temporarily unavailable. Your document wording has been preserved.';
  return 'The CRM request could not be verified. Refresh before continuing.';
}
export class CRMDocumentController {
  state = initialCRMDocumentState();
  private epoch = 0; private abort: AbortController | null = null; private disposed = false;
  constructor(private doc: DocumentResponse, private actor: CRMDocumentActor, private transport: CRMDocumentTransport,
    private changed: (state: CRMDocumentState) => void, private editorClean: () => boolean,
    private adopt: (document: DocumentResponse) => boolean, private now = () => Date.now()) { checkedCRMDocumentActor(actor); }
  private update(p: Partial<CRMDocumentState>) { if (!this.disposed) { this.state = { ...this.state, ...p }; this.changed(this.state); } }
  private current(e: number) { return !this.disposed && e === this.epoch && !this.abort?.signal.aborted; }
  private actorMatches(v: unknown) { const a = checkedCRMDocumentActor(v); if (a.org_id !== this.actor.org_id || a.user_id !== this.actor.user_id || (a.role !== 'owner' && this.doc.sender_id !== a.user_id)) throw new Error(invalid); }
  private documentMatches(w: CRMDocumentWitness, d = this.doc) { if (w.org_id !== this.actor.org_id || w.user_id !== this.actor.user_id || w.document_id !== d.id || w.org_id !== d.org_id
    || w.updated_at !== d.updated_at || w.html_source_commitment !== (d.html_source_commitment ?? '')) throw new Error(invalid); }
  private same(w: CRMDocumentWitness, c: CRMDocumentContext) { this.documentMatches(w); if (crmWitnessKey(w) !== crmWitnessKey(c)) throw new Error(invalid); }
  private start(busy: CRMDocumentState['busy']) { this.abort?.abort(); this.abort = new AbortController(); const epoch = ++this.epoch;
    this.update({ busy, confirmation: '', error: null, notice: null }); return { epoch, signal: this.abort.signal }; }
  interrupt() { const uncertain = this.state.needsReadback || this.state.busy === 'apply'; this.epoch++; this.abort?.abort(); this.abort = null;
    this.update({ fresh: false, busy: null, confirmation: '', search: null, observation: null, readback: null, needsReadback: uncertain,
      readbackReason: uncertain ? this.state.readbackReason ?? 'uncertain' : null }); }
  dispose() { this.interrupt(); this.disposed = true; }
  syncDocument(d: DocumentResponse) { if (crmDocumentPin(d) === crmDocumentPin(this.doc)) return; this.interrupt(); this.doc = d; }
  private baseline(c: CRMDocumentContext) {
    const mappings = crmBaseline(c), selected: CRMDocumentState['selected'] = {};
    for (const m of mappings) selected[m.source_kind] = { kind: m.source_kind, id: m.source_ref, label: m.source_ref, secondary: '', record_updated_at: '' };
    return { context: c, mappings, selected, fresh: true, needsReadback: false, readbackReason: null, readback: null, search: null, observation: null, confirmation: '' };
  }
  sendBlocked(): boolean { const s = this.state, c = s.context; return !!s.busy || !s.fresh || s.needsReadback || !c || c.mapping_review_required
    || crmMappingKey(s.mappings) !== crmMappingKey(crmBaseline(c)) || !!s.observation?.content_changed; }
  canDiscover(): boolean { const c = this.state.context; return !!c && c.supported && c.available && c.connection?.status === 'active' && this.state.fresh && !this.state.needsReadback && !this.state.busy; }
  private editable(): boolean { return this.doc.status === 'draft' && this.doc.org_id === this.actor.org_id && (this.actor.role === 'owner' || this.doc.sender_id === this.actor.user_id); }
  canObserve(): boolean { return this.editable() && !!this.state.context?.supported && this.state.fresh && !this.state.busy && !this.state.needsReadback && (!this.state.mappings.length || this.canDiscover()); }
  observationFresh(): boolean { const o = this.state.observation; return !!o && (!o.mappings.length || this.now() - Date.parse(o.observed_at) < 45000); }
  canApply(): boolean { const s = this.state, o = s.observation; return this.canObserve() && this.editorClean() && !!o?.can_apply && this.observationFresh()
    && s.confirmation === o.review_digest && crmMappingKey(s.mappings) === crmMappingKey(o.mappings); }
  confirm(digest: string, checked: boolean) { if (this.state.busy || !this.state.fresh || this.state.needsReadback || !this.observationFresh()) return;
    this.update({ confirmation: checked && digest === this.state.observation?.review_digest ? digest : '' }); }
  expire() { if (this.state.busy !== 'apply' && this.state.confirmation && !this.observationFresh()) this.update({ confirmation: '', notice: 'This observation expired. Read the CRM values again before applying them.' }); }
  select(choice: CRMChoice) {
    if (!this.canDiscover() || !kind(choice.kind) || !crmOpaqueID(choice.id)) return;
    this.update({ selected: { ...this.state.selected, [choice.kind]: choice }, mappings: this.state.mappings.map((m) => m.source_kind === choice.kind ? { ...m, source_ref: choice.id } : m), observation: null, confirmation: '', error: null, notice: null });
  }
  map(variable: string, source?: { kind: CRMKind; path: string }) {
    const c = this.state.context; if (!c || !this.editable() || !this.state.fresh || this.state.busy || this.state.needsReadback || !c.variables.some((v) => v.name === variable)) return;
    let mappings = this.state.mappings.filter((m) => m.variable !== variable);
    if (source) { const chosen = this.state.selected[source.kind]; if (!chosen || !c.catalog[source.kind]?.some((f) => f.path === source.path)) return;
      mappings = [...mappings, { variable, source_kind: source.kind, source_path: source.path, source_ref: chosen.id }]; }
    this.update({ mappings: crmMappings(mappings), observation: null, confirmation: '', error: null, notice: null });
  }
  unlink() { if (!this.state.context?.supported || !this.editable() || !this.state.fresh || this.state.busy || this.state.needsReadback) return;
    this.update({ mappings: [], observation: null, confirmation: '', error: null, notice: null }); }
  async refresh() {
    if (this.disposed || this.state.busy || this.state.needsReadback) return;
    const op = this.start('refresh'); this.update({ fresh: false });
    try { this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return;
      const c = checkedCRMContext(await this.transport.context(this.doc.id, op.signal)); if (!this.current(op.epoch)) return;
      if (c.org_id === this.actor.org_id && c.user_id === this.actor.user_id && c.document_id === this.doc.id && c.org_id === this.doc.org_id
          && (c.updated_at !== this.doc.updated_at || c.html_source_commitment !== (this.doc.html_source_commitment ?? ''))) {
        this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return;
        this.update({ fresh: false, needsReadback: true, readbackReason: 'stale', error: 'A newer saved document is available. Inspect it before replacing local inputs.' }); return;
      }
      this.documentMatches(c);
      this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return; this.update(this.baseline(c));
    } catch (e) { if (this.current(op.epoch)) this.update({ fresh: false, error: crmDocumentError(e) }); }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  async search(k: CRMKind, query: string, offset = 0) {
    if (!this.canDiscover() || !validCRMSearch(query, offset)) { this.update({ error: 'Search with two to 100 characters, or leave the search empty for recent records.' }); return; }
    const c = this.state.context!, op = this.start('search');
    try { this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return;
      const r = checkedCRMSearch(await this.transport.search(this.doc.id, { ...crmExpected(c), kind: k, query, offset }, op.signal)); if (!this.current(op.epoch)) return;
      this.same(r, c); if (r.kind !== k || r.query !== query || r.offset !== offset) throw new Error(invalid);
      this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return; this.update({ search: r });
    } catch (e) { if (this.current(op.epoch)) this.update({ search: null, fresh: false, error: crmDocumentError(e) }); }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  async observe() {
    if (!this.canObserve()) return;
    const c = this.state.context!, mappings = crmMappings(this.state.mappings), op = this.start('observe'); this.update({ observation: null });
    try { this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return;
      const o = checkedCRMObservation(await this.transport.observe(this.doc.id, { ...crmExpected(c), mappings }, op.signal)); if (!this.current(op.epoch)) return;
      this.same(o, c); if (crmMappingKey(o.mappings) !== crmMappingKey(mappings) || o.items.some((i) => {
        const field = c.variables.find((v) => v.name === i.variable);
        return i.current_value !== field?.current_value || i.current_present !== field?.current_present;
      })) throw new Error(invalid);
      this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return; this.update({ observation: o });
    } catch (e) { if (this.current(op.epoch)) this.update({ fresh: false, error: crmDocumentError(e) }); }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  async apply() {
    if (!this.canApply()) return;
    const c = this.state.context!, o = this.state.observation!, before = this.doc, mappings = crmMappings(this.state.mappings), op = this.start('apply'); let dispatched = false;
    try { this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch) || !this.editorClean()) return;
      dispatched = true;
      const r = checkedCRMApply(await this.transport.apply(before.id, { ...crmExpected(c), mappings, reviewed_digest: o.review_digest, confirmed: true }, op.signal)); if (!this.current(op.epoch)) return;
      this.documentMatches(r, r.document);
      const expectedValues: Record<string, string> = Object.assign(Object.create(null), before.variables_json);
      for (const item of o.items) { if (!item.available || typeof item.value !== 'string') throw new Error(invalid); expectedValues[item.variable] = item.value; }
      if (!sameValues(r.document.variables_json, expectedValues)) throw new Error(invalid);
      if (JSON.stringify(r.connection) !== JSON.stringify(c.connection) || r.document.source_kind !== before.source_kind || r.document.sender_id !== before.sender_id
          || r.document.has_html_source !== before.has_html_source || r.content_changed !== o.content_changed) throw new Error(invalid);
      if (before.has_html_source && (r.content_changed ? r.document.pdf_sha256 === before.pdf_sha256 || r.document.html_source_commitment === before.html_source_commitment
          : r.document.pdf_sha256 !== before.pdf_sha256 || r.document.html_source_commitment !== before.html_source_commitment || r.document.html_materialization_revision !== before.html_materialization_revision
            || (r.document.html_review_required === true) !== (before.html_review_required === true))) throw new Error(invalid);
      if (r.document.has_html_source) {
        const source = currentHTMLSource(await this.transport.source(before.id, op.signal), r.document);
        if (source.values.some((v) => v.text !== (Object.hasOwn(expectedValues, v.name) ? expectedValues[v.name] : ''))) throw new Error(invalid);
      } if (!this.current(op.epoch)) return;
      const next = checkedCRMContext(await this.transport.context(before.id, op.signal)); if (!this.current(op.epoch)) return; this.documentMatches(next, r.document);
      if (crmWitnessKey(next) !== crmWitnessKey(r) || next.mapping_review_required || crmMappingKey(crmBaseline(next)) !== crmMappingKey(mappings)
          || !contextValuesMatch(next, r.document)) throw new Error(invalid);
      this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return;
      if (!this.editorClean() || !this.adopt(r.document)) throw new Error(invalid); this.doc = r.document;
      this.update({ ...this.baseline(next), notice: r.content_changed ? 'CRM values were applied. Review the updated document before sending.' : 'The CRM mapping review was saved. The existing document values and PDF were retained.' });
    } catch (e) { if (this.current(op.epoch)) {
      const status = e && typeof e === 'object' && 'status' in e ? e.status : 0;
      const unknown = dispatched && (!status || (status as number) >= 500);
      this.update({ fresh: false, confirmation: '', needsReadback: unknown, readbackReason: unknown ? 'uncertain' : null,
        error: unknown ? 'The Apply result is uncertain. Inspect the saved document and mappings before another write; your manual wording is retained.' : crmDocumentError(e) });
    } } finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  async inspectReadback() {
    if (this.disposed || this.state.busy || !this.state.needsReadback) return;
    const op = this.start('readback');
    try { this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return;
      const d = checkedCRMDocument(await this.transport.document(this.doc.id, op.signal)); if (!this.current(op.epoch)) return;
      if (d.id !== this.doc.id || d.org_id !== this.doc.org_id || d.sender_id !== this.doc.sender_id || d.status !== 'draft' || d.source_kind !== this.doc.source_kind || d.has_html_source !== this.doc.has_html_source) throw new Error(invalid);
      if (d.has_html_source) currentHTMLSource(await this.transport.source(d.id, op.signal), d); if (!this.current(op.epoch)) return;
      const c = checkedCRMContext(await this.transport.context(d.id, op.signal)); if (!this.current(op.epoch)) return; this.documentMatches(c, d);
      if (!contextValuesMatch(c, d)) throw new Error(invalid);
      this.actorMatches(await this.transport.identity(op.signal)); if (!this.current(op.epoch)) return; this.update({ readback: { document: d, context: c } });
    } catch (e) { if (this.current(op.epoch)) this.update({ readback: null, error: crmDocumentError(e) }); }
    finally { if (this.current(op.epoch)) this.update({ busy: null }); }
  }
  adoptReadback() {
    const r = this.state.readback; if (!r || !this.editorClean() || this.state.busy || !this.state.needsReadback) return;
    if (!this.adopt(r.document)) { this.update({ error: invalid }); return; } this.doc = r.document;
    const uncertain = this.state.readbackReason === 'uncertain';
    this.update({ ...this.baseline(r.context), notice: uncertain
      ? 'The inspected saved document and mappings are loaded. An earlier interrupted request may still complete; another change will require fresh review.'
      : 'The newer inspected document and mappings are loaded. Review their current content before sending.' });
  }
}
