import { htmlSHA256, htmlUUID } from './htmlRevision';
import type { HTMLValueDefinition, HTMLSectionDefinition } from './htmlTemplate';

export interface SupersessionActor { org_id: string; user_id: string }
export interface SupersessionTemplatePin { id: string; version: number; content_sha256: string; approved_by: string; approved_at: string }
export interface SupersessionParent { execution_id: string; execution_sha256: string; document_id: string; source_commitment: string; materialization_id: string; materialization_revision: number; template: SupersessionTemplatePin }
export interface SupersessionReady extends SupersessionActor { schema_version: 1; state: 'ready'; creation_available: boolean; prior: SupersessionParent; template: { id: string; version: number; content_sha256: string; values: HTMLValueDefinition[]; defaults: Record<string, string>; sections: HTMLSectionDefinition[] } }
export interface SupersessionLinked extends SupersessionActor { schema_version: 1; state: 'linked'; prior_document_id: string; document_id: string }
export type SupersessionContext = SupersessionReady | SupersessionLinked;
export interface SupersessionMarker extends SupersessionActor { schema_version: 1; prior_document_id: string; prior_execution_id: string; template_id: string; request_id: string }
export interface SupersessionResult { schema_version: 1; state: 'committed'; request_id: string; prior_execution_id: string; prior_document_id: string; document_id: string; source_commitment: string }
export type SupersessionOutcome = SupersessionResult | { state: 'unconfirmed' | 'closed' };
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === keys.length && Object.keys(v).every(k => keys.includes(k));
const id = (v: unknown): v is string => htmlUUID(v) && v === v.toLowerCase();
const revision = (v: unknown): v is number => Number.isInteger(v) && Number(v) > 0 && Number(v) <= 2147483647;
const name = (v: unknown): v is string => typeof v === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(v);
const text = (v: unknown, limit: number): v is string => typeof v === 'string' && Array.from(v).length <= limit && !/[\uD800-\uDFFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(v);
const fail = (): never => { throw new Error('The linked draft context could not be verified. Reload before creating a draft.'); };
export function checkedSupersessionContext(v: unknown, actor: SupersessionActor, documentID: string): SupersessionContext {
  if (!record(v) || v.schema_version !== 1 || v.org_id !== actor.org_id || v.user_id !== actor.user_id || !id(v.org_id) || !id(v.user_id) || !id(documentID)) return fail();
  if (v.state === 'linked') {
    if (!exact(v, ['schema_version', 'state', 'org_id', 'user_id', 'prior_document_id', 'document_id']) || v.prior_document_id !== documentID || !id(v.document_id) || v.document_id === documentID) return fail();
    return v as unknown as SupersessionLinked;
  }
  if (!exact(v, ['schema_version', 'state', 'org_id', 'user_id', 'creation_available', 'prior', 'template']) || v.state !== 'ready' || typeof v.creation_available !== 'boolean') return fail();
  const p = v.prior, t = v.template;
  if (!exact(p, ['execution_id', 'execution_sha256', 'document_id', 'source_commitment', 'materialization_id', 'materialization_revision', 'template']) || !id(p.execution_id) || !htmlSHA256(p.execution_sha256) || p.document_id !== documentID || !htmlSHA256(p.source_commitment) || !id(p.materialization_id) || !revision(p.materialization_revision)) return fail();
  const old = p.template;
  if (!exact(old, ['id', 'version', 'content_sha256', 'approved_by', 'approved_at']) || !id(old.id) || !revision(old.version) || !htmlSHA256(old.content_sha256) || !id(old.approved_by) || !text(old.approved_at, 64) || !Number.isFinite(Date.parse(old.approved_at))) return fail();
  if (!exact(t, ['id', 'version', 'content_sha256', 'values', 'defaults', 'sections']) || t.id !== old.id || !revision(t.version) || !htmlSHA256(t.content_sha256) || !Array.isArray(t.values) || t.values.length > 64 || !Array.isArray(t.sections) || t.sections.length > 64 || !record(t.defaults)) return fail();
  const values = new Map<string, number>(), sections = new Set<string>();
  for (const f of t.values) { if (!exact(f, ['name', 'required', 'max_chars']) || !name(f.name) || values.has(f.name) || typeof f.required !== 'boolean' || !Number.isInteger(f.max_chars) || Number(f.max_chars) < 0 || Number(f.max_chars) > 8192) return fail(); values.set(f.name, Number(f.max_chars) || 8192); }
  for (const [key, value] of Object.entries(t.defaults)) if (!values.has(key) || !text(value, values.get(key)!)) return fail();
  for (const f of t.sections) { if (!exact(f, ['name', 'default_text', 'max_chars']) || !name(f.name) || sections.has(f.name) || !Number.isInteger(f.max_chars) || Number(f.max_chars) < 0 || Number(f.max_chars) > 32768 || !text(f.default_text, Number(f.max_chars) || 32768)) return fail(); sections.add(f.name); }
  return v as unknown as SupersessionReady;
}
export function checkedSupersessionMarker(v: unknown): SupersessionMarker {
  if (!exact(v, ['schema_version', 'org_id', 'user_id', 'prior_document_id', 'prior_execution_id', 'template_id', 'request_id']) || v.schema_version !== 1 || ![v.org_id, v.user_id, v.prior_document_id, v.prior_execution_id, v.template_id, v.request_id].every(id)) return fail();
  return v as unknown as SupersessionMarker;
}
export const supersessionMarkerKey = 'hash.presign.supersession.pending.v1';
export function readSupersessionMarker(storage: Pick<Storage, 'getItem'>) {
  try { const raw = storage.getItem(supersessionMarkerKey); return { marker: raw === null ? null : checkedSupersessionMarker(JSON.parse(raw)), invalid: false }; } catch { return { marker: null, invalid: true }; }
}
export function saveSupersessionMarker(storage: Pick<Storage, 'setItem' | 'removeItem'>, marker: SupersessionMarker | null) { if (marker) storage.setItem(supersessionMarkerKey, JSON.stringify(checkedSupersessionMarker(marker))); else storage.removeItem(supersessionMarkerKey); }
export function supersessionCommand(context: SupersessionReady, nameValue: string, values: Record<string, string>, sections: Record<string, string>, requestID: string) {
  const c = checkedSupersessionContext(context, context, context.prior.document_id);
  if (c.state !== 'ready' || !c.creation_available || !id(requestID) || !text(nameValue, 200) || !nameValue.trim()) return fail();
  if (!record(values) || !record(sections) || Object.keys(values).some(k => !c.template.values.some(f => f.name === k)) || Object.keys(sections).some(k => !c.template.sections.some(f => f.name === k))) return fail();
  for (const f of c.template.values) if ((Object.hasOwn(values, f.name) && !text(values[f.name], f.max_chars || 8192)) || (f.required && (!Object.hasOwn(values, f.name) || !values[f.name].trim()))) return fail();
  for (const f of c.template.sections) if (Object.hasOwn(sections, f.name) && !text(sections[f.name], f.max_chars || 32768)) return fail();
  return { prior: c.prior, template_id: c.template.id, source: { name: nameValue, expected_template_version: c.template.version, expected_template_content_sha256: c.template.content_sha256, values, sections, request_id: requestID, expected_org_id: c.org_id, expected_user_id: c.user_id } };
}
export function checkedSupersessionResult(v: unknown, marker: SupersessionMarker): SupersessionResult {
  const m = checkedSupersessionMarker(marker);
  if (!exact(v, ['schema_version', 'request_id', 'state', 'prior_execution_id', 'prior_document_id', 'document_id', 'source_commitment']) || v.schema_version !== 1 || v.state !== 'committed' || v.request_id !== m.request_id || v.prior_document_id !== m.prior_document_id || v.prior_execution_id !== m.prior_execution_id || !id(v.document_id) || v.document_id === m.prior_document_id || !htmlSHA256(v.source_commitment)) return fail();
  return v as unknown as SupersessionResult;
}
export function checkedSupersessionClosure(v: unknown, marker: SupersessionMarker): boolean {
  const m = checkedSupersessionMarker(marker);
  return exact(v, ['state', 'org_id', 'user_id', 'template_id', 'request_id', 'closed_at']) && v.state === 'closed' && v.org_id === m.org_id && v.user_id === m.user_id && v.template_id === m.template_id && v.request_id === m.request_id && text(v.closed_at, 64) && Number.isFinite(Date.parse(v.closed_at));
}
