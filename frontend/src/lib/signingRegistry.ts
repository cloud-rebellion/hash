// Registry and self-authority only. These records do not enable signing or sending.
import { htmlSHA256, htmlUUID as sharedHTMLUUID } from './htmlRevision';
import { htmlContractProfile, type HTMLContractProfile, type HTMLSectionDefinition, type HTMLValueDefinition } from './htmlTemplate';

export const signingRegistryMarkerKey = 'hash.signing-authority-request.v1';
const htmlUUID = (v: unknown): v is string => sharedHTMLUUID(v) && v === v.toLowerCase();
export const signingNilUUID = '00000000-0000-0000-0000-000000000000';
export const signingOperations = ['workflow.approve', 'workflow.retire', 'workflow.archive', 'grant.create', 'grant.revise', 'grant.self_revoke', 'grant.owner_revoke'] as const;
export type SigningOperation = typeof signingOperations[number];
export interface SigningActor { org_id: string; user_id: string; role: 'owner' | 'sender' | 'viewer' }
export interface SigningReference { id: string; revision: number; sha256: string }
export interface SigningTemplatePin { id: string; version: number; content_sha256: string; approved_by: string; approved_at: string }
export interface SigningExecutor { kind: 'member' | 'api_key'; user_id: string; credential_id: string }
export interface SigningRules { input_mode: 'reviewed_document' | 'approved_data'; input_rules_sha256: string; data_rules_sha256: string; recipient_rules_sha256: string }
export interface SigningValueRule { variable: string; mode: string; literal?: string; grantor_field?: string; source_kind?: string; source_path?: string }
export interface SigningSectionRule { section: string; mode: string; literal?: string }
export interface SigningWorkflowDefinition {
  version: 1; id: string; policy_id: string; org_id: string; revision: number; name: string;
  kind: 'reviewed_document_send_v1' | 'approved_data_send_v1'; template: SigningTemplatePin; executor: SigningExecutor;
  operation: 'pre_sign_and_send';
  input_rules: { version: 1; source_schema_version: 3; standalone: true; signature_fields_only: true; author_must_be_grantor: true };
  data_rules: { version: 1; values: SigningValueRule[]; sections: SigningSectionRule[]; crm?: { connection_id: string; generation: string; origin: string; team_id: string; user_id: string; selection: string; records: { kind: string; id?: string }[] } };
  recipient_rules: { version: 1; provider: 'named_grantor_exact'; customer: 'printed_profile_exact'; mode: 'parallel'; provider_company_name: string; provider_company_id: string; provider_authority_basis: string };
  max_grant_duration_seconds: number; max_uses: number;
}
export interface SigningPolicy {
  schema_version: 1; id: string; org_id: string; revision: number; template: SigningTemplatePin;
  workflow: { id: string; revision: number; content_sha256: string; approved_by: string; approved_at: string };
  executor: SigningExecutor; operation: 'pre_sign_and_send'; rules: SigningRules; max_grant_duration_seconds: number; max_uses: number;
  approved_by: string; approved_at: string;
}
export interface SigningNamedRepresentative { user_id: string; name: string; email: string; company_name: string; company_id: string; authority_basis: string }
export interface SigningStyle { font: string; font_sha256: string }
export interface SigningCopy { version: number; sha256: string }
export interface SigningGrant {
  schema_version: 1; id: string; org_id: string; revision: number; policy: SigningReference; grantor: SigningNamedRepresentative;
  signature: SigningStyle; disclosure: SigningCopy; granted_at: string; not_before: string; expires_at: string; max_uses: number;
}
export interface SigningWorkflowView { org_id: string; user_id: string; definition: SigningWorkflowDefinition; definition_sha256: string; policy: SigningPolicy; policy_reference: SigningReference; current_revision: number; archived: boolean; retired: boolean }
export interface SigningGrantView { org_id: string; user_id: string; grant: SigningGrant; reference: SigningReference; current_revision: number; revoked: boolean; revocation_reason?: string; expired: boolean; consumed_uses: number; execution_available: false }
export interface SigningContext { org_id: string; user_id: string; self: { id: string; name: string; email: string; role: 'owner' | 'sender' | 'viewer' }; execution_available: false; fonts: SigningStyle[]; disclosure: SigningCopy & { text: string } }
export interface SigningTemplateChoice { name: string; template: SigningTemplatePin; values: HTMLValueDefinition[]; sections: HTMLSectionDefinition[]; defaults: Record<string, string>; contract_profile: HTMLContractProfile }
export interface SigningTemplateCatalog { org_id: string; user_id: string; items: SigningTemplateChoice[]; truncated: boolean }
export interface SigningWorkflowIntent { request_id: string; expected_org_id: string; expected_user_id: string; expected_revision: number; definition: SigningWorkflowDefinition }
export interface SigningGrantIntent { request_id: string; expected_org_id: string; expected_user_id: string; grant_id: string; expected_revision: number; policy: SigningReference; company_name: string; company_id: string; authority_basis: string; font: string; not_before: string; expires_at: string; max_uses: number }
export interface SigningResourceIntent { request_id: string; expected_org_id: string; expected_user_id: string; reference: SigningReference; confirmed: true }
export interface SigningWorkflowPreview { org_id: string; user_id: string; intent: SigningWorkflowIntent; definition_sha256: string; rules: SigningRules; receipt: string; expires_at: string }
export interface SigningGrantPreview { org_id: string; user_id: string; intent: SigningGrantIntent; grantor: SigningNamedRepresentative; signature: SigningStyle; disclosure: SigningCopy; receipt: string; expires_at: string }
export type SigningPreview = SigningWorkflowPreview | SigningGrantPreview;
export interface SigningOutcome { org_id: string; user_id: string; request_id: string; state: 'committed' | 'closed'; operation: SigningOperation | 'request.close'; command_sha256?: string; resource_kind?: string; reference: SigningReference; occurred_at: string }
export interface SigningMarker { version: 1; org_id: string; user_id: string; request_id: string; operation: SigningOperation; resource_id: string; resource_revision: number; resource_sha256?: string; command_sha256?: string }

const invalid = 'The signing authority response could not be verified. Your draft is retained.';
const bytes = (v: unknown, max = 4096): v is string => typeof v === 'string' && new TextEncoder().encode(v).length <= max;
const requiredText = (v: unknown, max = 4096): v is string => bytes(v, max) && !!v.trim() && !/[\u0000-\u001f\u007f]/u.test(v);
const timestamp = (v: unknown): v is string => bytes(v, 40) && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(Date.parse(`${v.slice(0, 19)}Z`)).toISOString().slice(0, 19) === v.slice(0, 19);
export const signingEligibleName = (v: unknown): v is string => requiredText(v, 800) && v.trim() === v && Array.from(v).length <= 200 && !/\p{Cc}/u.test(v);
function normalizedTime(v: string) {
  const match = /^(.*T\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(v)!;
  const second = new Date(Date.parse(`${match[1]}${match[3]}`)).toISOString().slice(0, 19), fraction = (match[2] ?? '').slice(0, 6).replace(/0+$/, '');
  return `${second}${fraction ? `.${fraction}` : ''}Z`;
}
const revision = (v: unknown, zero = false): v is number => Number.isInteger(v) && (v as number) >= (zero ? 0 : 1) && (v as number) <= 1_000_000;
const variable = (v: unknown): v is string => bytes(v, 64) && /^[a-z][a-z0-9_]{0,63}$/.test(v);
function object(v: unknown, keys: string[], optional: string[] = []): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v) || keys.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !keys.includes(k) && !optional.includes(k))) throw new Error(invalid);
  return v as Record<string, unknown>;
}
function array(v: unknown, max = 100): unknown[] { if (!Array.isArray(v) || v.length > max) throw new Error(invalid); return v; }
function unique<T>(items: T[], key: (v: T) => string): T[] { if (new Set(items.map(key)).size !== items.length) throw new Error(invalid); return items; }
function actor(r: Record<string, unknown>) { if (!htmlUUID(r.org_id) || !htmlUUID(r.user_id)) throw new Error(invalid); }
export function checkedSigningActor(v: unknown): SigningActor {
  const r = v as Record<string, unknown>; if (!r || typeof r !== 'object') throw new Error(invalid); actor(r);
  if (!['owner', 'sender', 'viewer'].includes(r.role as string)) throw new Error(invalid);
  return { org_id: r.org_id as string, user_id: r.user_id as string, role: r.role as SigningActor['role'] };
}
export function checkedSigningReference(v: unknown, empty = false): SigningReference {
  const r = object(v, ['id', 'revision', 'sha256']);
  if (empty && r.id === signingNilUUID && r.revision === 0 && r.sha256 === '') return r as unknown as SigningReference;
  if (!htmlUUID(r.id) || !revision(r.revision) || !htmlSHA256(r.sha256)) throw new Error(invalid);
  return { ...r } as unknown as SigningReference;
}
function template(v: unknown): SigningTemplatePin {
  const r = object(v, ['id', 'version', 'content_sha256', 'approved_by', 'approved_at']);
  if (!htmlUUID(r.id) || !revision(r.version) || !htmlSHA256(r.content_sha256) || !htmlUUID(r.approved_by) || !timestamp(r.approved_at)) throw new Error(invalid);
  return { ...r, approved_at: normalizedTime(r.approved_at) } as unknown as SigningTemplatePin;
}
function executor(v: unknown): SigningExecutor {
  const r = object(v, ['kind', 'user_id', 'credential_id']);
  if (!htmlUUID(r.user_id) || !(r.kind === 'member' ? r.credential_id === signingNilUUID : r.kind === 'api_key' && htmlUUID(r.credential_id))) throw new Error(invalid);
  return { ...r } as unknown as SigningExecutor;
}
function rules(v: unknown): SigningRules {
  const r = object(v, ['input_mode', 'input_rules_sha256', 'data_rules_sha256', 'recipient_rules_sha256']);
  if (!['reviewed_document', 'approved_data'].includes(r.input_mode as string) || ![r.input_rules_sha256, r.data_rules_sha256, r.recipient_rules_sha256].every(htmlSHA256)) throw new Error(invalid);
  return { ...r } as unknown as SigningRules;
}
function limits(duration: unknown, uses: unknown) { if (!Number.isInteger(duration) || (duration as number) < 1 || (duration as number) > 366 * 86400 || !revision(uses)) throw new Error(invalid); }
export function checkedSigningDefinition(v: unknown): SigningWorkflowDefinition {
  const r = object(v, ['version', 'id', 'policy_id', 'org_id', 'revision', 'name', 'kind', 'template', 'executor', 'operation', 'input_rules', 'data_rules', 'recipient_rules', 'max_grant_duration_seconds', 'max_uses']);
  if (r.version !== 1 || ![r.id, r.policy_id, r.org_id].every(htmlUUID) || !revision(r.revision) || !requiredText(r.name, 800) || !['reviewed_document_send_v1', 'approved_data_send_v1'].includes(r.kind as string) || r.operation !== 'pre_sign_and_send') throw new Error(invalid);
  const input = object(r.input_rules, ['version', 'source_schema_version', 'standalone', 'signature_fields_only', 'author_must_be_grantor']);
  if (input.version !== 1 || input.source_schema_version !== 3 || input.standalone !== true || input.signature_fields_only !== true || input.author_must_be_grantor !== true) throw new Error(invalid);
  const data = object(r.data_rules, ['version', 'values', 'sections'], ['crm']); if (data.version !== 1) throw new Error(invalid);
  const values = unique(array(data.values, 64).map(v => {
    const x = object(v, ['variable', 'mode'], ['literal', 'grantor_field', 'source_kind', 'source_path']);
    if (!variable(x.variable) || !['reviewed_value', 'approved_default', 'literal', 'absent', 'grantor_field', 'crm_scalar'].includes(x.mode as string)) throw new Error(invalid);
    const allowed = x.mode === 'literal' ? ['literal'] : x.mode === 'grantor_field' ? ['grantor_field'] : x.mode === 'crm_scalar' ? ['source_kind', 'source_path'] : [];
    if (['literal', 'grantor_field', 'source_kind', 'source_path'].some(k => Object.hasOwn(x, k) !== allowed.includes(k)) || (x.mode === 'literal' && !bytes(x.literal, 131072)) || (x.mode === 'grantor_field' && !['name', 'email', 'company_name', 'company_id', 'authority_basis'].includes(x.grantor_field as string))
      || (x.mode === 'crm_scalar' && (!['crm.deal', 'crm.contact', 'crm.company'].includes(x.source_kind as string) || !requiredText(x.source_path, 128)))) throw new Error(invalid);
    return { ...x } as unknown as SigningValueRule;
  }), x => x.variable).sort((a, b) => a.variable < b.variable ? -1 : a.variable > b.variable ? 1 : 0);
  const sections = unique(array(data.sections, 64).map(v => {
    const x = object(v, ['section', 'mode'], ['literal']);
    if (!variable(x.section) || !['reviewed_value', 'approved_default', 'literal'].includes(x.mode as string) || (Object.hasOwn(x, 'literal') !== (x.mode === 'literal')) || (x.mode === 'literal' && !bytes(x.literal, 131072))) throw new Error(invalid);
    return { ...x } as unknown as SigningSectionRule;
  }), x => x.section).sort((a, b) => a.section < b.section ? -1 : a.section > b.section ? 1 : 0);
  let crm: SigningWorkflowDefinition['data_rules']['crm'];
  if (Object.hasOwn(data, 'crm')) {
    const c = object(data.crm, ['connection_id', 'generation', 'origin', 'team_id', 'user_id', 'selection', 'records']);
    if (!htmlUUID(c.connection_id) || typeof c.generation !== 'string' || !/^[1-9][0-9]{0,18}$/.test(c.generation) || BigInt(c.generation) > 9223372036854775807n || !requiredText(c.origin, 2048)
      || ![c.team_id, c.user_id].every(v => bytes(v, 256) && /^[A-Za-z0-9_-]+$/.test(v)) || !['fixed_record_set', 'execution_record_set'].includes(c.selection as string)) throw new Error(invalid);
    const url = new URL(c.origin); if (!['http:', 'https:'].includes(url.protocol) || url.origin !== c.origin || url.username || url.password) throw new Error(invalid);
    const records = unique(array(c.records, 3).map(v => { const x = object(v, ['kind'], ['id']); if (!['crm.deal', 'crm.contact', 'crm.company'].includes(x.kind as string) || (c.selection === 'fixed_record_set' ? !bytes(x.id, 256) || !/^[A-Za-z0-9_-]+$/.test(x.id) : Object.hasOwn(x, 'id'))) throw new Error(invalid); return { ...x } as { kind: string; id?: string }; }), x => x.kind).sort((a, b) => a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0);
    if (!records.length) throw new Error(invalid);
    crm = { ...c, records } as unknown as typeof crm;
  }
  const recipients = object(r.recipient_rules, ['version', 'provider', 'customer', 'mode', 'provider_company_name', 'provider_company_id', 'provider_authority_basis']);
  if (recipients.version !== 1 || recipients.provider !== 'named_grantor_exact' || recipients.customer !== 'printed_profile_exact' || recipients.mode !== 'parallel' || ![recipients.provider_company_name, recipients.provider_company_id, recipients.provider_authority_basis].every(v => requiredText(v, 4096))) throw new Error(invalid);
  limits(r.max_grant_duration_seconds, r.max_uses);
  if (values.some(v => v.mode === 'crm_scalar') !== !!crm || (r.kind === 'approved_data_send_v1' && (values.some(v => v.mode === 'reviewed_value') || sections.some(v => v.mode === 'reviewed_value')))) throw new Error(invalid);
  return { ...r, template: template(r.template), executor: executor(r.executor), input_rules: { ...input }, data_rules: { version: 1, values, sections, ...(crm ? { crm } : {}) }, recipient_rules: { ...recipients } } as unknown as SigningWorkflowDefinition;
}
function representative(v: unknown): SigningNamedRepresentative { const r = object(v, ['user_id', 'name', 'email', 'company_name', 'company_id', 'authority_basis']); if (!htmlUUID(r.user_id) || ![r.name, r.email, r.company_name, r.company_id, r.authority_basis].every(v => requiredText(v, 4096))) throw new Error(invalid); return { ...r } as unknown as SigningNamedRepresentative; }
function style(v: unknown): SigningStyle { const r = object(v, ['font', 'font_sha256']); if (!requiredText(r.font, 100) || !htmlSHA256(r.font_sha256)) throw new Error(invalid); return { ...r } as unknown as SigningStyle; }
function copy(v: unknown): SigningCopy { const r = object(v, ['version', 'sha256']); if (!revision(r.version) || !htmlSHA256(r.sha256)) throw new Error(invalid); return { ...r } as unknown as SigningCopy; }
export function checkedSigningContext(v: unknown): SigningContext {
  const r = object(v, ['org_id', 'user_id', 'self', 'execution_available', 'fonts', 'disclosure']); actor(r);
  const self = object(r.self, ['id', 'name', 'email', 'role']);
  if (self.id !== r.user_id || !bytes(self.name, 4096) || !requiredText(self.email, 1024) || !['owner', 'sender', 'viewer'].includes(self.role as string) || r.execution_available !== false) throw new Error(invalid);
  const fonts = unique(array(r.fonts, 16).map(style), x => x.font);
  const d = object(r.disclosure, ['version', 'sha256', 'text']); const disclosure = { ...copy({ version: d.version, sha256: d.sha256 }), text: d.text as string }; if (!bytes(d.text, 32768) || !d.text.trim()) throw new Error(invalid);
  return { org_id: r.org_id as string, user_id: r.user_id as string, self: { ...self } as SigningContext['self'], execution_available: false, fonts, disclosure };
}
export function checkedSigningTemplates(v: unknown): SigningTemplateCatalog {
  const r = object(v, ['org_id', 'user_id', 'items', 'truncated']); actor(r); if (typeof r.truncated !== 'boolean') throw new Error(invalid);
  const items = unique(array(r.items, 20).map(v => {
    const t = object(v, ['name', 'template', 'values', 'sections', 'defaults', 'contract_profile']); if (!requiredText(t.name, 800)) throw new Error(invalid);
    const values = unique(array(t.values, 64).map(v => { const x = object(v, ['name', 'required', 'max_chars']); if (!variable(x.name) || typeof x.required !== 'boolean' || !Number.isInteger(x.max_chars) || (x.max_chars as number) < 1 || (x.max_chars as number) > 8192) throw new Error(invalid); return { ...x } as unknown as HTMLValueDefinition; }), x => x.name);
    const sections = unique(array(t.sections, 64).map(v => { const x = object(v, ['name', 'default_text', 'max_chars']); if (!variable(x.name) || !bytes(x.default_text, 131072) || !Number.isInteger(x.max_chars) || (x.max_chars as number) < 1 || (x.max_chars as number) > 32768) throw new Error(invalid); return { ...x } as unknown as HTMLSectionDefinition; }), x => x.name);
    if (!t.defaults || typeof t.defaults !== 'object' || Array.isArray(t.defaults) || Object.entries(t.defaults).some(([k, x]) => !values.some(v => v.name === k) || !bytes(x, 131072))) throw new Error(invalid);
    const profile = htmlContractProfile({ schema_version: 2, html: '', css: '', values, sections, contract_profile: t.contract_profile as HTMLContractProfile }); if (!profile) throw new Error(invalid);
    return { name: t.name as string, template: template(t.template), values, sections, defaults: { ...t.defaults } as Record<string, string>, contract_profile: profile };
  }), t => `${t.template.id}:${t.template.version}`);
  return { org_id: r.org_id as string, user_id: r.user_id as string, items, truncated: r.truncated };
}
function checkedPolicy(v: unknown): SigningPolicy {
  const r = object(v, ['schema_version', 'id', 'org_id', 'revision', 'template', 'workflow', 'executor', 'operation', 'rules', 'max_grant_duration_seconds', 'max_uses', 'approved_by', 'approved_at']);
  const w = object(r.workflow, ['id', 'revision', 'content_sha256', 'approved_by', 'approved_at']);
  if (r.schema_version !== 1 || ![r.id, r.org_id, r.approved_by, w.id, w.approved_by].every(htmlUUID) || !revision(r.revision) || !revision(w.revision) || !htmlSHA256(w.content_sha256) || !timestamp(w.approved_at) || !timestamp(r.approved_at) || r.operation !== 'pre_sign_and_send') throw new Error(invalid);
  limits(r.max_grant_duration_seconds, r.max_uses);
  return { ...r, template: template(r.template), workflow: { ...w }, executor: executor(r.executor), rules: rules(r.rules) } as unknown as SigningPolicy;
}
export function checkedSigningWorkflow(v: unknown): SigningWorkflowView {
  const r = object(v, ['org_id', 'user_id', 'definition', 'definition_sha256', 'policy', 'policy_reference', 'current_revision', 'archived', 'retired']); actor(r);
  const definition = checkedSigningDefinition(r.definition), policy = checkedPolicy(r.policy), ref = checkedSigningReference(r.policy_reference);
  if (!htmlSHA256(r.definition_sha256) || !revision(r.current_revision) || (r.current_revision as number) < definition.revision || typeof r.archived !== 'boolean' || typeof r.retired !== 'boolean'
    || definition.org_id !== r.org_id || policy.org_id !== r.org_id || ref.id !== policy.id || ref.revision !== policy.revision || definition.policy_id !== policy.id || policy.workflow.id !== definition.id || policy.workflow.revision !== definition.revision || policy.workflow.content_sha256 !== r.definition_sha256
    || signingKey(definition.template) !== signingKey(policy.template) || signingKey(definition.executor) !== signingKey(policy.executor) || definition.revision !== policy.revision
    || definition.max_uses !== policy.max_uses || definition.max_grant_duration_seconds !== policy.max_grant_duration_seconds || policy.rules.input_mode !== (definition.kind === 'reviewed_document_send_v1' ? 'reviewed_document' : 'approved_data')
    || policy.workflow.approved_by !== policy.approved_by || policy.workflow.approved_at !== policy.approved_at) throw new Error(invalid);
  return { ...r, definition, policy, policy_reference: ref } as unknown as SigningWorkflowView;
}
export function checkedSigningGrant(v: unknown): SigningGrantView {
  const r = object(v, ['org_id', 'user_id', 'grant', 'reference', 'current_revision', 'revoked', 'expired', 'consumed_uses', 'execution_available'], ['revocation_reason']); actor(r);
  const g = object(r.grant, ['schema_version', 'id', 'org_id', 'revision', 'policy', 'grantor', 'signature', 'disclosure', 'granted_at', 'not_before', 'expires_at', 'max_uses']);
  const ref = checkedSigningReference(r.reference);
  if (g.schema_version !== 1 || !htmlUUID(g.id) || g.org_id !== r.org_id || !revision(g.revision) || ![g.granted_at, g.not_before, g.expires_at].every(timestamp) || Date.parse(g.expires_at as string) <= Date.parse(g.not_before as string) || !revision(g.max_uses)
    || !revision(r.current_revision) || (r.current_revision as number) < (g.revision as number) || typeof r.revoked !== 'boolean' || typeof r.expired !== 'boolean' || !Number.isInteger(r.consumed_uses) || (r.consumed_uses as number) < 0 || (r.consumed_uses as number) > (g.max_uses as number) || r.execution_available !== false
    || ref.id !== g.id || ref.revision !== g.revision || (Object.hasOwn(r, 'revocation_reason') && !requiredText(r.revocation_reason, 256))) throw new Error(invalid);
  return { ...r, reference: ref, grant: { ...g, policy: checkedSigningReference(g.policy), grantor: representative(g.grantor), signature: style(g.signature), disclosure: copy(g.disclosure) } } as unknown as SigningGrantView;
}
export function checkedSigningCollection<T>(v: unknown, checked: (v: unknown) => T): { org_id: string; user_id: string; items: T[] } {
  const r = object(v, ['org_id', 'user_id', 'items']); actor(r); const items = array(r.items).map(checked);
  for (const item of items) { const w = item as { org_id: string; user_id: string }; if (w.org_id !== r.org_id || w.user_id !== r.user_id) throw new Error(invalid); }
  return { org_id: r.org_id as string, user_id: r.user_id as string, items };
}
export function checkedWorkflowIntent(v: unknown): SigningWorkflowIntent {
  const r = object(v, ['request_id', 'expected_org_id', 'expected_user_id', 'expected_revision', 'definition']);
  if (![r.request_id, r.expected_org_id, r.expected_user_id].every(htmlUUID) || !revision(r.expected_revision, true)) throw new Error(invalid);
  const definition = checkedSigningDefinition(r.definition); if (definition.org_id !== r.expected_org_id || definition.revision !== (r.expected_revision as number) + 1) throw new Error(invalid);
  return { ...r, definition } as unknown as SigningWorkflowIntent;
}
export function checkedGrantIntent(v: unknown): SigningGrantIntent {
  const r = object(v, ['request_id', 'expected_org_id', 'expected_user_id', 'grant_id', 'expected_revision', 'policy', 'company_name', 'company_id', 'authority_basis', 'font', 'not_before', 'expires_at', 'max_uses']);
  if (![r.request_id, r.expected_org_id, r.expected_user_id, r.grant_id].every(htmlUUID) || !revision(r.expected_revision, true) || ![r.company_name, r.company_id, r.authority_basis, r.font].every(v => requiredText(v, 4096)) || !timestamp(r.not_before) || !timestamp(r.expires_at) || !revision(r.max_uses)) throw new Error(invalid);
  return { ...r, policy: checkedSigningReference(r.policy), not_before: normalizedTime(r.not_before), expires_at: normalizedTime(r.expires_at) } as unknown as SigningGrantIntent;
}
export function checkedSigningPreview(v: unknown, kind: 'workflow' | 'grant'): SigningPreview {
  const r = object(v, kind === 'workflow' ? ['org_id', 'user_id', 'intent', 'definition_sha256', 'rules', 'receipt', 'expires_at'] : ['org_id', 'user_id', 'intent', 'grantor', 'signature', 'disclosure', 'receipt', 'expires_at']); actor(r);
  if (!requiredText(r.receipt, 16384) || /\s/u.test(r.receipt) || !timestamp(r.expires_at)) throw new Error(invalid);
  if (kind === 'workflow') { if (!htmlSHA256(r.definition_sha256)) throw new Error(invalid); return { ...r, intent: checkedWorkflowIntent(r.intent), rules: rules(r.rules) } as unknown as SigningWorkflowPreview; }
  return { ...r, intent: checkedGrantIntent(r.intent), grantor: representative(r.grantor), signature: style(r.signature), disclosure: copy(r.disclosure) } as unknown as SigningGrantPreview;
}
export function checkedSigningOutcome(v: unknown): SigningOutcome {
  const r = object(v, ['org_id', 'user_id', 'request_id', 'state', 'operation', 'reference', 'occurred_at'], ['command_sha256', 'resource_kind']); actor(r);
  if (!htmlUUID(r.request_id) || !['committed', 'closed'].includes(r.state as string) || ![...signingOperations, 'request.close'].includes(r.operation as SigningOperation) || !timestamp(r.occurred_at)) throw new Error(invalid);
  const ref = checkedSigningReference(r.reference, r.state === 'closed');
  if (r.state === 'committed' ? !htmlSHA256(r.command_sha256) || !['workflow', 'grant'].includes(r.resource_kind as string) || r.operation === 'request.close' : Object.hasOwn(r, 'command_sha256') || Object.hasOwn(r, 'resource_kind') || ref.id !== signingNilUUID) throw new Error(invalid);
  return { ...r, reference: ref } as unknown as SigningOutcome;
}
export function checkedSigningMarker(v: unknown): SigningMarker {
  const r = object(v, ['version', 'org_id', 'user_id', 'request_id', 'operation', 'resource_id', 'resource_revision'], ['resource_sha256', 'command_sha256']); actor(r);
  if (r.version !== 1 || !htmlUUID(r.request_id) || !htmlUUID(r.resource_id) || !revision(r.resource_revision) || !signingOperations.includes(r.operation as SigningOperation) || (Object.hasOwn(r, 'resource_sha256') && !htmlSHA256(r.resource_sha256)) || (Object.hasOwn(r, 'command_sha256') && !htmlSHA256(r.command_sha256))) throw new Error(invalid);
  return { ...r } as unknown as SigningMarker;
}
export function readSigningMarker(storage: Pick<Storage, 'getItem'>): SigningMarker | null { const raw = storage.getItem(signingRegistryMarkerKey); if (raw === null) return null; if (raw.length > 1024) throw new Error(invalid); return checkedSigningMarker(JSON.parse(raw)); }
export function saveSigningMarker(storage: Pick<Storage, 'setItem' | 'removeItem'>, marker: SigningMarker | null) { if (marker) storage.setItem(signingRegistryMarkerKey, JSON.stringify(checkedSigningMarker(marker))); else storage.removeItem(signingRegistryMarkerKey); }
// Recursive key ordering makes JSON member order irrelevant while retaining rule-array order.
export function signingKey(v: unknown): string { const canonical = (v: unknown): unknown => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, x]) => [k, canonical(x)])) : v; return JSON.stringify(canonical(v)); }

export interface SigningRegistryTransport {
  identity(signal: AbortSignal): Promise<unknown>;
  context(signal: AbortSignal): Promise<unknown>;
  templates(signal: AbortSignal): Promise<unknown>;
  workflows(signal: AbortSignal): Promise<unknown>;
  grants(signal: AbortSignal, owner: boolean): Promise<unknown>;
  preview(kind: 'workflow' | 'grant', intent: SigningWorkflowIntent | SigningGrantIntent, signal: AbortSignal): Promise<unknown>;
  mutate(operation: SigningOperation, input: unknown, signal: AbortSignal): Promise<unknown>;
  outcome(marker: SigningMarker, signal: AbortSignal): Promise<unknown>;
  close(marker: SigningMarker, signal: AbortSignal): Promise<unknown>;
  signatureFont(style: SigningStyle, signal: AbortSignal): Promise<string>;
}
export interface SigningRegistryState {
  context: SigningContext | null; workflows: SigningWorkflowView[]; grants: SigningGrantView[]; templates: SigningTemplateChoice[]; templatesTruncated: boolean;
  fresh: boolean; busy: string | null; preview: SigningPreview | null; confirmed: boolean;
  marker: SigningMarker | null; outcome: SigningOutcome | null; markerError: boolean; error: string | null; notice: string | null; signatureFont: string | null;
}
export const initialSigningRegistryState = (): SigningRegistryState => ({ context: null, workflows: [], grants: [], templates: [], templatesTruncated: false, fresh: false, busy: null, preview: null, confirmed: false, marker: null, outcome: null, markerError: false, error: null, notice: null, signatureFont: null });
function safeError(error: unknown): string {
  const status = error && typeof error === 'object' && 'status' in error ? (error as { status: unknown }).status : null;
  return status === 401 ? 'Your original sign-in expired. Sign in and inspect the same request before continuing.' : status === 403 ? 'Your current role no longer allows this action. Your draft and pending request are retained.' : status === 404 ? 'No terminal outcome is confirmed yet. Inspect or stop the same request; another request remains blocked.' : status === 409 ? 'The selected authority or approval changed. Refresh and review again after resolving any pending request.' : status === 503 ? 'Signing authority is temporarily unavailable. Your draft and pending request are retained.' : invalid;
}
export class SigningRegistryController {
  state = initialSigningRegistryState();
  private epoch = 0;
  private abort: AbortController | null = null;
  private disposed = false;
  private draftVersion = 0;
  private previewVersion = -1;
  private pending: { operation: SigningOperation; input: unknown } | null = null;
  constructor(private transport: SigningRegistryTransport, private changed: (state: SigningRegistryState) => void,
    private markerChanged: (marker: SigningMarker | null) => void, private ownerPage = false, private now = () => Date.now()) {}
  private update(patch: Partial<SigningRegistryState>) { this.state = { ...this.state, ...patch }; this.changed(this.state); }
  private start(busy: string) { this.abort?.abort(); this.abort = new AbortController(); const epoch = ++this.epoch; this.update({ busy, error: null, notice: null }); return { epoch, signal: this.abort.signal }; }
  private current(epoch: number) { return !this.disposed && epoch === this.epoch; }
  private expectActor(value: { org_id: string; user_id: string }, expected: { org_id: string; user_id: string }) { if (value.org_id !== expected.org_id || value.user_id !== expected.user_id) throw new Error(invalid); }
  private async actor(signal: AbortSignal, expected?: SigningActor) { const a = checkedSigningActor(await this.transport.identity(signal)); if (expected) { this.expectActor(a, expected); if (a.role !== expected.role) throw new Error(invalid); } return a; }
  private contextActor(context: SigningContext): SigningActor { return { org_id: context.org_id, user_id: context.user_id, role: context.self.role }; }
  private persist(marker: SigningMarker | null) { this.markerChanged(marker); this.update({ marker }); }
  restore(marker: SigningMarker | null, invalidMarker = false) { this.update({ marker: marker ? checkedSigningMarker(marker) : null, markerError: invalidMarker, outcome: null }); }
  invalidate() { this.draftVersion++; if (!this.state.marker) { this.abort?.abort(); this.epoch++; this.update({ busy: null }); } this.update({ preview: null, confirmed: false, notice: null, signatureFont: null }); }
  interrupt() { this.abort?.abort(); this.epoch++; this.update({ busy: null, fresh: false, preview: null, confirmed: false, signatureFont: null }); }
  dispose() { this.interrupt(); this.disposed = true; }
  get canWrite() { return !this.disposed && this.state.fresh && !!this.state.context && !this.state.busy && !this.state.marker && !this.state.markerError; }
  get canCreate() { return this.canWrite && (this.ownerPage ? this.state.context?.self.role === 'owner' : ['owner', 'sender'].includes(this.state.context!.self.role) && signingEligibleName(this.state.context!.self.name)); }
  get canConfirm() { return this.canCreate && !!this.state.preview && this.state.confirmed && this.previewVersion === this.draftVersion && Date.parse(this.state.preview.expires_at) > this.now(); }
  async refresh() {
    if (this.disposed || this.state.busy) return;
    const { epoch, signal } = this.start('refresh'); this.update({ fresh: false, preview: null, confirmed: false });
    try {
      const admitted = await this.actor(signal); if (!this.current(epoch)) return;
      const prior = this.state.context; if (prior) this.expectActor(admitted, prior);
      if (this.state.marker) this.expectActor(admitted, this.state.marker);
      const context = checkedSigningContext(await this.transport.context(signal)); if (!this.current(epoch)) return; this.expectActor(context, admitted);
      if (context.self.role !== admitted.role) throw new Error(invalid);
      let templates: SigningTemplateCatalog = { org_id: admitted.org_id, user_id: admitted.user_id, items: [], truncated: false };
      if (this.ownerPage && admitted.role === 'owner') { templates = checkedSigningTemplates(await this.transport.templates(signal)); if (!this.current(epoch)) return; this.expectActor(templates, admitted); }
      const workflows = checkedSigningCollection(await this.transport.workflows(signal), checkedSigningWorkflow); if (!this.current(epoch)) return; this.expectActor(workflows, admitted);
      const grants = checkedSigningCollection(await this.transport.grants(signal, this.ownerPage && admitted.role === 'owner'), checkedSigningGrant); if (!this.current(epoch)) return; this.expectActor(grants, admitted);
      if (!this.ownerPage && grants.items.some(g => g.grant.grantor.user_id !== admitted.user_id)) throw new Error(invalid);
      await this.actor(signal, admitted); if (!this.current(epoch)) return;
      this.update({ context, workflows: workflows.items, grants: grants.items, templates: templates.items, templatesTruncated: templates.truncated, fresh: true });
    } catch (e) { if (this.current(epoch)) this.update({ fresh: false, error: safeError(e) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async preview(intent: SigningWorkflowIntent | SigningGrantIntent) {
    if (!this.canCreate) return;
    const kind = this.ownerPage ? 'workflow' : 'grant';
    let validated: SigningWorkflowIntent | SigningGrantIntent;
    try { validated = kind === 'workflow' ? checkedWorkflowIntent(intent) : checkedGrantIntent(intent); } catch (e) { this.update({ error: safeError(e), preview: null, confirmed: false }); return; }
    const context = this.state.context!, expected = this.contextActor(context), version = this.draftVersion;
    if (validated.expected_org_id !== expected.org_id || validated.expected_user_id !== expected.user_id) { this.update({ error: invalid }); return; }
    const { epoch, signal } = this.start('preview'); this.update({ preview: null, confirmed: false, signatureFont: null });
    try {
      await this.actor(signal, expected); if (!this.current(epoch)) return;
      const latest = checkedSigningContext(await this.transport.context(signal)); if (!this.current(epoch)) return;
      if (signingKey(latest) !== signingKey(context)) throw new Error(invalid);
      const p = checkedSigningPreview(await this.transport.preview(kind, validated, signal), kind); if (!this.current(epoch)) return;
      this.expectActor(p, expected);
      if (signingKey(p.intent) !== signingKey(validated) || version !== this.draftVersion || Date.parse(p.expires_at) <= this.now() || Date.parse(p.expires_at) > this.now() + 5 * 60000 + 5000) throw new Error(invalid);
      let signatureFont: string | null = null;
      if (kind === 'grant') {
        const g = p as SigningGrantPreview, i = validated as SigningGrantIntent;
        if (g.grantor.user_id !== context.user_id || g.grantor.name !== context.self.name || g.grantor.email !== context.self.email || g.grantor.company_name !== i.company_name || g.grantor.company_id !== i.company_id || g.grantor.authority_basis !== i.authority_basis
          || !context.fonts.some(f => signingKey(f) === signingKey(g.signature)) || g.signature.font !== i.font || signingKey(g.disclosure) !== signingKey({ version: context.disclosure.version, sha256: context.disclosure.sha256 })) throw new Error(invalid);
        signatureFont = await this.transport.signatureFont(g.signature, signal); if (!this.current(epoch)) return;
        if (!requiredText(signatureFont, 128)) throw new Error(invalid);
      }
      await this.actor(signal, expected); if (!this.current(epoch)) return;
      this.previewVersion = version; this.update({ preview: p, signatureFont });
    } catch (e) { if (this.current(epoch)) this.update({ preview: null, confirmed: false, error: safeError(e) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  confirm(checked: boolean) { this.update({ confirmed: checked && !!this.state.preview && this.previewVersion === this.draftVersion && Date.parse(this.state.preview.expires_at) > this.now() }); }
  async approve() {
    if (!this.canConfirm) return;
    const preview = this.state.preview!;
    const operation = this.ownerPage ? 'workflow.approve' : (preview as SigningGrantPreview).intent.expected_revision === 0 ? 'grant.create' : 'grant.revise';
    const resource = this.ownerPage ? { id: (preview as SigningWorkflowPreview).intent.definition.id, revision: (preview as SigningWorkflowPreview).intent.definition.revision, sha256: (preview as SigningWorkflowPreview).definition_sha256 }
      : { id: (preview as SigningGrantPreview).intent.grant_id, revision: (preview as SigningGrantPreview).intent.expected_revision + 1 };
    await this.dispatch(operation, { intent: preview.intent, receipt: preview.receipt, confirmed: true }, preview.intent.request_id, resource);
  }
  async resource(operation: SigningOperation, reference: SigningReference, confirmed: boolean) {
    if (!this.canWrite || !confirmed) return;
    const c = this.state.context!, owner = c.self.role === 'owner';
    let allowed = false;
    if (operation === 'workflow.retire' || operation === 'workflow.archive') allowed = owner && this.state.workflows.some(w => w.definition.id === reference.id && w.definition.revision === reference.revision && w.definition_sha256 === reference.sha256 && !(operation === 'workflow.archive' ? w.archived : w.retired));
    else if (operation === 'grant.self_revoke') allowed = this.state.grants.some(g => signingKey(g.reference) === signingKey(reference) && g.grant.grantor.user_id === c.user_id && !g.revoked);
    else if (operation === 'grant.owner_revoke') allowed = owner && this.state.grants.some(g => signingKey(g.reference) === signingKey(reference) && !g.revoked);
    if (!allowed) return;
    const request_id = crypto.randomUUID();
    await this.dispatch(operation, { request_id, expected_org_id: c.org_id, expected_user_id: c.user_id, reference: checkedSigningReference(reference), confirmed: true }, request_id, reference);
  }
  private checkedOutcome(raw: unknown, marker: SigningMarker): SigningOutcome {
    const result = checkedSigningOutcome(raw); this.expectActor(result, marker);
    if (result.request_id !== marker.request_id || (result.state === 'committed' && (result.operation !== marker.operation || result.reference.id !== marker.resource_id || result.reference.revision !== marker.resource_revision || (marker.resource_sha256 && result.reference.sha256 !== marker.resource_sha256)
      || result.resource_kind !== (marker.operation.startsWith('workflow.') ? 'workflow' : 'grant'))) || (result.state === 'closed' && (result.operation !== 'request.close' || marker.command_sha256)) || (marker.command_sha256 && result.command_sha256 !== marker.command_sha256)) throw new Error(invalid);
    return result;
  }
  private async dispatch(operation: SigningOperation, input: unknown, request_id: string, resource: { id: string; revision: number; sha256?: string }) {
    if (!this.canWrite) return;
    const context = this.state.context!, expected = this.contextActor(context);
    const { epoch, signal } = this.start('confirm'); let dispatched = false;
    try {
      await this.actor(signal, expected); if (!this.current(epoch)) return;
      const latest = checkedSigningContext(await this.transport.context(signal)); if (!this.current(epoch)) return; if (signingKey(latest) !== signingKey(context)) throw new Error(invalid);
      const marker: SigningMarker = { version: 1, org_id: expected.org_id, user_id: expected.user_id, request_id, operation, resource_id: resource.id, resource_revision: resource.revision, ...(resource.sha256 ? { resource_sha256: resource.sha256 } : {}) };
      this.persist(marker); this.pending = { operation, input: structuredClone(input) }; dispatched = true;
      const raw = await this.transport.mutate(operation, input, signal); if (!this.current(epoch)) return;
      const outcome = this.checkedOutcome(raw, marker);
      await this.actor(signal, expected); if (!this.current(epoch)) return;
      if (outcome.command_sha256) this.persist({ ...marker, command_sha256: outcome.command_sha256 });
      this.update({ outcome, preview: null, confirmed: false, fresh: false, notice: 'The request has a verified terminal outcome. Acknowledge it before another change.' });
    } catch (e) { if (this.current(epoch)) this.update({ error: safeError(e) + (dispatched ? ' This request may have completed. Inspect the same request before continuing.' : ''), fresh: false, confirmed: false }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async inspect() {
    if (this.disposed || this.state.busy || !this.state.marker || this.state.markerError) return;
    const marker = this.state.marker, { epoch, signal } = this.start('inspect'); this.update({ outcome: null });
    try {
      const a = await this.actor(signal); if (!this.current(epoch)) return; this.expectActor(a, marker);
      const outcome = this.checkedOutcome(await this.transport.outcome(marker, signal), marker); if (!this.current(epoch)) return;
      await this.actor(signal, a); if (!this.current(epoch)) return;
      if (outcome.command_sha256) this.persist({ ...marker, command_sha256: outcome.command_sha256 });
      this.update({ outcome, notice: outcome.state === 'closed' ? 'This request was stopped before commitment. Acknowledge the closure to prepare a fresh review.' : 'The original request committed. Its recorded outcome is preserved; current authority may have changed.' });
    } catch (e) { if (this.current(epoch)) this.update({ error: safeError(e) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async retry() {
    if (this.disposed || this.state.busy || !this.state.marker || !this.pending || this.state.outcome) return;
    const marker = this.state.marker, pending = this.pending, { epoch, signal } = this.start('retry');
    try {
      const a = await this.actor(signal); if (!this.current(epoch)) return; this.expectActor(a, marker);
      const outcome = this.checkedOutcome(await this.transport.mutate(pending.operation, pending.input, signal), marker); if (!this.current(epoch)) return;
      await this.actor(signal, a); if (!this.current(epoch)) return;
      if (outcome.command_sha256) this.persist({ ...marker, command_sha256: outcome.command_sha256 });
      this.update({ outcome, fresh: false, preview: null, confirmed: false });
    } catch (e) { if (this.current(epoch)) this.update({ error: safeError(e) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async stop(confirmed: boolean) {
    if (!confirmed || this.disposed || !this.state.marker || this.state.markerError || this.state.marker.command_sha256 || this.state.outcome?.state === 'committed') return;
    const marker = this.state.marker, { epoch, signal } = this.start('stop'); this.update({ outcome: null, preview: null, confirmed: false, fresh: false });
    try {
      const a = await this.actor(signal); if (!this.current(epoch)) return; this.expectActor(a, marker);
      const outcome = this.checkedOutcome(await this.transport.close(marker, signal), marker); if (!this.current(epoch)) return;
      await this.actor(signal, a); if (!this.current(epoch)) return;
      if (outcome.command_sha256) this.persist({ ...marker, command_sha256: outcome.command_sha256 });
      this.update({ outcome });
    } catch (e) { if (this.current(epoch)) this.update({ error: safeError(e) }); }
    finally { if (this.current(epoch)) this.update({ busy: null }); }
  }
  async acknowledge() {
    if (this.disposed || this.state.busy || !this.state.marker || !this.state.outcome) return;
    const marker = this.state.marker, outcome = this.state.outcome, { epoch, signal } = this.start('acknowledge');
    try {
      const a = await this.actor(signal); if (!this.current(epoch)) return; this.expectActor(a, marker); this.checkedOutcome(outcome, marker);
      this.persist(null); this.pending = null; this.update({ outcome: null, preview: null, confirmed: false, fresh: false, busy: null }); await this.refresh();
    } catch (e) { if (this.current(epoch)) this.update({ error: safeError(e), busy: null }); }
  }
  get canRetry() { return !!this.pending && !!this.state.marker && !this.state.outcome && !this.state.busy; }
}
