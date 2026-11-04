import { APIError } from './client';
import { validReminderSelection, type AutomationPreferences, type AutomationPreferenceDraft, type ReminderPolicy, type ReminderSelection, type ReminderSnapshot } from '../automationSettings';

export async function automationJSON(method: 'GET' | 'PUT', path: string, signal: AbortSignal, body?: object): Promise<unknown> {
  const response = await fetch(path, { method, signal, credentials: 'include', cache: 'no-store', redirect: 'error',
    headers: body ? { Accept: 'application/json', 'Content-Type': 'application/json' } : { Accept: 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'Automation request rejected.'); }
  const reader = response.body?.getReader(); if (!reader) throw new Error('Missing automation response');
  const chunks: Uint8Array[] = []; let length = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; length += part.value.byteLength;
    if (length > 65536) { await reader.cancel(); throw new Error('Automation response exceeds bound'); } chunks.push(part.value); } }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length); let at = 0; for (const part of chunks) { bytes.set(part, at); at += part.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
export const automationObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
export const automationRevision = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
export const automationTimestamp = (v: unknown): v is string | null => v === null || typeof v === 'string' && v.length <= 64 && Number.isFinite(Date.parse(v));
export function parseAutomationPreferences(value: unknown): AutomationPreferences {
  if (!automationObject(value) || value.schema_version !== 1 || !automationRevision(value.revision)
    || typeof value.notify_viewed !== 'boolean' || typeof value.notify_signed !== 'boolean'
    || value.revision === 0 && (value.notify_viewed || value.notify_signed)
    || value.viewed_scope !== 'first_view_per_recipient_per_send' || !automationTimestamp(value.updated_at)) throw new Error('Automation preferences contract rejected');
  return value as unknown as AutomationPreferences;
}
export async function getAutomationPreferences(signal: AbortSignal) { return parseAutomationPreferences(await automationJSON('GET', '/api/v1/automation-preferences', signal)); }
export async function putAutomationPreferences(saved: AutomationPreferences, draft: AutomationPreferenceDraft, signal: AbortSignal) {
  const value = parseAutomationPreferences(await automationJSON('PUT', '/api/v1/automation-preferences', signal, { expected_revision: saved.revision, notify_viewed: draft.notify_viewed, notify_signed: draft.notify_signed }));
  if (value.revision !== saved.revision + 1 || value.notify_viewed !== draft.notify_viewed || value.notify_signed !== draft.notify_signed) throw new Error('Saved automation preferences identity rejected');
  return value;
}

const uuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);
function reminderPolicy(value: unknown, scope: 'template' | 'document', inherit: boolean): ReminderPolicy {
  if (!automationObject(value) || typeof value.mode !== 'string' || !['legacy','disabled','interval',...(inherit ? ['inherit'] : [])].includes(value.mode)
    || !validReminderSelection(value as unknown as ReminderSelection, scope) || !Array.isArray(value.offsets_days) || value.offsets_days.length > 365) throw new Error('Reminder policy contract rejected');
  const mode = value.mode as ReminderSelection['mode'], days = value.interval_days as number, count = value.max_fires as number;
  const offsets = mode === 'legacy' ? [3,7] : mode === 'interval' ? Array.from({ length: count }, (_value, at) => days * (at+1)) : [];
  const observedOffsets = value.offsets_days;
  if (offsets.length !== observedOffsets.length || offsets.some((day, at) => day !== observedOffsets[at])) throw new Error('Reminder offsets contract rejected');
  return { mode, interval_days: days, max_fires: count, offsets_days: offsets };
}
export function parseReminderPolicy(value: unknown, scope: 'template' | 'document', id: string): ReminderSnapshot {
  if (!uuid(id) || !automationObject(value) || value.schema_version !== 1 || !automationRevision(value.revision) || !automationTimestamp(value.updated_at)) throw new Error('Reminder snapshot contract rejected');
  if (scope === 'template') {
    if (value.template_id !== id.toLowerCase()) throw new Error('Foreign template reminder policy');
    const policy = reminderPolicy(value.policy, 'template', false);
    if (value.revision === 0 && policy.mode !== 'legacy') throw new Error('Absent template default must remain legacy');
    return { scope, id: value.template_id as string, revision: value.revision, updated_at: value.updated_at, selection: { mode: policy.mode, interval_days: policy.interval_days, max_fires: policy.max_fires }, effective_policy: policy,
      source: value.revision === 0 ? 'legacy' : 'template', editable: true, frozen: false };
  }
  if (value.document_id !== id.toLowerCase() || value.updated_at === null || typeof value.editable !== 'boolean' || typeof value.frozen !== 'boolean'
    || !['legacy','template','document','frozen'].includes(value.source as string) || value.frozen && value.editable || value.source === 'frozen' && !value.frozen) throw new Error('Document reminder snapshot contract rejected');
  const selection = reminderPolicy(value.selection, 'document', true), effective = reminderPolicy(value.effective_policy, 'document', false);
  return { scope, id: value.document_id as string, revision: value.revision, updated_at: value.updated_at,
    selection: { mode: selection.mode, interval_days: selection.interval_days, max_fires: selection.max_fires }, effective_policy: effective,
    source: value.source as ReminderSnapshot['source'], editable: value.editable, frozen: value.frozen };
}
function reminderPath(scope: 'template' | 'document', id: string) {
  if (!uuid(id)) throw new Error('Invalid reminder resource');
  return `/api/v1/${scope === 'template' ? 'templates' : 'documents'}/${encodeURIComponent(id)}/reminder-policy`;
}
export async function getReminderPolicy(scope: 'template' | 'document', id: string, signal: AbortSignal): Promise<ReminderSnapshot> {
  return parseReminderPolicy(await automationJSON('GET', reminderPath(scope,id), signal), scope,id);
}
export async function putReminderPolicy(saved: ReminderSnapshot, draft: ReminderSelection, signal: AbortSignal): Promise<ReminderSnapshot> {
  if (!saved.editable || saved.frozen || !validReminderSelection(draft, saved.scope) || saved.scope === 'document' && !saved.updated_at) throw new Error('Reminder mutation unavailable');
  const result = parseReminderPolicy(await automationJSON('PUT', reminderPath(saved.scope,saved.id), signal,
    { expected_revision: saved.revision, ...(saved.scope === 'document' ? { expected_updated_at: saved.updated_at } : {}), mode: draft.mode, interval_days: draft.interval_days, max_fires: draft.max_fires }), saved.scope,saved.id);
  if (result.revision !== saved.revision+1 || result.selection.mode !== draft.mode || result.selection.interval_days !== draft.interval_days || result.selection.max_fires !== draft.max_fires) throw new Error('Saved reminder policy identity rejected');
  return result;
}
