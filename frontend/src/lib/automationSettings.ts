import { writable } from 'svelte/store';

export type ReminderMode = 'inherit' | 'legacy' | 'disabled' | 'interval';
export interface ReminderSelection { mode: ReminderMode; interval_days: number; max_fires: number }
export interface ReminderPolicy extends ReminderSelection { offsets_days: number[] }
export interface ReminderSnapshot {
  scope: 'template' | 'document'; id: string; revision: number; updated_at: string | null;
  selection: ReminderSelection; effective_policy: ReminderPolicy;
  source: 'legacy' | 'template' | 'document' | 'frozen'; editable: boolean; frozen: boolean;
}
export interface AutomationPreferenceDraft { notify_viewed: boolean; notify_signed: boolean }
export interface AutomationPreferences extends AutomationPreferenceDraft {
  schema_version: 1; revision: number; viewed_scope: 'first_view_per_recipient_per_send'; updated_at: string | null;
}
export interface SavedAutomationState<T, D> {
  saved: T | null; draft: D; busy: 'loading' | 'saving' | null; dirty: boolean;
  unconfirmed: boolean; authorized: boolean; error: string | null; notice: string | null;
}
export function reminderSelection(mode: ReminderMode, days = 1, count = 1): ReminderSelection {
  return { mode, interval_days: mode === 'interval' ? days : 0, max_fires: mode === 'legacy' ? 2 : mode === 'interval' ? count : 0 };
}
export function validReminderSelection(value: ReminderSelection, scope: 'template' | 'document'): boolean {
  if (value.mode === 'inherit') return scope === 'document' && value.interval_days === 0 && value.max_fires === 0;
  if (value.mode === 'legacy') return value.interval_days === 0 && value.max_fires === 2;
  if (value.mode === 'disabled') return value.interval_days === 0 && value.max_fires === 0;
  return value.mode === 'interval' && Number.isSafeInteger(value.interval_days) && value.interval_days >= 1 && value.interval_days <= 365
    && Number.isSafeInteger(value.max_fires) && value.max_fires >= 1 && value.max_fires <= 365 && value.interval_days * value.max_fires <= 365;
}

// One finite request owner shared by these two closed settings forms. A hung
// fetch cannot leave controls busy forever; late writes cannot publish success.
function savedForm<T extends { revision: number }, D extends object>(ports: {
  load(signal: AbortSignal): Promise<T>; save(saved: T, draft: D, signal: AbortSignal): Promise<T>;
}, initial: D, fields: (saved: T) => D, valid: (draft: D) => boolean, editable: (saved: T) => boolean, timeoutMs: number) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new RangeError('Invalid request deadline');
  let state: SavedAutomationState<T, D> = { saved: null, draft: { ...initial }, busy: null, dirty: false, unconfirmed: false, authorized: false, error: null, notice: null };
  const store = writable(state); let sequence = 0, disposed = false;
  let active: AbortController | null = null, releaseRequest: (() => void) | null = null;
  const same = (a: D, b: D) => Object.keys(initial).every(key => a[key as keyof D] === b[key as keyof D]);
  const publish = (patch: Partial<typeof state>) => { state = { ...state, ...patch }; store.set(state); };
  function begin(busy: 'loading' | 'saving') {
    if (disposed || state.busy) return null;
    const id = ++sequence, controller = new AbortController(); active = controller;
    let reject!: (error: Error) => void;
    const aborted = new Promise<never>((_resolve, fail) => { reject = fail; });
    const abort = () => reject(new Error('Request deadline or cancellation'));
    controller.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    releaseRequest = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', abort); };
    publish({ busy, error: null, notice: null });
    return { id, signal: controller.signal, wait: <V>(promise: Promise<V>) => Promise.race([promise, aborted]) };
  }
  const current = (id: number) => !disposed && sequence === id;
  function finish(id: number) { if (current(id)) { releaseRequest?.(); releaseRequest = null; active = null; publish({ busy: null }); } }
  function failed(error: unknown, saving: boolean) {
    const status = Number((error as { status?: number })?.status) || 0;
    const conflict = status === 409 || status === 412;
    publish({ authorized: status === 401 || status === 403 ? false : state.authorized,
      unconfirmed: state.unconfirmed || conflict || (saving && (status === 0 || status >= 500)),
      error: status === 401 ? 'Your session has expired. Please sign in again.' : status === 403 ? 'These controls are available only to the authorized sender.'
        : conflict ? 'The saved settings changed. Reload them before saving again.' : saving && (status === 0 || status >= 500)
          ? 'Saving is unconfirmed. Reload the saved settings before another change.' : saving ? 'The settings were not saved. Check the values and try again.' : 'The settings could not be loaded. Try again.' });
  }
  async function load() {
    const request = begin('loading'); if (!request) return false;
    try {
      const saved = await request.wait(ports.load(request.signal)); if (!current(request.id)) return false;
      const draft = state.dirty ? state.draft : fields(saved), dirty = !same(draft, fields(saved));
      publish({ saved, draft, dirty, unconfirmed: false, authorized: true,
        notice: dirty ? 'The latest saved settings are loaded. Review your unsaved changes.' : null }); return true;
    } catch (error) { if (current(request.id)) failed(error, false); return false; }
    finally { finish(request.id); }
  }
  function edit(draft: D) {
    if (disposed || state.busy || state.unconfirmed || !state.authorized || !state.saved || !editable(state.saved)) return false;
    publish({ draft: { ...draft }, dirty: !same(draft, fields(state.saved)), error: null, notice: null }); return true;
  }
  function cancel() {
    if (disposed || state.busy || state.unconfirmed || !state.saved) return false;
    publish({ draft: fields(state.saved), dirty: false, error: null, notice: null }); return true;
  }
  async function save(externalBlocked = false) {
    if (disposed || state.busy || state.unconfirmed || externalBlocked || !state.authorized || !state.saved || !state.dirty || !editable(state.saved)) return false;
    if (!valid(state.draft)) { publish({ error: 'Choose a valid interval and repeat count within one year.' }); return false; }
    const before = state.saved, draft = { ...state.draft }, request = begin('saving'); if (!request) return false;
    try {
      const saved = await request.wait(ports.save(before, draft, request.signal)); if (!current(request.id)) return false;
      if (saved.revision !== before.revision + 1 || !same(fields(saved), draft)) throw new Error('Unbound saved settings');
      publish({ saved, draft: fields(saved), dirty: false, unconfirmed: false, notice: 'Settings saved.' }); return true;
    } catch (error) { if (current(request.id)) failed(error, true); return false; }
    finally { finish(request.id); }
  }
  function sourceChanged() {
    if (disposed || !state.saved || state.unconfirmed) return false;
    publish({ unconfirmed: true, error: 'The document changed. Reload the saved policy before another change.', notice: null }); return true;
  }
  function dispose() { if (disposed) return; disposed = true; sequence++; active?.abort(); releaseRequest?.(); active = null; releaseRequest = null; }
  return { subscribe: store.subscribe, load, edit, cancel, save, sourceChanged, dispose };
}
export function createAutomationPreferencesForm(ports: { load(signal: AbortSignal): Promise<AutomationPreferences>; save(saved: AutomationPreferences, draft: AutomationPreferenceDraft, signal: AbortSignal): Promise<AutomationPreferences> }, timeoutMs = 30000) {
  return savedForm(ports, { notify_viewed: false, notify_signed: false }, value => ({ notify_viewed: value.notify_viewed, notify_signed: value.notify_signed }),
    value => typeof value.notify_viewed === 'boolean' && typeof value.notify_signed === 'boolean', () => true, timeoutMs);
}
export function createReminderPolicyForm(scope: 'template' | 'document', ports: { load(signal: AbortSignal): Promise<ReminderSnapshot>; save(saved: ReminderSnapshot, draft: ReminderSelection, signal: AbortSignal): Promise<ReminderSnapshot> }, timeoutMs = 30000) {
  return savedForm(ports, reminderSelection(scope === 'document' ? 'inherit' : 'legacy'), value => ({ ...value.selection }), value => validReminderSelection(value, scope), value => value.editable && !value.frozen, timeoutMs);
}
