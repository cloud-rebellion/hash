import { writable } from 'svelte/store';

export type SMTPMode = 'unconfigured' | 'installation_legacy' | 'configured' | 'disabled';
export type SMTPConnection = '' | 'starttls' | 'tls';
export type SMTPAuthentication = '' | 'keep' | 'replace' | 'relay';
export interface WorkspaceSMTP {
  schema_version: 1; revision: number; mode: SMTPMode; configured: boolean;
  host: string; port: 0 | 587 | 465; tls_mode: SMTPConnection;
  sender_name: string; sender_email: string; username_set: boolean; password_set: boolean; updated_at: string | null;
}
export interface SMTPDraft { host: string; connection: SMTPConnection; sender_name: string; sender_email: string }
export type SMTPField = keyof SMTPDraft | 'authentication' | 'username' | 'password';
export type SMTPSaveInput = {
  expected_revision: number; host: string; port: 587 | 465; tls_mode: 'starttls' | 'tls'; sender_name: string; sender_email: string;
} & ({ credentials_action: 'keep' } | { credentials_action: 'replace'; username: string; password: string });
export interface SMTPTestReceipt { delivery_id: string; status: 'pending' | 'retrying' | 'sent' | 'failed'; smtp_accepted: boolean; inbox_delivery_confirmed: false }
export interface WorkspaceSMTPPorts {
  load(signal: AbortSignal): Promise<WorkspaceSMTP>;
  save(input: SMTPSaveInput, signal: AbortSignal): Promise<WorkspaceSMTP>;
  disable(revision: number, signal: AbortSignal): Promise<WorkspaceSMTP>;
  test(revision: number, signal: AbortSignal): Promise<SMTPTestReceipt>;
  status(id: string, signal: AbortSignal): Promise<SMTPTestReceipt>;
}
export interface SMTPState {
  metadata: WorkspaceSMTP | null; draft: SMTPDraft; authentication: SMTPAuthentication;
  usernameEntered: boolean; passwordEntered: boolean; credentialEpoch: number;
  authorized: boolean; dirty: boolean; busy: 'loading' | 'saving' | 'disabling' | 'testing' | null;
  error: string | null; notice: string | null; conflict: boolean; outcomeUnknown: boolean; disablePrompt: boolean;
  testReceipt: (SMTPTestReceipt & { revision: number }) | null; testError: string | null; testUnknown: boolean; polling: boolean;
}
export const smtpBytes = (value: string) => new TextEncoder().encode(value).byteLength;
const control = (value: string) => /[\u0000-\u001f\u007f]/.test(value);
export const normalizedSMTPHost = (value: string) => value.trim().toLowerCase();
export function sameSMTPEndpoint(draft: SMTPDraft, saved: WorkspaceSMTP | null): boolean {
  return !!saved?.configured && normalizedSMTPHost(draft.host) === saved.host && draft.connection === saved.tls_mode
    && (draft.connection === 'starttls' ? 587 : draft.connection === 'tls' ? 465 : 0) === saved.port;
}
const fields = (saved: WorkspaceSMTP | null): SMTPDraft => ({ host: saved?.host ?? '', connection: saved?.tls_mode ?? '', sender_name: saved?.sender_name ?? '', sender_email: saved?.sender_email ?? '' });
export function smtpDraftProblems(draft: SMTPDraft, authentication: SMTPAuthentication, saved: WorkspaceSMTP | null, username = '', password = ''): Partial<Record<SMTPField, string>> {
  const errors: Partial<Record<SMTPField, string>> = {}; const host = normalizedSMTPHost(draft.host);
  if (!host || smtpBytes(host) > 253 || control(host) || /[\s/\\?#@\[\]]/.test(host)
      || !(host.includes(':') ? /^[a-f0-9:.]+$/.test(host) && (host.match(/:/g)?.length ?? 0) >= 2 : /^[a-z0-9.-]+$/.test(host))) errors.host = 'Enter an SMTP hostname or IP address without a URL or port.';
  if (draft.connection !== 'starttls' && draft.connection !== 'tls') errors.connection = 'Choose STARTTLS on port 587 or TLS on port 465.';
  if (!draft.sender_name.trim() || smtpBytes(draft.sender_name.trim()) > 200 || control(draft.sender_name)) errors.sender_name = 'Enter a sender name of up to 200 bytes, on one line.';
  const email = draft.sender_email.trim();
  if (!/^[^\s<>@]+@[^\s<>@]+$/.test(email) || smtpBytes(email) > 254 || control(email)) errors.sender_email = 'Enter a sender email address without a display name.';
  if (authentication === 'keep') {
    if (!sameSMTPEndpoint(draft, saved)) errors.authentication = 'The server changed. Enter credentials again or explicitly choose an unauthenticated TLS relay.';
  } else if (authentication === 'replace') {
    if (!username || smtpBytes(username) > 256 || control(username)) errors.username = 'Enter a new SMTP username of up to 256 bytes.';
    if (!password || smtpBytes(password) > 4096 || control(password)) errors.password = 'Enter a new SMTP password of up to 4096 bytes.';
  } else if (authentication !== 'relay') errors.authentication = 'Choose saved credentials, new credentials or an unauthenticated TLS relay.';
  return errors;
}
class SMTPTimeout extends Error {}
function statusOf(error: unknown) { return typeof error === 'object' && error !== null && 'status' in error ? Number(error.status) : 0; }
const rejected = (error: unknown) => [400, 401, 403, 409, 429].includes(statusOf(error));
function safeMessage(error: unknown, operation: SMTPState['busy']) {
  const status = statusOf(error);
  if (status === 401) return 'Your session has expired. Please sign in again.';
  if (status === 403) return 'Only workspace owners can manage delivery.';
  if (status === 409) return 'Delivery settings changed in another session. Reload the latest revision before continuing.';
  if (status === 400) return 'Check the delivery fields and try again.';
  if (status === 429) return 'A test is already pending, or the workspace test limit was reached. Wait before sending another.';
  if (operation === 'loading') return 'Delivery settings could not be loaded. Try again.';
  if (operation === 'testing') return 'The test request could not be confirmed. It may still send; this page will not submit it again automatically.';
  return 'The change could not be confirmed. Reload the latest revision before trying again.';
}

// New credentials stay only in this owner closure. The observable store never
// contains their values, and clearing also remounts the masked input elements.
export function createWorkspaceSMTPController(ports: WorkspaceSMTPPorts, options: { requestTimeoutMs?: number; pollIntervalMs?: number; pollAttempts?: number; pollWindowMs?: number } = {}) {
  const timeout = options.requestTimeoutMs ?? 15_000, interval = options.pollIntervalMs ?? 2_000, attempts = options.pollAttempts ?? 20, windowMs = options.pollWindowMs ?? 60_000;
  if (![timeout, interval, attempts, windowMs].every(Number.isSafeInteger) || timeout < 1 || timeout > 30_000 || interval < 1 || interval > 5_000 || attempts < 1 || attempts > 20 || windowMs < 1 || windowMs > 60_000) throw new RangeError('Invalid delivery request bounds');
  let state: SMTPState = { metadata: null, draft: fields(null), authentication: '', usernameEntered: false, passwordEntered: false, credentialEpoch: 0, authorized: false, dirty: false, busy: null, error: null, notice: null, conflict: false, outcomeUnknown: false, disablePrompt: false, testReceipt: null, testError: null, testUnknown: false, polling: false };
  const store = writable(state); let username = '', password = '', disposed = false, sequence = 0, pollingSequence = 0;
  let requestController: AbortController | null = null, pollController: AbortController | null = null;
  function publish(patch: Partial<SMTPState>) { if (!disposed) { state = { ...state, ...patch }; store.set(state); } }
  function clearCredentials() { username = ''; password = ''; publish({ usernameEntered: false, passwordEntered: false, credentialEpoch: state.credentialEpoch + 1 }); }
  function dirty() { const baseline = fields(state.metadata); return (Object.keys(baseline) as (keyof SMTPDraft)[]).some(key => baseline[key] !== state.draft[key]) || state.authentication !== (state.metadata?.configured ? 'keep' : '') || username !== '' || password !== ''; }
  function stopPolling(clear = false) { pollingSequence++; pollController?.abort(); pollController = null; publish({ polling: false, ...(clear ? { testReceipt: null, testError: null } : {}) }); }
  async function bounded<T>(controller: AbortController, operation: (signal: AbortSignal) => Promise<T>, limit = timeout): Promise<T> {
    if (controller.signal.aborted) throw new SMTPTimeout();
    let timer: ReturnType<typeof setTimeout> | undefined; let onAbort = () => {};
    const stopped = new Promise<never>((_, reject) => { onAbort = () => reject(new SMTPTimeout()); controller.signal.addEventListener('abort', onAbort, { once: true }); timer = setTimeout(() => controller.abort(), limit); });
    try { return await Promise.race([operation(controller.signal), stopped]); }
    finally { clearTimeout(timer); controller.signal.removeEventListener('abort', onAbort); }
  }
  async function run(operation: NonNullable<SMTPState['busy']>, work: (signal: AbortSignal) => Promise<void>): Promise<boolean> {
    if (disposed || state.busy) return false;
    const id = ++sequence, controller = new AbortController(); requestController = controller;
    publish({ busy: operation, error: null, notice: null });
    try { await bounded(controller, work); return !disposed && id === sequence; }
    catch (error) {
      if (!disposed && id === sequence) {
        const unauthorized = [401, 403].includes(statusOf(error));
        publish({ error: safeMessage(error, operation), authorized: unauthorized ? false : state.authorized,
          conflict: statusOf(error) === 409 || state.conflict,
          outcomeUnknown: operation !== 'loading' && !rejected(error) || state.outcomeUnknown,
          ...(operation === 'testing' && !rejected(error) ? { testUnknown: true } : {}) });
        if (unauthorized) { clearCredentials(); stopPolling(); }
      }
      return false;
    } finally { if (!disposed && id === sequence) { if (operation !== 'loading') clearCredentials(); requestController = null; publish({ busy: null }); } }
  }
  async function load(discard = false) {
    if (disposed || state.busy || state.dirty && !discard) return false; stopPolling(true); clearCredentials();
    return run('loading', async signal => {
      const saved = await ports.load(signal); if (disposed || signal.aborted) return;
      publish({ metadata: saved, draft: fields(saved), authentication: saved.configured ? 'keep' : '', dirty: false, authorized: true, conflict: false, outcomeUnknown: false, disablePrompt: false });
    });
  }
  function edit(field: keyof SMTPDraft, value: string) {
    if (disposed || state.busy || !state.authorized) return false;
    if (field === 'connection' && !['', 'starttls', 'tls'].includes(value)) return false;
    if (field === 'host' || field === 'connection') clearCredentials();
    publish({ draft: { ...state.draft, [field]: value }, notice: null, disablePrompt: false }); publish({ dirty: dirty() }); return true;
  }
  function authenticate(value: SMTPAuthentication) {
    if (disposed || state.busy || !state.authorized || !['', 'keep', 'replace', 'relay'].includes(value)) return false;
    clearCredentials(); publish({ authentication: value, notice: null }); publish({ dirty: dirty() }); return true;
  }
  function credential(field: 'username' | 'password', value: string) {
    if (disposed || state.busy || !state.authorized || state.authentication !== 'replace') return false;
    if (field === 'username') username = value; else password = value;
    publish({ usernameEntered: username !== '', passwordEntered: password !== '', dirty: dirty(), notice: null }); return true;
  }
  function problems() { return smtpDraftProblems(state.draft, state.authentication, state.metadata, username, password); }
  function cancel() { if (disposed || state.busy || !state.metadata) return false; clearCredentials(); publish({ draft: fields(state.metadata), authentication: state.metadata.configured ? 'keep' : '', dirty: false, disablePrompt: false, notice: null, error: state.conflict || state.outcomeUnknown ? state.error : null }); return true; }
  const canMutate = () => state.authorized && state.metadata !== null && !state.conflict && !state.outcomeUnknown && !state.busy;
  async function save() {
    if (!canMutate() || !state.dirty) return false;
    const invalid = Object.values(problems())[0]; if (invalid) { publish({ error: invalid }); return false; }
    const saved = state.metadata!, input = { expected_revision: saved.revision, host: normalizedSMTPHost(state.draft.host), port: state.draft.connection === 'starttls' ? 587 : 465, tls_mode: state.draft.connection, sender_name: state.draft.sender_name.trim(), sender_email: state.draft.sender_email.trim(),
      ...(state.authentication === 'keep' ? { credentials_action: 'keep' } : { credentials_action: 'replace', username: state.authentication === 'relay' ? '' : username, password: state.authentication === 'relay' ? '' : password }) } as SMTPSaveInput;
    stopPolling(true);
    return run('saving', async signal => {
      const result = await ports.save(input, signal); if (disposed || signal.aborted) return;
      const authenticated = input.credentials_action === 'keep' ? saved.username_set : input.username !== '';
      if (result.mode !== 'configured' || !result.configured || result.revision !== saved.revision + 1 || result.host !== input.host || result.port !== input.port || result.tls_mode !== input.tls_mode || result.sender_name !== input.sender_name || result.sender_email !== input.sender_email || result.username_set !== authenticated || result.password_set !== authenticated) throw new Error('Unbound delivery save');
      publish({ metadata: result, draft: fields(result), authentication: 'keep', dirty: false, notice: 'Delivery settings saved. The SMTP connection has not been tested.' });
    });
  }
  function requestDisable() { if (!canMutate() || !['configured', 'installation_legacy'].includes(state.metadata!.mode)) return false; publish({ disablePrompt: true, error: null }); return true; }
  function cancelDisable() { if (disposed || state.busy) return false; publish({ disablePrompt: false }); return true; }
  async function disable() {
    if (!canMutate() || !state.disablePrompt) return false; const revision = state.metadata!.revision; stopPolling(true);
    return run('disabling', async signal => { const result = await ports.disable(revision, signal); if (disposed || signal.aborted) return;
      if (result.mode !== 'disabled' || result.configured || result.revision !== revision + 1) throw new Error('Unbound delivery disable');
      publish({ metadata: result, draft: fields(result), authentication: '', dirty: false, disablePrompt: false, notice: 'Workspace delivery disabled. No installation fallback was enabled.' });
    });
  }
  async function monitor() {
    if (disposed || !state.authorized || !state.testReceipt || state.polling || ['sent', 'failed'].includes(state.testReceipt.status)) return false;
    const selected = state.testReceipt, id = ++pollingSequence, controller = new AbortController(); pollController = controller; const end = Date.now() + windowMs;
    const current = () => !disposed && id === pollingSequence && !controller.signal.aborted && state.metadata?.revision === selected.revision;
    publish({ polling: true, testError: null });
    try {
      for (let attempt = 0; attempt < attempts && Date.now() < end; attempt++) {
        const result = await bounded(controller, signal => ports.status(selected.delivery_id, signal), Math.max(1, Math.min(timeout, end - Date.now())));
        if (!current()) return false;
        if (result.delivery_id !== selected.delivery_id) throw new Error('Unbound test status');
        publish({ testReceipt: { ...result, revision: selected.revision } });
        if (result.status === 'sent' || result.status === 'failed') return true;
        if (attempt + 1 < attempts && Date.now() < end) await new Promise<void>(resolve => {
          const finish = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', finish); resolve(); };
          const timer = setTimeout(finish, Math.min(interval, Math.max(1, end - Date.now()))); controller.signal.addEventListener('abort', finish, { once: true });
        });
      }
      if (current()) publish({ testError: 'Monitoring paused. The message may still be queued; check its status without sending another test.' });
    } catch (error) {
      if (!disposed && id === pollingSequence) { const unauthorized = [401, 403].includes(statusOf(error)); if (unauthorized) { clearCredentials(); publish({ authorized: false }); }
        publish({ testError: unauthorized ? safeMessage(error, 'loading') : 'Test status could not be confirmed. Check again without sending another test.' }); }
    } finally { if (!disposed && id === pollingSequence) { pollController = null; publish({ polling: false }); } }
    return false;
  }
  async function test() {
    if (!canMutate() || !state.metadata!.configured || state.dirty || state.testUnknown || state.testReceipt && ['pending', 'retrying'].includes(state.testReceipt.status)) return false;
    const revision = state.metadata!.revision; stopPolling(true);
    const ok = await run('testing', async signal => { const result = await ports.test(revision, signal); if (disposed || signal.aborted) return;
      if (result.status !== 'pending' || result.smtp_accepted || result.inbox_delivery_confirmed) throw new Error('Unbound test request');
      publish({ testReceipt: { ...result, revision }, testError: null });
    });
    if (ok) void monitor(); return ok;
  }
  function dispose() { if (disposed) return; clearCredentials(); stopPolling(); disposed = true; sequence++; requestController?.abort(); requestController = null; }
  return { subscribe: store.subscribe, load, edit, authenticate, credential, problems, cancel, save, requestDisable, cancelDisable, disable, test, monitor, dispose };
}
export type WorkspaceSMTPController = ReturnType<typeof createWorkspaceSMTPController>;
