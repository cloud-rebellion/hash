import { writable } from 'svelte/store';
import { emailDesignProblem } from './emailDesign';
import type { WorkspaceSMTP, SMTPTestReceipt } from './workspaceSMTP';

export const emailTemplateKinds = [
  'email.invite', 'email.reminder', 'email.completed_signer', 'email.completed_sender',
  'email.declined', 'email.changes_requested', 'email.new_comment', 'email.voided', 'email.quota_warning_80',
] as const;
export type EmailTemplateKind = typeof emailTemplateKinds[number];
export const editableEmailTemplateKinds: readonly EmailTemplateKind[] = [
  'email.invite', 'email.reminder', 'email.completed_signer', 'email.completed_sender', 'email.changes_requested', 'email.new_comment',
  'email.declined', 'email.quota_warning_80',
];
export interface EmailTemplateFields {
  subject_template: string;
  html_template: string;
  text_template: string;
  design_json?: string;
}
export interface EmailTemplate extends EmailTemplateFields {
  kind: EmailTemplateKind;
  revision: number;
  editable: boolean;
  updated_at?: string | null;
  variables: string[];
  mandatory_content: 'appended_by_hash';
}
export interface EmailTemplateCatalog {
  schema_version: 1;
  templates: EmailTemplate[];
  limits: { subject_bytes: number; html_bytes: number; text_bytes: number; design_bytes?: number };
  preview_synthetic: true;
}
export interface EmailTemplatePreview {
  locale: WorkspaceEmailLocale;
  schema_version: 1;
  synthetic: true;
  revision: number;
  subject: string;
  html: string;
  text: string;
  mandatory_content_preserved: true;
}
export interface EmailDesignProposal {
  schema_version: 1; kind: EmailTemplateKind; expected_revision: number; input: EmailTemplateInput;
  preview: EmailTemplatePreview; saved: false;
}
export type EmailTemplateInput = EmailTemplateFields & { expected_revision: number };
export type EmailTemplatePreviewInput = EmailTemplateInput & { preview_locale?: WorkspaceEmailLocale };
export interface EmailTemplateEditorPorts {
  propose?: (kind: EmailTemplateKind, input: EmailTemplatePreviewInput, prompt: string, signal: AbortSignal) => Promise<EmailDesignProposal>;
  load: (signal: AbortSignal) => Promise<EmailTemplateCatalog>;
  save: (kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal) => Promise<EmailTemplate>;
  preview: (kind: EmailTemplateKind, input: EmailTemplatePreviewInput, signal: AbortSignal) => Promise<EmailTemplatePreview>;
}
export type EmailField = keyof EmailTemplateFields;
export interface EmailEditorState {
  catalog: EmailTemplateCatalog | null;
  selected: EmailTemplate | null;
  draft: EmailTemplateFields;
  busy: 'loading' | 'saving' | 'previewing' | 'proposing' | null;
  error: string | null;
  notice: string | null;
  conflict: boolean;
  dirty: boolean;
  preview: EmailTemplatePreview | null;
  previewOutdated: boolean;
  previewLocale?: WorkspaceEmailLocale;
  authorized: boolean;
  proposal: EmailDesignProposal | null;
}
const emptyFields = (): EmailTemplateFields => ({ subject_template: '', html_template: '', text_template: '' });
export function emailTemplateFields(value: EmailTemplateFields): EmailTemplateFields {
  return { subject_template: value.subject_template, html_template: value.html_template, text_template: value.text_template, ...(value.design_json === undefined ? {} : { design_json: value.design_json }) };
}
function sameFields(a: EmailTemplateFields, b: EmailTemplateFields) {
  return a.subject_template === b.subject_template && a.html_template === b.html_template && a.text_template === b.text_template && (a.design_json ?? '') === (b.design_json ?? '');
}
export function canEditEmailTemplate(value: EmailTemplate | null): boolean {
  return value?.editable === true && editableEmailTemplateKinds.includes(value.kind);
}
export function isBuiltInEmailTemplate(value: EmailTemplateFields & { revision: number }): boolean {
  return value.revision === 0 && value.subject_template === '' && value.html_template === '' && value.text_template === '' && !value.design_json;
}
export function emailFieldBytes(value: string) { return new TextEncoder().encode(value).byteLength; }
export function emailDraftProblems(draft: EmailTemplateFields, limits: EmailTemplateCatalog['limits']): Partial<Record<EmailField, string>> {
  const errors: Partial<Record<EmailField, string>> = {};
  if (emailFieldBytes(draft.subject_template) > limits.subject_bytes) errors.subject_template = 'The subject is too long.';
  if (/[\r\n]/.test(draft.subject_template)) errors.subject_template = 'The subject must be one line.';
  if (emailFieldBytes(draft.html_template) > limits.html_bytes) errors.html_template = 'The HTML content is too long.';
  if (emailFieldBytes(draft.text_template) > limits.text_bytes) errors.text_template = 'The plain text content is too long.';
  const designProblem = emailDesignProblem(draft.design_json);
  if (designProblem) errors.design_json = designProblem;
  return errors;
}
class EmailRequestTimeout extends Error {}
function safeFailure(error: unknown, operation: 'loading' | 'saving' | 'previewing' | 'proposing') {
  if (error instanceof EmailRequestTimeout) {
    if (operation === 'saving') return 'Saving timed out. Reload the latest revision to check whether it was saved.';
    if (operation === 'previewing') return 'The preview timed out. Your draft is unchanged.';
    if (operation === 'proposing') return 'The design proposal timed out. Your draft is unchanged.';
    return 'Email templates took too long to load. Try again.';
  }
  const status = typeof error === 'object' && error !== null && 'status' in error ? Number(error.status) : 0;
  if (status === 401) return 'Your session has expired. Please sign in again.';
  if (status === 403) return 'Only workspace owners can manage email templates.';
  if (status === 409) return 'This template changed in another session. Reload the latest revision before continuing.';
  if (status === 412) return 'Configure an enabled workspace AI provider in Settings before requesting a design proposal.';
  if (operation === 'proposing') return 'The design proposal could not be generated. Your draft is unchanged.';
  if (status === 400) return 'Check the content, design, logo and variables, then try again.';
  if (operation === 'saving' && (status === 0 || status >= 500)) return 'Could not confirm whether the template was saved. Reload the latest revision before another save.';
  if (operation === 'loading') return 'Email templates could not be loaded. Try again.';
  if (operation === 'previewing') return 'The preview could not be generated. Your draft is unchanged.';
  return 'The template could not be saved. Your draft is unchanged.';
}

// The component uses these same callbacks. One owner spans each complete request;
// disposal/late responses cannot change a newer page or report false success.
export function createEmailTemplateEditor(ports: EmailTemplateEditorPorts, options: { requestTimeoutMs?: number } = {}) {
  const deadlineMs = options.requestTimeoutMs ?? 30_000;
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 30_000) throw new RangeError('Invalid request deadline');
  let state: EmailEditorState = {
    catalog: null, selected: null, draft: emptyFields(), busy: null, error: null, notice: null,
    conflict: false, dirty: false, preview: null, previewOutdated: false, authorized: false, proposal: null,
  };
  const store = writable(state);
  let disposed = false;
  let sequence = 0;
  let controller: AbortController | null = null;
  let cleanupRequest: (() => void) | null = null;
  function publish(patch: Partial<EmailEditorState>) { state = { ...state, ...patch }; store.set(state); }
  function start(kind: NonNullable<EmailEditorState['busy']>) {
    if (disposed || state.busy) return null;
    const operation = ++sequence;
    const ownedController = new AbortController(); controller = ownedController;
    let timedOut = false;
    let rejectAbort!: (reason: Error) => void;
    const aborted = new Promise<never>((_resolve, reject) => { rejectAbort = reject; });
    const onAbort = () => rejectAbort(timedOut ? new EmailRequestTimeout() : new Error('Request cancelled'));
    ownedController.signal.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { timedOut = true; ownedController.abort(); }, deadlineMs);
    cleanupRequest = () => { clearTimeout(timer); ownedController.signal.removeEventListener('abort', onAbort); };
    publish({ busy: kind, error: null, notice: null, proposal: null });
    return { operation, signal: ownedController.signal, wait: <T>(promise: Promise<T>) => Promise.race([promise, aborted]) };
  }
  function current(operation: number) { return !disposed && operation === sequence; }
  function finish(operation: number) { if (current(operation)) { cleanupRequest?.(); cleanupRequest = null; controller = null; publish({ busy: null }); } }
  function failure(error: unknown, operation: 'loading' | 'saving' | 'previewing' | 'proposing') {
    const status = (error as {status?: number})?.status;
    publish({ error: safeFailure(error, operation), conflict: status === 409 || (operation === 'saving' && (error instanceof EmailRequestTimeout || !status || status >= 500)) || state.conflict,
      authorized: status === 401 || status === 403 ? false : state.authorized,
      previewOutdated: state.preview !== null, proposal: null });
  }
  function input(): EmailTemplateInput | null {
    if (!state.selected || !state.catalog || !state.authorized || state.conflict) return null;
    if (!canEditEmailTemplate(state.selected) && (!isBuiltInEmailTemplate(state.selected) || !sameFields(state.draft, state.selected))) {
      publish({ error: 'This message uses built-in content. Customization is unavailable.' }); return null;
    }
    const problems = Object.values(emailDraftProblems(state.draft, state.catalog.limits));
    if (problems.length) { publish({ error: problems[0]! }); return null; }
    return { ...emailTemplateFields(state.draft), expected_revision: state.selected.revision };
  }
  async function load() {
    const request = start('loading'); if (!request) return false;
    const selectedKind = state.selected?.kind;
    try {
      const catalog = await request.wait(ports.load(request.signal));
      if (!current(request.operation)) return false;
      const selected = catalog.templates.find(item => item.kind === selectedKind) ?? catalog.templates[0] ?? null;
      publish({ catalog, selected, draft: selected ? emailTemplateFields(selected) : emptyFields(), dirty: false,
        conflict: false, preview: null, previewOutdated: false, proposal: null, authorized: true });
      return true;
    } catch (error) {
      if (current(request.operation)) failure(error, 'loading');
      return false;
    } finally { finish(request.operation); }
  }
  function select(kind: EmailTemplateKind) {
    if (disposed || state.busy || state.dirty || !state.authorized || state.selected?.kind === kind) return false;
    const selected = state.catalog?.templates.find(item => item.kind === kind); if (!selected) return false;
    publish({ selected, draft: emailTemplateFields(selected), error: null, notice: null, conflict: false,
      dirty: false, preview: null, previewOutdated: false, proposal: null });
    return true;
  }
  function edit(field: EmailField, value: string) {
    if (disposed || state.busy || !state.selected || !state.authorized || !canEditEmailTemplate(state.selected)) return false;
    const draft = { ...state.draft, [field]: value };
    publish({ draft, dirty: !sameFields(draft, state.selected), error: state.conflict ? state.error : null, notice: null,
      previewOutdated: state.preview !== null, proposal: null });
    return true;
  }
  function cancel() {
    if (disposed || state.busy || !state.selected) return false;
    publish({ draft: emailTemplateFields(state.selected), dirty: false, notice: null, error: state.conflict ? state.error : null,
      preview: null, previewOutdated: false, proposal: null });
    return true;
  }
  function setPreviewLocale(value: WorkspaceEmailLocale | undefined) {
    if (disposed || (value !== undefined && !isWorkspaceEmailLocale(value)) || state.previewLocale === value || state.busy === 'saving' || state.busy === 'loading') return false;
    sequence++; controller?.abort(); cleanupRequest?.(); cleanupRequest = null; controller = null;
    publish({ previewLocale: value, preview: null, previewOutdated: false, proposal: null, busy: null, error: null, notice: null });
    return true;
  }
  function previewInput(draft: EmailTemplateInput): EmailTemplatePreviewInput {
    return { ...draft, ...(state.previewLocale === undefined ? {} : { preview_locale: state.previewLocale }) };
  }
  async function preview() {
    if (disposed || state.busy) return false;
    const source = input(); const selected = state.selected; if (!source || !selected) return false;
    const draft = previewInput(source);
    const request = start('previewing'); if (!request) return false;
    try {
      const result = await request.wait(ports.preview(selected.kind, draft, request.signal));
      if (!current(request.operation)) return false;
      if (result.revision !== draft.expected_revision || !result.synthetic || !result.mandatory_content_preserved || !emailPreviewLocale(selected.kind, result.locale, draft.preview_locale)) {
        throw new Error('Unbound preview');
      }
      publish({ preview: result, previewOutdated: false });
      return true;
    } catch (error) {
      if (current(request.operation)) failure(error, 'previewing');
      return false;
    } finally { finish(request.operation); }
  }
  async function save() {
    if (disposed || state.busy || state.proposal || !state.dirty || !canEditEmailTemplate(state.selected)) return false;
    const draft = input(); const selected = state.selected; if (!draft || !selected) return false;
    const request = start('saving'); if (!request) return false;
    try {
      const result = await request.wait(ports.save(selected.kind, draft, request.signal));
      if (!current(request.operation)) return false;
      if (result.kind !== selected.kind || result.revision <= draft.expected_revision || !canEditEmailTemplate(result)) throw new Error('Unbound saved revision');
      const catalog = state.catalog!;
      publish({ catalog: { ...catalog, templates: catalog.templates.map(item => item.kind === result.kind ? result : item) },
        selected: result, draft: emailTemplateFields(result), dirty: false, conflict: false, preview: null, previewOutdated: false,
        notice: 'Template saved. Already queued emails are unchanged.' });
      return true;
    } catch (error) {
      if (current(request.operation)) failure(error, 'saving');
      return false;
    } finally { finish(request.operation); }
  }
  async function propose(prompt: string) {
    if (disposed || state.busy || !ports.propose || !canEditEmailTemplate(state.selected) || !prompt.trim() || emailFieldBytes(prompt) > 4096) return false;
    const source = input(); const selected = state.selected; if (!source || !selected) return false;
    const draft = previewInput(source);
    const request = start('proposing'); if (!request) return false;
    try {
      const result = await request.wait(ports.propose(selected.kind, draft, prompt, request.signal));
      if (!current(request.operation)) return false;
      if (result.schema_version !== 1 || result.saved !== false || result.kind !== selected.kind || result.expected_revision !== selected.revision
          || result.input.expected_revision !== selected.revision || result.preview.revision !== selected.revision
          || !result.preview.synthetic || !result.preview.mandatory_content_preserved || !emailPreviewLocale(selected.kind, result.preview.locale, draft.preview_locale)
          || Object.keys(result.input).some(key => !['expected_revision', 'subject_template', 'html_template', 'text_template', 'design_json'].includes(key))
          || Object.keys(emailDraftProblems(result.input, state.catalog!.limits)).length) throw new Error('Unbound design proposal');
      publish({ proposal: result });
      return true;
    } catch (error) {
      if (current(request.operation)) failure(error, 'proposing');
      return false;
    } finally { finish(request.operation); }
  }
  function acceptProposal() {
    const proposal = state.proposal;
    if (disposed || state.busy || !state.authorized || state.conflict || !canEditEmailTemplate(state.selected)
        || !proposal || proposal.kind !== state.selected?.kind || proposal.expected_revision !== state.selected.revision) return false;
    const draft = emailTemplateFields(proposal.input);
    publish({ draft, dirty: !sameFields(draft, state.selected), preview: proposal.preview, previewOutdated: false, proposal: null,
      notice: 'AI proposal added to your unsaved draft. Review it and save when ready.' });
    return true;
  }
  function discardProposal() { if (!disposed && !state.busy) publish({ proposal: null }); }
  function invalidateQuotaPreview() {
    if (disposed || state.busy || state.selected?.kind !== 'email.quota_warning_80') return false;
    publish({ preview: null, previewOutdated: false, proposal: null }); return true;
  }
  function dispose() { disposed = true; sequence++; controller?.abort(); cleanupRequest?.(); cleanupRequest = null; controller = null; }
  return { subscribe: store.subscribe, load, select, edit, cancel, setPreviewLocale, preview, save, propose, acceptProposal, discardProposal, invalidateQuotaPreview, dispose };
}

// No preview resources, scripts, forms, navigation or parent privileges. The UI
// also makes this frame inert; plain text remains available as accessible text.
export function emailPreviewDocument(html: string): string {
  const policy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-src 'none'; base-uri 'none'; form-action 'none'; navigate-to 'none'";
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><meta name="referrer" content="no-referrer"></head><body style="margin:0;background:white;color:#171717">${html}</body></html>`;
}


export type WorkspaceEmailLocale = 'en' | 'sv';
export interface EmailTemplateSamplePorts {
  load(signal: AbortSignal): Promise<WorkspaceSMTP>;
  send(kind: EmailTemplateKind, templateRevision: number, smtpRevision: number, signal: AbortSignal, previewLocale?: WorkspaceEmailLocale): Promise<SMTPTestReceipt>;
  status(id: string, signal: AbortSignal): Promise<SMTPTestReceipt>;
}
export interface EmailTemplateSampleState {
  smtp: WorkspaceSMTP | null; receipt: SMTPTestReceipt | null; busy: boolean; error: string | null; uncertain: boolean;
  attemptLocale?: WorkspaceEmailLocale;
}
// A presentation choice cannot erase ownership of a durable test request. Its
// receipt/status remains tied to the original attempt, even after another
// preview language is selected. No locale change sends or retries anything.
export function createEmailTemplateSample(ports: EmailTemplateSamplePorts, options: { requestTimeoutMs?: number } = {}) {
  const timeoutMs = options.requestTimeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new RangeError('Invalid request deadline');
  type Scope = { kind: EmailTemplateKind; revision: number; locale?: WorkspaceEmailLocale; disabled: boolean };
  let scope: Scope | null = null, disposed = false, generation = 0, request: AbortController | null = null;
  let operation: 'settings' | 'send' | 'status' | null = null;
  let releaseRequest: (() => void) | null = null;
  let state: EmailTemplateSampleState = { smtp: null, receipt: null, busy: false, error: null, uncertain: false };
  const store = writable(state);
  const publish = (patch: Partial<EmailTemplateSampleState>) => { state = { ...state, ...patch }; store.set(state); };
  const identity = (value: Scope) => JSON.stringify([value.kind, value.revision]);
  function setScope(kind: EmailTemplateKind, revision: number, locale: WorkspaceEmailLocale | undefined, disabled = false) {
    if (disposed || !emailTemplateKinds.includes(kind) || !Number.isSafeInteger(revision) || revision < 0 || locale !== undefined && !isWorkspaceEmailLocale(locale)) return false;
    const next = { kind, revision, locale, disabled };
    if (scope && identity(scope) !== identity(next)) {
      const uncertain = state.uncertain || operation === 'send';
      generation++; request?.abort(); request = null; operation = null;
      publish({ busy: false, uncertain, error: uncertain ? 'Could not confirm whether the test was queued. Check your inbox and reload before another test.' : state.error });
    }
    scope = next;
    return true;
  }
  async function act(nextOperation: 'settings' | 'send' | 'status') {
    const selected = scope;
    if (disposed || !selected || state.busy
        || nextOperation === 'send' && (selected.disabled || state.uncertain || !state.smtp?.configured || !!state.receipt && !state.receipt.smtp_accepted && state.receipt.status !== 'failed')
        || nextOperation === 'status' && !state.receipt) return false;
    const ticket = ++generation, selectedIdentity = identity(selected), deliveryID = state.receipt?.delivery_id;
    const controller = new AbortController(); request = controller; operation = nextOperation;
    publish({ busy: true, error: null, ...(nextOperation === 'send' ? { attemptLocale: selected.locale, receipt: null } : {}) });
    let rejectAbort!: (error: Error) => void;
    const aborted = new Promise<never>((_resolve, reject) => { rejectAbort = reject; });
    const abort = () => rejectAbort(new Error('Test request interrupted'));
    controller.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const release = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', abort); };
    releaseRequest = release;
    const wait = <T>(promise: Promise<T>) => Promise.race([promise, aborted]);
    const current = () => !disposed && ticket === generation && scope !== null && selectedIdentity === identity(scope);
    try {
      if (nextOperation === 'settings') {
        const result = await wait(ports.load(controller.signal));
        if (controller.signal.aborted) throw new Error('Test request timed out');
        if (current()) publish({ smtp: result });
      } else if (nextOperation === 'send') {
        const result = await wait(ports.send(selected.kind, selected.revision, state.smtp!.revision, controller.signal, selected.locale));
        if (controller.signal.aborted) throw new Error('Test request timed out');
        if (current()) publish({ receipt: result });
      } else {
        const result = await wait(ports.status(deliveryID!, controller.signal));
        if (controller.signal.aborted) throw new Error('Test request timed out');
        if (result.delivery_id !== deliveryID) throw new Error('Test receipt identity changed');
        if (current()) publish({ receipt: result });
      }
      return current();
    } catch (cause) {
      if (!current()) return false;
      const status = Number((cause as { status?: number })?.status) || 0;
      if (nextOperation === 'send' && (status === 0 || status >= 500)) {
        publish({ uncertain: true, error: 'Could not confirm whether the test was queued. Check your inbox and reload before another test.' });
      } else if (status === 409) publish({ smtp: null, error: 'The saved template or delivery settings changed. Reload and review before testing.' });
      else if (status === 429) publish({ error: 'A test is pending or was requested recently. Check its status before sending another.' });
      else if (status === 401 || status === 403) publish({ smtp: null, error: 'Owner access is no longer available. Sign in again.' });
      else publish({ error: 'Could not check the email test. Try again.' });
      return false;
    } finally {
      release();
      if (current()) { request = null; operation = null; releaseRequest = null; publish({ busy: false }); }
    }
  }
  function dispose() { disposed = true; generation++; request?.abort(); releaseRequest?.(); releaseRequest = null; request = null; }
  return { subscribe: store.subscribe, setScope, act, dispose };
}

export interface WorkspaceEmailPreferences {
  schema_version: 1; org_id: string; revision: number; locale: WorkspaceEmailLocale; updated_at: string | null;
}
export const isWorkspaceEmailLocale = (value: unknown): value is WorkspaceEmailLocale => value === 'en' || value === 'sv';
export function emailPreviewLocale(kind: EmailTemplateKind, value: unknown, requested?: WorkspaceEmailLocale): value is WorkspaceEmailLocale {
  return isWorkspaceEmailLocale(value) && (requested === undefined ? kind === 'email.quota_warning_80' || value === 'en' : value === requested);
}
export function syntheticEmailLocale(kind: EmailTemplateKind | undefined, staff: WorkspaceEmailLocale, workspace?: WorkspaceEmailLocale, override?: WorkspaceEmailLocale): WorkspaceEmailLocale | undefined {
  return override ?? (kind === 'email.quota_warning_80' ? workspace : staff);
}
export function checkedWorkspaceEmailPreferences(value: unknown): WorkspaceEmailPreferences {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Email preferences contract rejected');
  const row = value as Record<string, unknown>;
  const timestamp = typeof row.updated_at === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(row.updated_at) && Number.isFinite(Date.parse(row.updated_at));
  if (Object.keys(row).some(key => !['schema_version','org_id','revision','locale','updated_at'].includes(key)) || row.schema_version !== 1
      || typeof row.org_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(row.org_id)
      || row.org_id === '00000000-0000-0000-0000-000000000000' || !Number.isSafeInteger(row.revision) || Number(row.revision) < 0
      || !isWorkspaceEmailLocale(row.locale) || (row.revision === 0 ? row.locale !== 'en' || row.updated_at !== null : !timestamp)) throw new Error('Email preferences contract rejected');
  return row as unknown as WorkspaceEmailPreferences;
}
export interface WorkspaceEmailPreferencesPorts {
  load(signal: AbortSignal): Promise<WorkspaceEmailPreferences>;
  save(saved: WorkspaceEmailPreferences, locale: WorkspaceEmailLocale, signal: AbortSignal): Promise<WorkspaceEmailPreferences>;
}
export interface WorkspaceEmailPreferencesState {
  saved: WorkspaceEmailPreferences | null; draftLocale: WorkspaceEmailLocale | ''; dirty: boolean;
  busy: 'loading' | 'saving' | null; authorized: boolean; unconfirmed: boolean; error: string | null; notice: string | null;
}
class WorkspaceEmailScopeChanged extends Error {}
// This owner setting has its own finite request and CAS. Neither UI language nor
// unsaved template prose supplies its value, and reloading never discards either.
export function createWorkspaceEmailPreferences(ports: WorkspaceEmailPreferencesPorts, options: { requestTimeoutMs?: number } = {}) {
  const timeoutMs = options.requestTimeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new RangeError('Invalid request deadline');
  let state: WorkspaceEmailPreferencesState = { saved: null, draftLocale: '', dirty: false, busy: null, authorized: false, unconfirmed: false, error: null, notice: null };
  const store = writable(state); let disposed = false, sequence = 0, orgID: string | null = null;
  let active: AbortController | null = null, release: (() => void) | null = null;
  const publish = (patch: Partial<WorkspaceEmailPreferencesState>) => { state = { ...state, ...patch }; store.set(state); };
  function begin(busy: 'loading' | 'saving') {
    if (disposed || state.busy) return null;
    const id = ++sequence, controller = new AbortController(); active = controller;
    let timedOut = false, reject!: (error: Error) => void;
    const aborted = new Promise<never>((_resolve, fail) => { reject = fail; });
    const abort = () => reject(timedOut ? new EmailRequestTimeout() : new Error('Request cancelled'));
    controller.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    release = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', abort); };
    publish({ busy, error: null, notice: null });
    return { id, signal: controller.signal, wait: <T>(promise: Promise<T>) => Promise.race([promise, aborted]) };
  }
  const current = (id: number) => !disposed && id === sequence;
  function finish(id: number) { if (current(id)) { release?.(); release = null; active = null; publish({ busy: null }); } }
  function checked(value: WorkspaceEmailPreferences) {
    const saved = checkedWorkspaceEmailPreferences(value);
    if (orgID && saved.org_id !== orgID) throw new WorkspaceEmailScopeChanged();
    if (state.saved && (saved.revision < state.saved.revision || saved.revision === state.saved.revision && (saved.locale !== state.saved.locale || saved.updated_at !== state.saved.updated_at))) throw new Error('Email preference snapshot regressed');
    return saved;
  }
  function failed(error: unknown, saving: boolean) {
    const status = Number((error as { status?: number })?.status) || 0;
    const scopeChanged = error instanceof WorkspaceEmailScopeChanged;
    const unknown = saving && (status === 0 || status >= 500);
    publish({ authorized: scopeChanged || status === 401 || status === 403 ? false : state.authorized,
      unconfirmed: state.unconfirmed || scopeChanged || status === 409 || unknown || (!saving && state.saved !== null),
      error: scopeChanged ? 'The workspace changed. Reload this settings page before changing its email language.'
        : status === 401 ? 'Your session has expired. Please sign in again.' : status === 403 ? 'Only workspace owners can change the email language.'
        : status === 409 ? 'The saved email language changed. Load it before saving again.'
        : unknown ? 'Saving the email language is unconfirmed. Load the saved value before another save.'
        : saving ? 'The email language was not saved. Check your selection and try again.' : 'The saved email language could not be loaded. Try again.' });
  }
  async function load(externalBlocked = false) {
    if (externalBlocked) return false;
    const request = begin('loading'); if (!request) return false;
    try {
      const saved = checked(await request.wait(ports.load(request.signal))); if (!current(request.id)) return false;
      orgID ??= saved.org_id;
      const draftLocale = state.dirty ? state.draftLocale : saved.locale, dirty = draftLocale !== saved.locale;
      const wasUnconfirmed = state.unconfirmed;
      publish({ saved, draftLocale, dirty, unconfirmed: false, authorized: true,
        notice: dirty ? 'The latest saved language is loaded. Review your unsaved selection.' : wasUnconfirmed ? 'The saved email language is confirmed. Already queued emails are unchanged.' : null }); return true;
    } catch (error) { if (current(request.id)) failed(error, false); return false; }
    finally { finish(request.id); }
  }
  function edit(value: unknown) {
    if (disposed || state.busy || state.unconfirmed || !state.saved || state.saved.revision >= Number.MAX_SAFE_INTEGER || !state.authorized || !isWorkspaceEmailLocale(value)) return false;
    publish({ draftLocale: value, dirty: value !== state.saved.locale, error: null, notice: null }); return true;
  }
  function cancel() {
    if (disposed || state.busy || state.unconfirmed || !state.saved) return false;
    publish({ draftLocale: state.saved.locale, dirty: false, error: null, notice: null }); return true;
  }
  async function save(externalBlocked = false) {
    if (disposed || externalBlocked || state.busy || state.unconfirmed || !state.saved || state.saved.revision >= Number.MAX_SAFE_INTEGER || !state.authorized || !state.dirty || !isWorkspaceEmailLocale(state.draftLocale)) return false;
    const before = state.saved, locale = state.draftLocale, request = begin('saving'); if (!request) return false;
    try {
      const saved = checked(await request.wait(ports.save(before, locale, request.signal))); if (!current(request.id)) return false;
      if (saved.org_id !== before.org_id || saved.revision !== before.revision + 1 || saved.locale !== locale) throw new Error('Saved email preference identity rejected');
      publish({ saved, draftLocale: saved.locale, dirty: false, unconfirmed: false, notice: 'Email language saved. Already queued emails and custom wording are unchanged.' }); return true;
    } catch (error) { if (current(request.id)) failed(error, true); return false; }
    finally { finish(request.id); }
  }
  function dispose() { if (!disposed) { disposed = true; sequence++; active?.abort(); release?.(); active = null; release = null; } }
  return { subscribe: store.subscribe, load, edit, cancel, save, dispose };
}
