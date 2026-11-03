import { writable } from 'svelte/store';

export const emailTemplateKinds = [
  'email.invite', 'email.reminder', 'email.completed_signer', 'email.completed_sender',
  'email.declined', 'email.changes_requested', 'email.new_comment', 'email.voided', 'email.quota_warning_80',
] as const;
export type EmailTemplateKind = typeof emailTemplateKinds[number];
export const editableEmailTemplateKinds: readonly EmailTemplateKind[] = [
  'email.invite', 'email.reminder', 'email.completed_signer', 'email.completed_sender', 'email.changes_requested', 'email.new_comment',
];
export interface EmailTemplateFields {
  subject_template: string;
  html_template: string;
  text_template: string;
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
  limits: { subject_bytes: number; html_bytes: number; text_bytes: number };
  preview_synthetic: true;
}
export interface EmailTemplatePreview {
  schema_version: 1;
  synthetic: true;
  revision: number;
  subject: string;
  html: string;
  text: string;
  mandatory_content_preserved: true;
}
export type EmailTemplateInput = EmailTemplateFields & { expected_revision: number };
export interface EmailTemplateEditorPorts {
  load: (signal: AbortSignal) => Promise<EmailTemplateCatalog>;
  save: (kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal) => Promise<EmailTemplate>;
  preview: (kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal) => Promise<EmailTemplatePreview>;
}
export type EmailField = keyof EmailTemplateFields;
export interface EmailEditorState {
  catalog: EmailTemplateCatalog | null;
  selected: EmailTemplate | null;
  draft: EmailTemplateFields;
  busy: 'loading' | 'saving' | 'previewing' | null;
  error: string | null;
  notice: string | null;
  conflict: boolean;
  dirty: boolean;
  preview: EmailTemplatePreview | null;
  previewOutdated: boolean;
  authorized: boolean;
}
const emptyFields = (): EmailTemplateFields => ({ subject_template: '', html_template: '', text_template: '' });
export function emailTemplateFields(value: EmailTemplateFields): EmailTemplateFields {
  return { subject_template: value.subject_template, html_template: value.html_template, text_template: value.text_template };
}
function sameFields(a: EmailTemplateFields, b: EmailTemplateFields) {
  return a.subject_template === b.subject_template && a.html_template === b.html_template && a.text_template === b.text_template;
}
export function canEditEmailTemplate(value: EmailTemplate | null): boolean {
  return value?.editable === true && editableEmailTemplateKinds.includes(value.kind);
}
export function isBuiltInEmailTemplate(value: EmailTemplateFields & { revision: number }): boolean {
  return value.revision === 0 && value.subject_template === '' && value.html_template === '' && value.text_template === '';
}
export function emailFieldBytes(value: string) { return new TextEncoder().encode(value).byteLength; }
export function emailDraftProblems(draft: EmailTemplateFields, limits: EmailTemplateCatalog['limits']): Partial<Record<EmailField, string>> {
  const errors: Partial<Record<EmailField, string>> = {};
  if (emailFieldBytes(draft.subject_template) > limits.subject_bytes) errors.subject_template = 'The subject is too long.';
  if (/[\r\n]/.test(draft.subject_template)) errors.subject_template = 'The subject must be one line.';
  if (emailFieldBytes(draft.html_template) > limits.html_bytes) errors.html_template = 'The HTML content is too long.';
  if (emailFieldBytes(draft.text_template) > limits.text_bytes) errors.text_template = 'The plain text content is too long.';
  return errors;
}
class EmailRequestTimeout extends Error {}
function safeFailure(error: unknown, operation: 'loading' | 'saving' | 'previewing') {
  if (error instanceof EmailRequestTimeout) {
    if (operation === 'saving') return 'Saving timed out. Reload the latest revision to check whether it was saved.';
    if (operation === 'previewing') return 'The preview timed out. Your draft is unchanged.';
    return 'Email templates took too long to load. Try again.';
  }
  const status = typeof error === 'object' && error !== null && 'status' in error ? Number(error.status) : 0;
  if (status === 401) return 'Your session has expired. Please sign in again.';
  if (status === 403) return 'Only workspace owners can manage email templates.';
  if (status === 409) return 'This template changed in another session. Reload the latest revision before continuing.';
  if (status === 400) return 'Check the template fields and variables, then try again.';
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
    conflict: false, dirty: false, preview: null, previewOutdated: false, authorized: false,
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
    publish({ busy: kind, error: null, notice: null });
    return { operation, signal: ownedController.signal, wait: <T>(promise: Promise<T>) => Promise.race([promise, aborted]) };
  }
  function current(operation: number) { return !disposed && operation === sequence; }
  function finish(operation: number) { if (current(operation)) { cleanupRequest?.(); cleanupRequest = null; controller = null; publish({ busy: null }); } }
  function failure(error: unknown, operation: 'loading' | 'saving' | 'previewing') {
    const status = (error as {status?: number})?.status;
    publish({ error: safeFailure(error, operation), conflict: status === 409 || (error instanceof EmailRequestTimeout && operation === 'saving') || state.conflict,
      authorized: status === 401 || status === 403 ? false : state.authorized,
      previewOutdated: state.preview !== null });
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
        conflict: false, preview: null, previewOutdated: false, authorized: true });
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
      dirty: false, preview: null, previewOutdated: false });
    return true;
  }
  function edit(field: EmailField, value: string) {
    if (disposed || state.busy || !state.selected || !state.authorized || !canEditEmailTemplate(state.selected)) return false;
    const draft = { ...state.draft, [field]: value };
    publish({ draft, dirty: !sameFields(draft, state.selected), error: state.conflict ? state.error : null, notice: null,
      previewOutdated: state.preview !== null });
    return true;
  }
  function cancel() {
    if (disposed || state.busy || !state.selected) return false;
    publish({ draft: emailTemplateFields(state.selected), dirty: false, notice: null, error: state.conflict ? state.error : null,
      preview: null, previewOutdated: false });
    return true;
  }
  async function preview() {
    if (disposed || state.busy) return false;
    const draft = input(); const selected = state.selected; if (!draft || !selected) return false;
    const request = start('previewing'); if (!request) return false;
    try {
      const result = await request.wait(ports.preview(selected.kind, draft, request.signal));
      if (!current(request.operation)) return false;
      if (result.revision !== draft.expected_revision || !result.synthetic || !result.mandatory_content_preserved) {
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
    if (disposed || state.busy || !state.dirty || !canEditEmailTemplate(state.selected)) return false;
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
  function dispose() { disposed = true; sequence++; controller?.abort(); cleanupRequest?.(); cleanupRequest = null; controller = null; }
  return { subscribe: store.subscribe, load, select, edit, cancel, preview, save, dispose };
}

// No preview resources, scripts, forms, navigation or parent privileges. The UI
// also makes this frame inert; plain text remains available as accessible text.
export function emailPreviewDocument(html: string): string {
  const policy = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; navigate-to 'none'";
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><meta name="referrer" content="no-referrer"></head><body style="margin:0;background:white;color:#171717">${html}</body></html>`;
}
