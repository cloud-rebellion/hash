import { describe, expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { createEmailTemplateEditor, emailDraftProblems, emailPreviewDocument, emailTemplateKinds, editableEmailTemplateKinds, canEditEmailTemplate,
  type EmailTemplate, type EmailTemplateCatalog, type EmailTemplateEditorPorts, type EmailTemplateInput,
  type EmailTemplatePreview, type EmailTemplateKind } from './emailTemplateEditor';

const template = (kind: EmailTemplateKind = emailTemplateKinds[0], revision = 0): EmailTemplate => ({ kind, revision, editable: editableEmailTemplateKinds.includes(kind),
  subject_template: '', html_template: '', text_template: '', mandatory_content: 'appended_by_hash', variables: ['document_name', 'recipient_name'] });
const catalogue = (): EmailTemplateCatalog => ({ schema_version: 1, preview_synthetic: true,
  limits: { subject_bytes: 256, html_bytes: 16384, text_bytes: 8192 }, templates: emailTemplateKinds.map(kind => template(kind)) });
const rendered = (revision = 0): EmailTemplatePreview => ({ schema_version: 1, synthetic: true, revision,
  subject: 'Example document', html: '<p>Example recipient</p>', text: 'Example recipient', mandatory_content_preserved: true });
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function setup(overrides: Partial<EmailTemplateEditorPorts> = {}, options: { requestTimeoutMs?: number } = {}) {
  const calls = { load: 0, save: [] as EmailTemplateInput[], preview: [] as EmailTemplateInput[] };
  const ports: EmailTemplateEditorPorts = {
    load: async () => { calls.load++; return catalogue(); },
    save: async (kind, input) => { calls.save.push(input); return { ...template(kind, input.expected_revision + 1), ...input }; },
    preview: async (_kind, input) => { calls.preview.push(input); return rendered(input.expected_revision); },
    ...overrides,
  };
  return { editor: createEmailTemplateEditor(ports, options), calls };
}

describe('owner email template callbacks', () => {
  test('three built-in kinds cannot edit/save but can preview their exact blank revision0', async () => {
    const { editor, calls } = setup(); await editor.load();
    for (const kind of ['email.declined', 'email.voided', 'email.quota_warning_80'] as const) {
      expect(editor.select(kind)).toBe(true); expect(canEditEmailTemplate(get(editor).selected)).toBe(false);
      expect(editor.edit('subject_template', 'Ignored edition')).toBe(false); expect(await editor.save()).toBe(false);
      expect(await editor.preview()).toBe(true);
      expect(calls.preview.at(-1)).toEqual({ expected_revision: 0, subject_template: '', html_template: '', text_template: '' });
    }
    expect(calls.save).toHaveLength(0); editor.dispose();
  });
  test('malformed capability and incompatible kind never grant editing; unsupported editions are not ignored', async () => {
    expect(canEditEmailTemplate({ ...template(), editable: 'true' as unknown as boolean })).toBe(false);
    expect(canEditEmailTemplate({ ...template('email.voided'), editable: true })).toBe(false);
    const { editor, calls } = setup({ load: async () => ({ ...catalogue(), templates: [{ ...template('email.voided', 2), subject_template: 'Must not ignore' }] }) });
    await editor.load(); expect(await editor.preview()).toBe(false); expect(await editor.save()).toBe(false);
    expect(calls.preview).toHaveLength(0); expect(get(editor).error).toContain('Customization'); editor.dispose();
  });
  test('hung load aborts within the owned deadline; its late response cannot overwrite a new load', async () => {
    const old = deferred<EmailTemplateCatalog>(); let reads = 0; let signal!: AbortSignal;
    const { editor } = setup({ load: async value => { signal = value; return ++reads === 1 ? old.promise : { ...catalogue(), templates: [template(undefined, 8)] }; } }, { requestTimeoutMs: 10 });
    expect(await editor.load()).toBe(false); expect(signal.aborted).toBe(true); expect(get(editor).busy).toBeNull();
    expect(get(editor).error).toContain('too long'); expect(await editor.load()).toBe(true);
    old.resolve(catalogue()); await Promise.resolve(); expect(get(editor).selected?.revision).toBe(8); editor.dispose();
  });
  test('save timeout keeps the draft and unknown outcome fenced until explicit reload; late success is ignored', async () => {
    const old = deferred<EmailTemplate>(); let signal!: AbortSignal; let reads = 0;
    const { editor } = setup({ load: async () => ({ ...catalogue(), templates: [template(undefined, reads++ ? 1 : 0)] }),
      save: async (_kind, _input, value) => { signal = value; return old.promise; } }, { requestTimeoutMs: 10 });
    await editor.load(); editor.edit('text_template', 'Keep my draft'); expect(await editor.save()).toBe(false);
    expect(signal.aborted).toBe(true); expect(get(editor).busy).toBeNull(); expect(get(editor).conflict).toBe(true);
    expect(get(editor).draft.text_template).toBe('Keep my draft'); expect(await editor.save()).toBe(false);
    old.resolve({ ...template(undefined, 1), text_template: 'Keep my draft' }); await Promise.resolve();
    expect(get(editor).notice).toBeNull(); expect(get(editor).selected?.revision).toBe(0);
    expect(await editor.load()).toBe(true); expect(get(editor).selected?.revision).toBe(1); editor.dispose();
  });
  test('preview timeout releases busy and never displays a late sample', async () => {
    const old = deferred<EmailTemplatePreview>(); let signal!: AbortSignal;
    const { editor } = setup({ preview: async (_kind, _input, value) => { signal = value; return old.promise; } }, { requestTimeoutMs: 10 });
    await editor.load(); expect(await editor.preview()).toBe(false); expect(signal.aborted).toBe(true); expect(get(editor).busy).toBeNull();
    old.resolve(rendered()); await Promise.resolve(); expect(get(editor).preview).toBeNull(); editor.dispose();
  });
  test('disposal settles an indefinitely pending request and cancels its timer', async () => {
    const { editor } = setup({ load: async () => new Promise(() => {}) });
    const pending = editor.load(); editor.dispose(); expect(await pending).toBe(false); expect(get(editor).notice).toBeNull();
  });
  test('loads real defaults, previews without a save and binds the observed revision', async () => {
    const { editor, calls } = setup();
    expect(await editor.load()).toBe(true); expect(get(editor).authorized).toBe(true);
    expect(await editor.preview()).toBe(true);
    expect(calls.preview).toEqual([{ expected_revision: 0, subject_template: '', html_template: '', text_template: '' }]);
    expect(calls.save).toHaveLength(0); expect(get(editor).preview?.mandatory_content_preserved).toBe(true);
    editor.dispose();
  });
  test('keeps unsaved content until explicit cancel and blocks another template', async () => {
    const { editor } = setup(); await editor.load();
    editor.edit('html_template', '<p>Hello {{recipient_name}}</p>');
    expect(editor.select('email.reminder')).toBe(false); expect(get(editor).draft.html_template).toContain('recipient_name');
    expect(editor.cancel()).toBe(true); expect(get(editor).dirty).toBe(false);
    expect(editor.select('email.reminder')).toBe(true); expect(get(editor).selected?.kind).toBe('email.reminder'); editor.dispose();
  });
  test('retains one write owner until save finishes; no selection, edit, preview or second save', async () => {
    const response = deferred<EmailTemplate>(); let saves = 0;
    const { editor } = setup({ save: async () => { saves++; return response.promise; } }); await editor.load();
    editor.edit('subject_template', 'Hello'); const pending = editor.save();
    expect(get(editor).busy).toBe('saving'); expect(editor.edit('text_template', 'late')).toBe(false);
    expect(editor.cancel()).toBe(false); expect(editor.select('email.reminder')).toBe(false);
    expect(await editor.save()).toBe(false); expect(await editor.preview()).toBe(false); expect(saves).toBe(1);
    response.resolve({ ...template(undefined, 1), subject_template: 'Hello' }); expect(await pending).toBe(true);
    expect(get(editor).busy).toBeNull(); expect(get(editor).dirty).toBe(false); expect(get(editor).notice).toContain('Already queued'); editor.dispose();
  });
  test('sends only the selected content and expected revision; all blank resets use the same CAS', async () => {
    const { editor, calls } = setup({ load: async () => ({ ...catalogue(), templates: [{ ...template(undefined, 3), subject_template: 'Custom', html_template: '<p>Intro</p>', text_template: 'Intro' }] }) });
    await editor.load(); editor.edit('subject_template', ''); editor.edit('html_template', ''); editor.edit('text_template', '');
    expect(await editor.save()).toBe(true); expect(calls.save).toEqual([{ expected_revision: 3, subject_template: '', html_template: '', text_template: '' }]);
    expect(get(editor).selected?.revision).toBe(4); editor.dispose();
  });
  test('conflict preserves the draft and refuses retries until an explicit successful reload', async () => {
    let reads = 0, writes = 0;
    const { editor } = setup({ load: async () => { reads++; return { ...catalogue(), templates: [template(undefined, reads === 1 ? 2 : 5)] }; },
      save: async () => { writes++; throw { status: 409 }; } });
    await editor.load(); editor.edit('text_template', 'My draft'); expect(await editor.save()).toBe(false);
    expect(get(editor).draft.text_template).toBe('My draft'); expect(get(editor).conflict).toBe(true);
    expect(await editor.save()).toBe(false); expect(await editor.preview()).toBe(false); expect(writes).toBe(1);
    editor.edit('text_template', 'Still my draft'); expect(get(editor).error).toContain('another session');
    editor.cancel(); expect(get(editor).error).toContain('another session');
    expect(editor.select('email.invite')).toBe(false); expect(get(editor).conflict).toBe(true);
    expect(await editor.preview()).toBe(false);
    expect(await editor.load()).toBe(true); expect(get(editor).selected?.revision).toBe(5);
    expect(get(editor).draft.text_template).toBe(''); expect(get(editor).conflict).toBe(false); editor.dispose();
  });
  test('failed reload does not silently erase an existing draft', async () => {
    let reads = 0; const { editor } = setup({ load: async () => { if (++reads > 1) throw new Error('private database detail'); return catalogue(); } });
    await editor.load(); editor.edit('text_template', 'Keep me'); expect(await editor.load()).toBe(false);
    expect(get(editor).draft.text_template).toBe('Keep me'); expect(get(editor).error).not.toContain('database'); editor.dispose();
  });
  test('editing invalidates a previous sample and preview work blocks parallel writes', async () => {
    const response = deferred<EmailTemplatePreview>(); let previews = 0;
    const { editor } = setup({ preview: async () => { if (++previews === 1) return rendered(); return response.promise; } });
    await editor.load(); await editor.preview(); editor.edit('subject_template', 'Updated'); expect(get(editor).previewOutdated).toBe(true);
    const pending = editor.preview(); expect(await editor.save()).toBe(false); expect(editor.edit('subject_template', 'raced')).toBe(false);
    response.resolve(rendered()); expect(await pending).toBe(true); expect(get(editor).previewOutdated).toBe(false); editor.dispose();
  });
  test('owner revocation fails closed without a second save or preview', async () => {
    let requests = 0; const { editor } = setup({ preview: async () => { requests++; throw { status: 403 }; } });
    await editor.load(); editor.edit('text_template', 'Draft'); await editor.preview();
    expect(get(editor).authorized).toBe(false); expect(editor.edit('text_template', 'late')).toBe(false);
    expect(await editor.preview()).toBe(false); expect(await editor.save()).toBe(false); expect(requests).toBe(1); editor.dispose();
  });
  test('disposal aborts the request and rejects its late result without a saved notice', async () => {
    const response = deferred<EmailTemplate>(); let signal!: AbortSignal;
    const { editor } = setup({ save: async (_kind, _input, value) => { signal = value; return response.promise; } }); await editor.load();
    editor.edit('text_template', 'Draft'); const pending = editor.save(); editor.dispose(); expect(signal.aborted).toBe(true);
    response.resolve({ ...template(undefined, 1), text_template: 'Draft' }); expect(await pending).toBe(false); expect(get(editor).notice).toBeNull();
  });
  test('foreign save identity or unbound preview cannot publish success', async () => {
    const { editor } = setup({ save: async () => template('email.reminder', 1), preview: async () => rendered(4) }); await editor.load();
    editor.edit('text_template', 'Draft'); expect(await editor.save()).toBe(false); expect(get(editor).dirty).toBe(true);
    expect(await editor.preview()).toBe(false); expect(get(editor).preview).toBeNull(); expect(get(editor).notice).toBeNull(); editor.dispose();
  });
  test('UTF-8 limits and header line breaks refuse before either request', async () => {
    const { editor, calls } = setup(); await editor.load(); editor.edit('subject_template', 'å'.repeat(129));
    expect(await editor.save()).toBe(false); expect(await editor.preview()).toBe(false);
    editor.edit('subject_template', 'Hello\r\nBcc: no'); expect(await editor.save()).toBe(false);
    expect(calls.save).toHaveLength(0); expect(calls.preview).toHaveLength(0);
    expect(emailDraftProblems({ subject_template: '', html_template: '', text_template: '' }, catalogue().limits)).toEqual({}); editor.dispose();
  });
  test('synthetic preview document puts restrictive CSP before supplied content', () => {
    const html = emailPreviewDocument('<p>Sample</p>');
    expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<p>Sample'));
    expect(html).toContain("default-src 'none'"); expect(html).toContain("img-src 'none'");
    expect(html).toContain("form-action 'none'"); expect(html).toContain("base-uri 'none'");
  });
});
