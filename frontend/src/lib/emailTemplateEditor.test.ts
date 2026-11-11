import { describe, expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { createEmailTemplateEditor, emailDraftProblems, emailPreviewDocument, emailTemplateKinds, editableEmailTemplateKinds, canEditEmailTemplate,
  type EmailTemplate, type EmailTemplateCatalog, type EmailTemplateEditorPorts, type EmailTemplateInput,
  type EmailTemplatePreview, type EmailTemplateKind, createWorkspaceEmailPreferences, checkedWorkspaceEmailPreferences, type WorkspaceEmailPreferences, type WorkspaceEmailPreferencesPorts } from './emailTemplateEditor';

const template = (kind: EmailTemplateKind = emailTemplateKinds[0], revision = 0): EmailTemplate => ({ kind, revision, editable: editableEmailTemplateKinds.includes(kind),
  subject_template: '', html_template: '', text_template: '', mandatory_content: 'appended_by_hash', variables: ['document_name', 'recipient_name'] });
const catalogue = (): EmailTemplateCatalog => ({ schema_version: 1, preview_synthetic: true,
  limits: { subject_bytes: 256, html_bytes: 16384, text_bytes: 8192 }, templates: emailTemplateKinds.map(kind => template(kind)) });
const rendered = (revision = 0): EmailTemplatePreview => ({ schema_version: 1, synthetic: true, revision,
  locale: 'en', subject: 'Example document', html: '<p>Example recipient</p>', text: 'Example recipient', mandatory_content_preserved: true });
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
  test('voided remains catalog-only and can preview only its exact blank revision0', async () => {
    const { editor, calls } = setup(); await editor.load();
    for (const kind of ['email.voided'] as const) {
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
    expect(html).toContain("default-src 'none'"); expect(html).toContain("img-src data:");
    expect(html).toContain("form-action 'none'"); expect(html).toContain("base-uri 'none'");
  });
});

import { defaultEmailDesign } from './emailDesign';
const branded = () => JSON.stringify(defaultEmailDesign());
test('editing content preserves loaded design; explicit built-in design clearing uses the same immutable CAS', async () => {
  const { editor, calls } = setup({ load: async () => ({ ...catalogue(), templates: [{ ...template(undefined, 5), design_json: branded() }] }) });
  await editor.load(); editor.edit('text_template', 'Updated'); await editor.preview();
  expect(calls.preview[0].design_json).toBe(branded()); editor.edit('design_json', ''); expect(await editor.save()).toBe(true);
  expect(calls.save[0].design_json).toBe(''); expect(calls.save[0].expected_revision).toBe(5); editor.dispose();
});
test('AI proposal preview needs explicit accept into an unsaved draft and then an explicit CAS save', async () => {
  const { editor, calls } = setup({ propose: async (kind, input) => ({ schema_version: 1, kind, expected_revision: input.expected_revision, saved: false,
    input: { ...input, subject_template: 'AI proposed', design_json: branded() }, preview: rendered(input.expected_revision) }) });
  await editor.load(); editor.edit('text_template', 'My intro'); expect(await editor.propose('Readable branded design')).toBe(true);
  expect(get(editor).draft.subject_template).toBe(''); expect(get(editor).proposal?.preview.synthetic).toBe(true); expect(calls.save).toHaveLength(0);
  expect(await editor.save()).toBe(false); expect(editor.acceptProposal()).toBe(true);
  expect(get(editor).draft.subject_template).toBe('AI proposed'); expect(get(editor).dirty).toBe(true); expect(get(editor).selected?.revision).toBe(0);
  expect(get(editor).previewOutdated).toBe(false); expect(calls.save).toHaveLength(0); expect(await editor.save()).toBe(true);
  expect(calls.save[0].expected_revision).toBe(0); expect(calls.save[0].design_json).toBe(branded()); editor.dispose();
});
test('AI failed provider, stale revision and timeout retain draft and never invent a proposal or save', async () => {
  for (const status of [412, 409, 403]) {
    const { editor, calls } = setup({ propose: async () => { throw { status }; } }); await editor.load(); editor.edit('text_template', 'Keep draft');
    expect(await editor.propose('Style')).toBe(false); expect(get(editor).draft.text_template).toBe('Keep draft'); expect(get(editor).proposal).toBeNull();
    expect(calls.save).toHaveLength(0); expect(get(editor).conflict).toBe(status === 409); expect(get(editor).authorized).toBe(status !== 403); editor.dispose();
  }
  const late = deferred<any>(); const { editor } = setup({ propose: async () => late.promise }, { requestTimeoutMs: 10 }); await editor.load();
  expect(await editor.propose('Style')).toBe(false); late.resolve({}); await Promise.resolve(); expect(get(editor).proposal).toBeNull(); expect(get(editor).busy).toBeNull(); editor.dispose();
});
test('editing after a proposal invalidates it, and malformed design refuses before a request', async () => {
  const { editor, calls } = setup({ propose: async (kind, input) => ({ schema_version: 1, kind, expected_revision: input.expected_revision, saved: false, input: { ...input, design_json: branded() }, preview: rendered() }) });
  await editor.load(); await editor.propose('Style'); editor.edit('text_template', 'Manual edit'); expect(get(editor).proposal).toBeNull(); expect(editor.acceptProposal()).toBe(false);
  editor.edit('design_json', JSON.stringify({ ...defaultEmailDesign(), layout_html: '<div>Missing slot</div>' })); expect(await editor.preview()).toBe(false); expect(await editor.save()).toBe(false); expect(calls.preview).toHaveLength(0); expect(calls.save).toHaveLength(0); editor.dispose();
});


test('declined and quota editing requires the actual native editable capability', async () => {
  for (const kind of ['email.declined', 'email.quota_warning_80'] as const) {
    const active = setup(); await active.editor.load(); expect(active.editor.select(kind)).toBe(true);
    expect(active.editor.edit('text_template', 'Literal wording, inte översatt')).toBe(true); expect(await active.editor.save()).toBe(true);
    expect(active.calls.save[0].text_template).toBe('Literal wording, inte översatt'); active.editor.dispose();
    const denied = setup({ load: async () => ({ ...catalogue(), templates: [{ ...template(kind), editable: false }] }) });
    await denied.editor.load(); expect(denied.editor.edit('text_template', 'Blocked')).toBe(false); expect(await denied.editor.save()).toBe(false); denied.editor.dispose();
  }
});
test('quota-preview invalidation preserves literal template draft fields and never reloads, saves or sends', async () => {
  const { editor, calls } = setup(); await editor.load(); editor.select('email.quota_warning_80'); editor.edit('text_template', 'Keep my wording');
  expect(await editor.preview()).toBe(true); expect(get(editor).preview?.locale).toBe('en');
  const before = { ...get(editor).draft }; expect(editor.invalidateQuotaPreview()).toBe(true);
  expect(get(editor).draft).toEqual(before); expect(get(editor).dirty).toBe(true); expect(get(editor).preview).toBeNull(); expect(calls.load).toBe(1); expect(calls.save).toEqual([]);
  editor.cancel(); editor.select('email.invite'); expect(await editor.preview()).toBe(true); expect(editor.invalidateQuotaPreview()).toBe(false); expect(get(editor).preview).not.toBeNull(); editor.dispose();
});
const workspaceID = '22222222-2222-4222-8222-222222222222';
const preferences = (revision = 0, locale: 'en' | 'sv' = 'en'): WorkspaceEmailPreferences => ({ schema_version: 1, org_id: workspaceID, revision, locale, updated_at: revision ? '2030-01-01T12:00:00.123456Z' : null });
function preferenceSetup(overrides: Partial<WorkspaceEmailPreferencesPorts> = {}, requestTimeoutMs = 30000) {
  const calls: { saved: WorkspaceEmailPreferences; locale: string; signal: AbortSignal }[] = [];
  const form = createWorkspaceEmailPreferences({ load: async () => preferences(), save: async (saved, locale, signal) => { calls.push({ saved, locale, signal }); return preferences(saved.revision + 1, locale); }, ...overrides }, { requestTimeoutMs });
  return { form, calls };
}
test('workspace language is empty until server truth loads and explicit save retains the exact CAS', async () => {
  const { form, calls } = preferenceSetup(); expect(get(form).draftLocale).toBe(''); expect(get(form).authorized).toBe(false); expect(form.edit('sv')).toBe(false);
  await form.load(); expect(get(form).saved).toEqual(preferences()); expect(get(form).draftLocale).toBe('en'); expect(calls).toEqual([]);
  form.edit('sv'); expect(get(form).saved?.locale).toBe('en'); expect(get(form).dirty).toBe(true); expect(await form.save()).toBe(true);
  expect(calls).toHaveLength(1); expect(calls[0].saved).toEqual(preferences()); expect(calls[0].locale).toBe('sv'); expect(get(form).saved).toEqual(preferences(1, 'sv')); expect(get(form).notice).toContain('custom wording'); form.dispose();
});
test('preference conflict and unknown outcome retain intent and forbid a second save until an explicit read', async () => {
  for (const error of [{ status: 409 }, { status: 503 }, new Error('PRIVATE transport details')]) {
    let saves = 0, reads = 0;
    const { form } = preferenceSetup({ load: async () => ++reads === 1 ? preferences() : preferences(2), save: async () => { saves++; throw error; } });
    await form.load(); form.edit('sv'); expect(await form.save()).toBe(false); expect(get(form).saved?.revision).toBe(0); expect(get(form).draftLocale).toBe('sv'); expect(get(form).unconfirmed).toBe(true);
    expect(get(form).error).not.toContain('PRIVATE'); expect(await form.save()).toBe(false); expect(form.edit('en')).toBe(false); expect(form.cancel()).toBe(false); expect(saves).toBe(1);
    expect(await form.load()).toBe(true); expect(get(form).saved?.revision).toBe(2); expect(get(form).draftLocale).toBe('sv'); expect(get(form).dirty).toBe(true); expect(get(form).unconfirmed).toBe(false); form.dispose();
  }
});
test('readback after a lost reply can confirm the current saved language without inventing another write', async () => {
  let reads = 0, saves = 0;
  const { form } = preferenceSetup({ load: async () => ++reads === 1 ? preferences() : preferences(1, 'sv'), save: async () => { saves++; throw { status: 503 }; } });
  await form.load(); form.edit('sv'); await form.save(); await form.load();
  expect(get(form).saved).toEqual(preferences(1, 'sv')); expect(get(form).dirty).toBe(false); expect(get(form).notice).toContain('confirmed'); expect(saves).toBe(1); form.dispose();
});
test('locale save timeout releases its finite request, keeps the selection and ignores late success', async () => {
  const response = deferred<WorkspaceEmailPreferences>(); let signal!: AbortSignal;
  const { form } = preferenceSetup({ save: async (_saved, _locale, value) => { signal = value; return response.promise; } }, 10);
  await form.load(); form.edit('sv'); expect(await form.save()).toBe(false); expect(signal.aborted).toBe(true); expect(get(form).busy).toBeNull(); expect(get(form).unconfirmed).toBe(true);
  response.resolve(preferences(1, 'sv')); await Promise.resolve(); expect(get(form).saved?.revision).toBe(0); expect(get(form).draftLocale).toBe('sv'); form.dispose();
});
test('owner revocation and foreign or regressed preferences cannot rebind a preserved draft', async () => {
  for (const error of [{ status: 401 }, { status: 403 }]) {
    const { form } = preferenceSetup({ save: async () => { throw error; } }); await form.load(); form.edit('sv'); await form.save();
    expect(get(form).authorized).toBe(false); expect(get(form).draftLocale).toBe('sv'); expect(await form.save()).toBe(false); form.dispose();
  }
  for (const next of [{ ...preferences(2), org_id: '33333333-3333-4333-8333-333333333333' }, preferences(), preferences(1, 'sv')]) {
    let reads = 0; const { form } = preferenceSetup({ load: async () => ++reads === 1 ? preferences(1) : next });
    await form.load(); form.edit('sv'); expect(await form.load()).toBe(false); expect(get(form).saved).toEqual(preferences(1)); expect(get(form).draftLocale).toBe('sv'); form.dispose();
  }
});
test('one preference write owns its pending interval and disposal prevents a late saved notice', async () => {
  const response = deferred<WorkspaceEmailPreferences>(); let writes = 0, signal!: AbortSignal;
  const { form } = preferenceSetup({ save: async (_saved, _locale, value) => { writes++; signal = value; return response.promise; } });
  await form.load(); form.edit('sv'); const pending = form.save(); expect(form.edit('en')).toBe(false); expect(await form.load()).toBe(false); expect(await form.save()).toBe(false); expect(writes).toBe(1);
  form.dispose(); expect(signal.aborted).toBe(true); response.resolve(preferences(1, 'sv')); expect(await pending).toBe(false); expect(get(form).notice).toBeNull();
});
test('preference DTO is closed and an absent setting must be the explicit English revision0 snapshot', () => {
  for (const row of [{ ...preferences(), locale: 'sv' }, { ...preferences(), locale: 'SV' }, { ...preferences(), org_id: '00000000-0000-0000-0000-000000000000' }, { ...preferences(), revision: Number.MAX_SAFE_INTEGER + 1 }, { ...preferences(1), updated_at: null }, { ...preferences(1), updated_at: 'yesterday' }, { ...preferences(), smtp_password: 'not part of this DTO' }]) expect(() => checkedWorkspaceEmailPreferences(row)).toThrow();
});

test('the maximum persisted preference revision remains readable but cannot start another write', async () => {
  const snapshot = preferences(Number.MAX_SAFE_INTEGER);
  expect(checkedWorkspaceEmailPreferences(snapshot)).toEqual(snapshot);
  const { form, calls } = preferenceSetup({ load: async () => snapshot }); await form.load();
  expect(form.edit('sv')).toBe(false); expect(await form.save()).toBe(false); expect(calls).toEqual([]); expect(get(form).unconfirmed).toBe(false); form.dispose();
});
