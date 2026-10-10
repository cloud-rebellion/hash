import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../api/client';
import { blankHTMLAuthorDraft, blankHTMLSigningPage, draftFromHTMLTemplate, htmlAuthorFingerprint, htmlAuthorInput, htmlAssetFromFile } from '../htmlAuthor';
import { htmlContractProfile, htmlPreviewSections, htmlProfileIssues, htmlSigningPageIssues, htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate } from '../htmlTemplate';
import { signingPageTemplateFixture } from '../htmlTemplate.test';

// Execute the actual production callbacks without a second implementation of
// the protocol. Rendering and Svelte reactivity are separately browser-tested.
function callback(source: string, name: string) {
  let start = source.indexOf(`function ${name}(`);
  if (source.slice(start - 6, start) === 'async ') start -= 6;
  const opening = source.indexOf('{', start);
  let position = opening, depth = 1;
  while (depth && ++position < source.length) {
    if (source[position] === '{') depth++;
    if (source[position] === '}') depth--;
  }
  if (start < 0 || opening < 0 || depth) throw new Error(`Missing production callback ${name}`);
  return source.slice(start, position + 1);
}
const event = { preventDefault() {} };
const userID = '11111111-1111-4111-8111-111111111111', orgID = '22222222-2222-4222-8222-222222222222';
const templateID = '33333333-3333-4333-8333-333333333333';
const owner = { user_id: userID, org_id: orgID, email: 'synthetic@example.invalid', role: 'owner' };
function design(version = 3) {
  return { id: templateID, org_id: orgID, name: 'Printed design', source_kind: 'html', version, content_sha256: 'a'.repeat(64),
    variables_json: { company: 'Approved default' }, html_master_json: { schema_version: 1, html: '<p><span data-hash-value="company"></span></p>', css: 'p { color: #123456; }',
      values: [{ name: 'company', required: true, max_chars: 100 }], sections: [], assets: [] },
    html_approval: { version, content_sha256: 'a'.repeat(64) } };
}
function preview() {
  return { bytes: Uint8Array.of(1), templateID, version: 3, contentSHA256: 'a'.repeat(64), materializationSHA256: 'b'.repeat(64),
    pdfSHA256: 'c'.repeat(64), pages: 2, receipt: 'own_session_receipt', expiresAt: new Date(Date.now() + 600_000).toISOString() };
}
function fixture(existing = true) {
  const calls: any[] = [];
  const initial = design(), local = draftFromHTMLTemplate(initial as any);
  const env: any = { templateID: existing ? templateID : null, sourceID: existing ? templateID : null, disposed: false,
    knownID: existing ? templateID : null, orgScope: orgID, me: { ...owner }, saved: existing ? initial : null, latest: null,
    draft: local, baseline: htmlAuthorFingerprint(existing ? local : blankHTMLAuthorDraft()),
    samples: { company: 'Preview sample' }, sectionSamples: {}, sampleBaseline: '{"values":{"company":"Approved default"},"sections":{}}',
    loading: false, busy: null, error: null, operation: 0, rowKey: 1, needsRefresh: false, writeUncertain: false, acknowledgedSave: null,
    preview: null, previewAbort: null, previewSamples: '', previewActor: '', previewSequence: 0, allPagesSeen: false, acknowledged: false, now: Date.now(),
    assetName: '', pendingAssetFile: null, assetFile: { value: '' },
    APIError, htmlAuthorInput, htmlAuthorFingerprint, draftFromHTMLTemplate, htmlContractProfile, htmlPreviewSections, htmlProfileIssues, htmlSigningPageIssues, htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate, htmlAssetFromFile, blankHTMLSigningPage,
    window: { confirm: () => false },
  };
  env.current = () => !env.disposed && env.templateID === env.sourceID;
  Object.defineProperties(env, {
    dirty: { get: () => htmlAuthorFingerprint(env.draft) !== env.baseline },
    sampleDirty: { get: () => JSON.stringify({ values: env.samples, sections: env.sectionSamples }) !== env.sampleBaseline },
    assetDraftDirty: { get: () => !!env.assetName || !!env.pendingAssetFile },
    canWrite: { get: () => !!env.me && env.me.org_id === env.orgScope && (!env.sourceID || env.saved !== null) && ['owner', 'sender'].includes(env.me.role) },
    canApprove: { get: () => env.canWrite && env.me.role === 'owner' },
    approved: { get: () => !!env.saved && isApprovedHTMLTemplate(env.saved) },
    previewKey: { get: () => `preview-${env.previewSequence}` },
    previewValid: { get: () => !!env.preview && !!env.saved && !env.dirty && !env.assetDraftDirty && !env.needsRefresh && !env.writeUncertain
      && env.preview.templateID === env.saved.id && env.preview.version === env.saved.version && env.preview.contentSHA256 === env.saved.content_sha256
      && env.previewActor === env.me?.user_id && env.previewSamples === JSON.stringify({ values: env.samples, sections: env.sectionSamples }) && env.now < Date.parse(env.preview.expiresAt) },
  });
  for (const [name, kind] of [['getMe', 'me'], ['getTemplate', 'detail'], ['createHTMLTemplate', 'create'], ['updateHTMLTemplate', 'update'],
    ['previewHTMLTemplate', 'preview'], ['approveHTMLTemplate', 'approve']]) {
    env[name] = (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind, args, resolve, reject }));
  }
  const names = ['invalidatePreview', 'detail', 'samePin', 'adopt', 'recordError', 'checkedIdentity', 'loadInitial', 'save', 'readLatest', 'adoptLatest',
    'addAsset', 'changeSigningPage', 'changeSigningLogo', 'generatePreview', 'receiveProof', 'approve', 'protectNavigation', 'protectUnload'];
  const source = readFileSync(new URL('./HtmlTemplateEditor.svelte', import.meta.url), 'utf8');
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(names.map((name) => callback(source, name)).join('\n'));
  const actions = new Function('env', `with(env) { ${code}; return { ${names.join(',')} }; }`)(env);
  return { env, calls, actions };
}
async function step() { await Promise.resolve(); await Promise.resolve(); }
function installPreview(state: ReturnType<typeof fixture>) {
  state.env.preview = preview(); state.env.previewActor = userID; state.env.previewSamples = JSON.stringify({ values: state.env.samples, sections: state.env.sectionSamples });
  state.env.previewSequence = 1; state.env.allPagesSeen = true; state.env.acknowledged = true;
}

test('CREATE success then readback 401/403/404 retains exact acknowledged pin and never dispatches a second CREATE', async () => {
  for (const status of [401, 403, 404]) {
    const state = fixture(false), entered = htmlAuthorFingerprint(state.env.draft);
    const pending = state.actions.save(event); await state.actions.save(event);
    expect(state.calls.map((call) => call.kind)).toEqual(['create']);
    state.calls[0].resolve({ ...design(1), html_approval: undefined }); await step();
    state.calls[1].reject(new APIError(status, 'Readback unavailable')); await pending;
    expect(state.env.knownID).toBe(templateID); expect(state.env.saved).toBeNull();
    expect(state.env.acknowledgedSave).toEqual({ id: templateID, version: 1, contentSHA256: 'a'.repeat(64) });
    expect(state.env.writeUncertain).toBe(true); expect(htmlAuthorFingerprint(state.env.draft)).toBe(entered);
    const reloading = state.actions.loadInitial(); state.calls[2].resolve(owner); await step(); state.calls[3].resolve(design(1)); await reloading;
    expect(state.env.latest.version).toBe(1); expect(state.env.saved).toBeNull();
    await state.actions.save(event); expect(state.calls.filter((call) => call.kind === 'create')).toHaveLength(1);
    state.actions.adoptLatest(); expect(state.env.saved).toBeNull();
    state.env.window.confirm = () => true; state.actions.adoptLatest(); expect(state.env.saved.version).toBe(1);
    await state.actions.save(event); expect(state.calls.filter((call) => call.kind === 'create')).toHaveLength(1);
  }
});
test('dirty existing inputs survive unauthorized save and session reload until deliberate revision adoption', async () => {
  const state = fixture(); state.env.draft.html += '<p>New wording</p>'; state.env.draft.values[0].default_value = 'Edited default';
  state.env.draft.assets = [{ name: 'logo', media_type: 'image/png', data_base64: 'AAAA', sha256: 'd'.repeat(64) }];
  const entered = htmlAuthorFingerprint(state.env.draft), pending = state.actions.save(event);
  state.calls[0].reject(new APIError(401, 'Expired session')); await pending; expect(state.env.me).toBeNull();
  const reloading = state.actions.loadInitial(); state.calls[1].resolve(owner); await step(); state.calls[2].resolve(design(4)); await reloading;
  expect(htmlAuthorFingerprint(state.env.draft)).toBe(entered); expect(state.env.saved.version).toBe(3); expect(state.env.latest.version).toBe(4);
  state.actions.adoptLatest(); expect(htmlAuthorFingerprint(state.env.draft)).toBe(entered);
  state.env.window.confirm = () => true; state.actions.adoptLatest(); expect(state.env.draft.values[0].default_value).toBe('Approved default');
});
test('malformed initial/reloaded identity clears authority and preview without rebinding or losing draft', async () => {
  const malformed = [{ role: 'owner' }, { ...owner, user_id: 'bad' }, { ...owner, org_id: '00000000-0000-0000-0000-000000000000' }, { ...owner, role: 'admin' }];
  for (const existing of [false, true]) for (const identity of malformed) {
    const state = fixture(existing), entered = htmlAuthorFingerprint(state.env.draft); installPreview(state);
    const pending = state.actions.loadInitial(); state.calls[0].resolve(identity); await pending;
    expect(state.env.me).toBeNull(); expect(state.env.preview).toBeNull(); expect(state.env.orgScope).toBe(orgID);
    expect(htmlAuthorFingerprint(state.env.draft)).toBe(entered); expect(state.calls).toHaveLength(1);
    await state.actions.save(event); expect(state.calls).toHaveLength(1);
  }
});
test('known tenant change clears authority, anchors original organisation and preserves new/existing input', async () => {
  for (const existing of [false, true]) {
    const state = fixture(existing), entered = htmlAuthorFingerprint(state.env.draft); installPreview(state);
    const pending = state.actions.loadInitial(); state.calls[0].resolve({ ...owner, org_id: '44444444-4444-4444-8444-444444444444' }); await pending;
    expect(state.env.orgScope).toBe(orgID); expect(state.env.me).toBeNull(); expect(state.env.preview).toBeNull();
    expect(htmlAuthorFingerprint(state.env.draft)).toBe(entered); await state.actions.save(event); expect(state.calls).toHaveLength(1);
  }
});
test('conflicts and unknown save outcomes preserve local assets/defaults and require explicit reconciliation', async () => {
  for (const failure of [new APIError(409, 'Revision changed'), new APIError(503, 'Please try again'), new TypeError('Connection lost')]) {
    const state = fixture(); state.env.draft.name = 'Local changed design'; const entered = htmlAuthorFingerprint(state.env.draft);
    const pending = state.actions.save(event); state.calls[0].reject(failure); await pending;
    expect(htmlAuthorFingerprint(state.env.draft)).toBe(entered);
    expect(state.env.needsRefresh || state.env.writeUncertain).toBe(true);
    expect(state.env.error).not.toContain('try again'); await state.actions.save(event); expect(state.calls).toHaveLength(1);
  }
});
test('preview dispatch uses only saved revision and explicit samples; sender may preview but cannot approve', async () => {
  const state = fixture(); state.env.me.role = 'sender';
  const pending = state.actions.generatePreview(); await state.actions.generatePreview();
  expect(state.calls).toHaveLength(1); expect(state.calls[0].args.slice(0, 4)).toEqual([templateID, 3, 'a'.repeat(64), { company: 'Preview sample' }]);
  state.calls[0].resolve(preview()); await pending; expect(state.env.previewValid).toBe(true);
  state.env.allPagesSeen = true; state.env.acknowledged = true; await state.actions.approve(); expect(state.calls).toHaveLength(1);
  expect(state.env.draft.values[0].default_value).toBe('Approved default');
});
test('page opt-in and local-logo callbacks create a new reviewable draft and never silently alter saved schema2 design', () => {
  const state = fixture(), template = signingPageTemplateFixture();
  template.id = templateID; template.org_id = orgID;
  template.html_master_json!.schema_version = 2; delete template.html_master_json!.signing_page;
  state.actions.adopt(template);
  state.actions.changeSigningPage({ currentTarget: { checked: true } });
  expect(state.env.draft.schema_version).toBe(3); expect(state.env.draft.signing_page).toEqual(blankHTMLSigningPage());
  expect(state.env.dirty).toBe(true); expect(state.env.saved.html_master_json.schema_version).toBe(2);
  state.env.draft.assets.push({ name: 'company_logo', media_type: 'image/png', sha256: 'f'.repeat(64), data_base64: 'AA==' });
  state.actions.changeSigningLogo({ currentTarget: { value: 'company_logo' } });
  expect(state.env.draft.signing_page.logo_sha256).toBe('f'.repeat(64));
  state.actions.changeSigningLogo({ currentTarget: { value: '' } });
  expect([state.env.draft.signing_page.logo_asset, state.env.draft.signing_page.logo_sha256, state.env.draft.signing_page.logo_alt]).toEqual(['', '', '']);
  const toggle = { currentTarget: { checked: false } }; state.actions.changeSigningPage(toggle);
  expect(toggle.currentTarget.checked).toBe(true); expect(state.env.draft.schema_version).toBe(3);
  state.env.window.confirm = () => true; state.actions.changeSigningPage({ currentTarget: { checked: false } });
  expect(state.env.draft.schema_version).toBe(2); expect(state.env.draft.signing_page).toBeNull();
});
test('combined page preview can sample a blank essential section without editing the approved default and still needs every page', async () => {
  const state = fixture(), template = signingPageTemplateFixture(); template.id = templateID; template.org_id = orgID;
  template.html_approval = { version: template.version, content_sha256: template.content_sha256! };
  template.html_master_json!.sections![0].default_text = '';
  state.actions.adopt(template);
  await state.actions.generatePreview(); expect(state.calls).toEqual([]); expect(state.env.error).toContain('scope');
  state.env.sectionSamples.scope_text = 'Synthetic owner-preview scope only';
  const pending = state.actions.generatePreview();
  expect(state.calls[0].args[5]).toEqual({ scope_text: 'Synthetic owner-preview scope only' });
  expect(state.env.saved.html_master_json.sections[0].default_text).toBe('');
  state.calls[0].resolve(preview()); await pending;
  state.actions.receiveProof({ key: state.env.previewKey, allPagesSeen: false }); state.env.acknowledged = true;
  await state.actions.approve(); expect(state.calls).toHaveLength(1);
  state.actions.receiveProof({ key: state.env.previewKey, allPagesSeen: true }); state.env.acknowledged = true;
  const approving = state.actions.approve();
  expect(state.calls[1].kind).toBe('approve');
  const approved = { ...template, html_approval: { ...template.html_approval, approved_by: userID, approved_at: new Date().toISOString() } };
  state.calls[1].resolve({ template_id: templateID, version: template.version, content_sha256: template.content_sha256, approved_by: userID, approved_at: approved.html_approval.approved_at });
  await step(); state.calls[2].resolve(approved); await approving;
  expect(state.env.approved).toBe(true); expect(state.env.saved.html_master_json.sections[0].default_text).toBe('');
});
test('late preview is discarded on source/sample/file/actor/pin/navigation change', async () => {
  for (const mode of ['source', 'sample', 'section', 'file', 'actor', 'pin', 'route', 'abort']) {
    const state = fixture(), pending = state.actions.generatePreview();
    if (mode === 'source') state.env.draft.name = 'Unsaved';
    if (mode === 'sample') state.env.samples.company = 'Different sample';
    if (mode === 'section') state.env.sectionSamples.scope = 'Different preview wording';
    if (mode === 'file') state.env.pendingAssetFile = new File(['x'], 'pending.png');
    if (mode === 'actor') state.env.me = { ...owner, user_id: '55555555-5555-4555-8555-555555555555' };
    if (mode === 'pin') state.env.saved = design(4);
    if (mode === 'route') state.env.disposed = true;
    if (mode === 'abort') state.env.previewAbort.abort();
    state.calls[0].resolve(preview()); await pending; expect(state.env.preview).toBeNull();
  }
});
test('approval requires owner, matching unexpired preview, completed pages and explicit acknowledgement', async () => {
  for (const mode of ['sender', 'pages', 'ack', 'sample', 'source', 'expiry', 'pin', 'actor']) {
    const state = fixture(); installPreview(state);
    if (mode === 'sender') state.env.me.role = 'sender';
    if (mode === 'pages') state.env.allPagesSeen = false;
    if (mode === 'ack') state.env.acknowledged = false;
    if (mode === 'sample') state.env.samples.company = 'Changed';
    if (mode === 'source') state.env.draft.name = 'Changed';
    if (mode === 'expiry') state.env.preview.expiresAt = new Date(0).toISOString();
    if (mode === 'pin') state.env.saved = design(4);
    if (mode === 'actor') state.env.previewActor = 'other-owner';
    await state.actions.approve(); expect(state.calls).toEqual([]);
  }
  const state = fixture(); installPreview(state);
  const pending = state.actions.approve(); await state.actions.approve(); expect(state.calls).toHaveLength(1);
  expect(state.calls[0].args).toEqual([templateID, 3, 'a'.repeat(64), state.env.preview]);
  const approved = { ...design(), html_approval: { ...design().html_approval, approved_by: userID, approved_at: new Date().toISOString() } };
  state.calls[0].resolve({ template_id: templateID, version: 3, content_sha256: 'a'.repeat(64), approved_by: userID, approved_at: approved.html_approval.approved_at });
  await step(); state.calls[1].resolve(approved); await pending;
  expect(state.env.approved).toBe(true); expect(state.env.acknowledged).toBe(false); expect(state.env.samples.company).toBe('Preview sample');
});
test('approval readback failure blocks blind retry and mismatched page proof never enables approval', async () => {
  const state = fixture(); installPreview(state);
  state.actions.receiveProof({ key: 'older-preview', allPagesSeen: false }); expect(state.env.allPagesSeen).toBe(true);
  state.actions.receiveProof({ key: state.env.previewKey, allPagesSeen: false }); expect(state.env.acknowledged).toBe(false);
  state.actions.receiveProof({ key: state.env.previewKey, allPagesSeen: true }); state.env.acknowledged = true;
  const pending = state.actions.approve(); state.calls[0].resolve({ template_id: templateID, version: 3, content_sha256: 'a'.repeat(64), approved_by: userID, approved_at: new Date().toISOString() });
  await step(); state.calls[1].reject(new APIError(401, 'Expired')); await pending;
  expect(state.env.writeUncertain).toBe(true); expect(state.env.preview).toBeNull(); expect(state.env.me).toBeNull();
  await state.actions.approve(); expect(state.calls).toHaveLength(2);
});
test('pending local file/name prevents save/preview and participates in navigation/unload/adoption prompts', async () => {
  for (const mode of ['name', 'file']) {
    const state = fixture(); if (mode === 'name') state.env.assetName = 'pending_logo'; else state.env.pendingAssetFile = new File(['x'], 'pending.png');
    state.env.sampleBaseline = JSON.stringify({ values: state.env.samples, sections: state.env.sectionSamples });
    await state.actions.save(event); await state.actions.generatePreview(); expect(state.calls).toEqual([]);
    let canceled = 0;
    state.actions.protectNavigation({ cancel() { canceled++; }, willUnload: false,
      from: { url: new URL('https://hash.invalid/templates/current/html') }, to: { url: new URL('https://hash.invalid/templates') } });
    expect(canceled).toBe(1);
    const unload = { preventDefault() { canceled++; }, returnValue: 'unset' }; state.actions.protectUnload(unload);
    expect(canceled).toBe(2); expect(unload.returnValue).toBe('');
    state.env.latest = design(4); state.actions.adoptLatest(); expect(state.env.saved.version).toBe(3);
    state.env.window.confirm = () => true; state.actions.adoptLatest(); expect(state.env.assetName).toBe(''); expect(state.env.pendingAssetFile).toBeNull();
  }
});
test('late save/read responses cannot adopt into a disposed route or changed organisation', async () => {
  const state = fixture(false), pending = state.actions.save(event); state.env.disposed = true;
  state.calls[0].resolve(design(1)); await pending; expect(state.env.knownID).toBeNull(); expect(state.calls).toHaveLength(1);
  const refresh = fixture(), reading = refresh.actions.readLatest(); refresh.calls[0].resolve(owner); await step(); refresh.env.disposed = true;
  refresh.calls[1].resolve(design(4)); await reading; expect(refresh.env.latest).toBeNull(); expect(refresh.env.saved.version).toBe(3);
});
