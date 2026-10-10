import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../api/client';
import { htmlProfileIssues, htmlProfileSectionValues, htmlTemplateFields, htmlValuesForSubmission } from '../htmlTemplate';
import { contractTemplateFixture } from '../htmlTemplate.test';

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
function bind(file: string, names: string[], env: any) {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8');
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(names.map((name) => callback(source, name)).join('\n'));
  return new Function('env', `with(env) { ${code}; return { ${names.join(',')} }; }`)(env);
}
const event = { preventDefault() {} };
function design(version = 3) {
  return { id: 'design', org_id: 'org', name: 'Design', source_kind: 'html', version, content_sha256: 'a'.repeat(64),
    variables_json: { customer: 'Approved default' }, html_master_json: { schema_version: 1, html: '<p></p>', css: '',
      values: [{ name: 'customer', required: true, max_chars: 200 }] },
    html_approval: { version, content_sha256: 'a'.repeat(64), approved_by: 'owner', approved_at: '2026-10-10T04:00:00Z' } };
}
function populateFixture() {
  const calls: any[] = [], created: any[] = [];
  const template = design();
  const env: any = { template, sourceID: 'design', sourceOrg: 'org', design: template, pendingDesign: null,
    fields: htmlTemplateFields(template as any), values: { customer: 'Typed <AB> & Co' }, name: 'Typed draft name',
    sections: {}, sectionDefinitions: [],
    approved: true, loading: false, busy: false, navigating: false, createdDocument: null, creationUncertain: false,
    disposed: false, readRevision: 0, error: null, needsRefresh: false, dirty: true,
    current: () => !env.disposed && env.template.id === env.sourceID,
    htmlTemplateFields, htmlValuesForSubmission, htmlProfileSectionValues, APIError,
    getTemplate: (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind: 'get', args, resolve, reject })),
    createHTMLTemplateDocument: (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind: 'create', args, resolve, reject })),
    onCreated: (doc: any) => created.push(doc), onDirtyChange: () => {}, onBusyChange: () => {},
    window: { confirm: () => false },
  };
  Object.defineProperty(env, 'profileIssues', { get: () => env.design.html_master_json?.contract_profile ? htmlProfileIssues(env.design.html_master_json.contract_profile, env.values, env.sections) : [] });
  return { env, calls, created, actions: bind('./HtmlTemplatePopulate.svelte', ['adoptDesign', 'refreshDesign', 'useUpdatedDesign', 'create', 'openCreatedDocument', 'protectNavigation'], env) };
}

test('contract populate rejects conflicting printed representative identities before creation without dispatching recipient edits', async () => {
  for (const conflict of ['email', 'company', 'authority']) {
    const state = populateFixture(), template = contractTemplateFixture();
    state.env.design = template; state.env.fields = htmlTemplateFields(template); state.env.values = { ...(template.variables_json as Record<string, string>) };
    state.env.sections = { scope_text: 'Reviewed scope.' };
    if (conflict === 'email') state.env.values.customer_representative_email = state.env.values.provider_representative_email;
    if (conflict === 'company') state.env.values.customer_company_id = state.env.values.provider_company_id;
    if (conflict === 'authority') state.env.values.customer_representative_authority = ' ';
    const entered = JSON.stringify(state.env.values);
    await state.actions.create(event);
    expect(state.calls).toEqual([]); expect(JSON.stringify(state.env.values)).toBe(entered); expect(state.env.error).toBeTruthy();
  }
});

test('human populated essential section uses its declaration key, accepts blank default with explicit text, and blocks blank or stale drafts', async () => {
  const state = populateFixture(), template = contractTemplateFixture(); template.html_master_json!.sections![0].default_text = '';
  state.actions.adoptDesign(template); state.env.sections.scope_text = 'Explicit human-proposed service scope.';
  const pending = state.actions.create(event); expect(state.calls[0].args[1].sections).toEqual({ scope_text: 'Explicit human-proposed service scope.' });
  expect(state.calls[0].args[1].sections.scope).toBeUndefined(); state.calls[0].reject(new APIError(400, 'Stopped for protocol test')); await pending;
  const entered = state.env.sections.scope_text; state.env.needsRefresh = true; await state.actions.create(event); expect(state.calls).toHaveLength(1); expect(state.env.sections.scope_text).toBe(entered);
  state.env.needsRefresh = false; state.env.sections.scope_text = ' '; await state.actions.create(event); expect(state.calls).toHaveLength(1); expect(state.env.error).toContain('scope');
});
function createdResult() {
  return { document: { id: 'doc', org_id: 'org', template_id: 'design', source_kind: 'pdf', has_html_source: true,
    html_review_required: true, status: 'draft' }, page_count: 1, review_required: true };
}

test('populate dispatches once with exact approved pin, preserves form on conflict, and never automatically adopts a changed revision', async () => {
  const state = populateFixture();
  const pending = state.actions.create(event); await state.actions.create(event);
  expect(state.calls).toHaveLength(1);
  expect(state.calls[0].args).toEqual(['design', { name: 'Typed draft name', expected_template_version: 3,
    expected_template_content_sha256: 'a'.repeat(64), values: { customer: 'Typed <AB> & Co' } }]);
  state.calls[0].reject(new APIError(409, 'Design changed')); await pending;
  expect(state.env.values).toEqual({ customer: 'Typed <AB> & Co' }); expect(state.env.name).toBe('Typed draft name');
  expect(state.env.needsRefresh).toBe(true); expect(state.env.busy).toBe(false); expect(state.created).toEqual([]);
  await state.actions.create(event); expect(state.calls).toHaveLength(1);
  const refreshing = state.actions.refreshDesign(); state.calls[1].resolve(design(4)); await refreshing;
  expect(state.env.design.version).toBe(3); expect(state.env.pendingDesign.version).toBe(4);
  state.actions.useUpdatedDesign(); expect(state.env.design.version).toBe(4); expect(state.env.values.customer).toBe('Typed <AB> & Co');
});

test('populate refuses missing values or unapproved state and preserves input on renderer/service failure', async () => {
  for (const mode of ['blank', 'unapproved']) {
    const state = populateFixture();
    if (mode === 'blank') state.env.values.customer = '  '; else state.env.approved = false;
    await state.actions.create(event); expect(state.calls).toEqual([]);
  }
  const state = populateFixture(); const pending = state.actions.create(event);
  state.calls[0].reject(new APIError(503, 'Renderer unavailable')); await pending;
  expect(state.env.values.customer).toBe('Typed <AB> & Co'); expect(state.env.name).toBe('Typed draft name');
  expect(state.env.needsRefresh).toBe(false); expect(state.created).toEqual([]);
  expect(state.env.creationUncertain).toBe(true);
});

test('accepted creation with failed navigation retains the draft and retries opening without a second POST', async () => {
  const state = populateFixture();
  state.env.onCreated = async () => { throw new Error('Navigation unavailable'); };
  const pending = state.actions.create(event); state.calls[0].resolve(createdResult()); await pending;
  expect(state.env.createdDocument.id).toBe('doc');
  expect(state.env.error).toContain('The draft was created');
  expect(state.env.values.customer).toBe('Typed <AB> & Co');
  expect(state.env.name).toBe('Typed draft name');
  await state.actions.create(event); expect(state.calls).toHaveLength(1);
  state.env.onCreated = (doc: any) => state.created.push(doc);
  await state.actions.openCreatedDocument();
  expect(state.created.map((doc) => doc.id)).toEqual(['doc']); expect(state.calls).toHaveLength(1);
});

test('pending user navigation is confirmed while the deliberate created-document transition is permitted', async () => {
  const state = populateFixture(); state.env.busy = true;
  let canceled = 0;
  const navigation = (path: string) => ({ cancel: () => canceled++, willUnload: false,
    from: { url: new URL('https://hash.invalid/templates') }, to: { url: new URL(`https://hash.invalid${path}`) } });
  state.actions.protectNavigation(navigation('/documents')); expect(canceled).toBe(1);
  state.env.window.confirm = () => true;
  state.actions.protectNavigation(navigation('/documents')); expect(canceled).toBe(1);
  state.env.window.confirm = () => false; state.env.busy = false; state.env.navigating = true;
  state.env.createdDocument = createdResult().document;
  state.actions.protectNavigation(navigation('/documents/doc')); expect(canceled).toBe(1);
  state.actions.protectNavigation(navigation('/documents/other')); expect(canceled).toBe(2);
});

test('revision adoption retains removed values for copying but dispatches only currently declared values', async () => {
  const state = populateFixture(); const revised = design(4);
  revised.html_master_json.values = [{ name: 'contact', required: true, max_chars: 200 }];
  revised.variables_json = { contact: 'New approved default' } as any;
  state.env.pendingDesign = revised; state.actions.useUpdatedDesign();
  expect(state.env.values).toEqual({ customer: 'Typed <AB> & Co', contact: 'New approved default' });
  const pending = state.actions.create(event);
  expect(state.calls[0].args[1].values).toEqual({ contact: 'New approved default' });
  state.calls[0].reject(new APIError(400, 'Refused')); await pending;
  expect(state.env.values.customer).toBe('Typed <AB> & Co');
});

test('explicit refreshed design adopts new defaults only where the previous approved default was untouched', () => {
  for (const edited of [false, true]) {
    const state = populateFixture();
    state.env.values.customer = edited ? 'Edited company name' : 'Approved default';
    const revised = design(4); revised.variables_json.customer = 'New approved company default';
    state.env.pendingDesign = revised; state.actions.useUpdatedDesign();
    expect(state.env.values.customer).toBe(edited ? 'Edited company name' : 'New approved company default');
    expect(state.env.design.version).toBe(4); expect(state.env.needsRefresh).toBe(false);
  }
});

test('unknown creation outcomes preserve values and block an unqualified repeat POST', async () => {
  for (const error of [new TypeError('Network unavailable'), new APIError(500, 'Server error'), new APIError(502, 'Gateway error'), new APIError(503, 'Please try again in a moment'), new APIError(504, 'Timeout')]) {
    const state = populateFixture(); const pending = state.actions.create(event);
    state.calls[0].reject(error); await pending;
    expect(state.env.creationUncertain).toBe(true); expect(state.env.values.customer).toBe('Typed <AB> & Co');
    expect(state.env.name).toBe('Typed draft name');
    expect(state.env.error).toContain('Check the document library');
    expect(state.env.error).toContain('Your entered values are preserved');
    expect(state.env.error).not.toContain('try again');
    await state.actions.create(event); expect(state.calls).toHaveLength(1);
  }
});

test('late design read or creation cannot affect a new selection or disposed route', async () => {
  const reading = populateFixture(); const pendingRead = reading.actions.refreshDesign();
  reading.env.template = { ...design(), id: 'other' }; reading.env.error = 'Current selection error';
  reading.calls[0].resolve(design(4)); await pendingRead;
  expect(reading.env.design.version).toBe(3); expect(reading.env.error).toBe('Current selection error');
  const state = populateFixture(); const pending = state.actions.create(event); state.env.disposed = true;
  state.calls[0].resolve({ document: { id: 'doc', org_id: 'org', template_id: 'design', source_kind: 'pdf', has_html_source: true,
    html_review_required: true, status: 'draft' }, page_count: 1, review_required: true }); await pending;
  expect(state.created).toEqual([]);
});

function reviewFixture() {
  const calls: any[] = [], reviewed: any[] = [];
  const env: any = { document: { id: 'doc', org_id: 'org', source_kind: 'pdf', has_html_source: true, html_review_required: true,
      updated_at: 'observed', pdf_sha256: 'a'.repeat(64), status: 'draft' }, sourceID: 'doc', sourceStamp: 'observed', sourceSHA: 'a'.repeat(64), sourceCommitment: '',
    disposed: false, canReview: true, revisionBlocked: false, loading: false, rendering: false, busy: false, error: null, activePDF: {}, allPagesSeen: true, acknowledged: true,
    current: () => !env.disposed && env.document.id === env.sourceID && env.document.updated_at === env.sourceStamp && env.document.pdf_sha256 === env.sourceSHA,
    reviewHTMLDocument: (...args: any[]) => new Promise((resolve, reject) => calls.push({ args, resolve, reject })),
    onReviewed: (doc: any) => reviewed.push(doc) };
  return { env, calls, reviewed, actions: bind('./HtmlPDFReview.svelte', ['approve'], env) };
}

test('manual review requires rendered pages, permission and acknowledgement, dispatches once and pins the observed PDF', async () => {
  for (const flag of ['canReview', 'activePDF', 'allPagesSeen', 'acknowledged']) {
    const state = reviewFixture(); state.env[flag] = false; await state.actions.approve(); expect(state.calls).toEqual([]);
  }
  const state = reviewFixture(); const pending = state.actions.approve(); await state.actions.approve();
  expect(state.calls).toHaveLength(1); expect(state.calls[0].args).toEqual(['doc', 'observed', 'a'.repeat(64)]);
  state.calls[0].resolve({ ...state.env.document, updated_at: 'reviewed', html_review_required: false }); await pending;
  expect(state.reviewed).toHaveLength(1);
});

test('stale review responses and mismatched PDF confirmations never approve the current document', async () => {
  for (const mode of ['route', 'digest', 'still pending']) {
    const state = reviewFixture(); const pending = state.actions.approve();
    if (mode === 'route') state.env.document = { ...state.env.document, id: 'other' };
    state.calls[0].resolve({ ...state.env.document, html_review_required: mode === 'still pending',
      pdf_sha256: mode === 'digest' ? 'b'.repeat(64) : 'a'.repeat(64) }); await pending;
    expect(state.reviewed).toEqual([]);
  }
  const state = reviewFixture(); const pending = state.actions.approve();
  state.calls[0].reject(new APIError(409, 'Document changed')); await pending;
  expect(state.env.acknowledged).toBe(false); expect(state.env.error).toBe('Document changed');
});

test('library selection sends an HTML design to its form without calling generic document creation', async () => {
  const calls: any[] = [];
  const env: any = { creatingId: null, selectedHTMLTemplate: null, htmlFormDirty: false, selectedTemplate: null, error: null,
    createDocumentFromTemplate: (...args: any[]) => calls.push(args) };
  const actions = bind('../../routes/templates/+page.svelte', ['useTemplate'], env);
  await actions.useTemplate(design()); expect(env.selectedHTMLTemplate.id).toBe('design'); expect(calls).toEqual([]);
});
