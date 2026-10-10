import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../api/client';
import { htmlProfileIssues, htmlProfileSectionValues, htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate } from '../htmlTemplate';
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
  const calls: any[] = [], template = design();
  const env: any = { template, sourceID: 'design', sourceOrg: 'org', design: template, pendingDesign: null,
    fields: htmlTemplateFields(template as any), values: { customer: 'Typed <AB> & Co' }, name: 'Typed draft name',
    sections: {}, sectionDefinitions: [], proposed: {}, populationState: { mappings: [], observation: null },
    approved: true, loading: false, busy: false, navigating: false, createdDocument: null, creationUncertain: false, markerError: false, clock: 0,
    disposed: false, readRevision: 0, error: null, needsRefresh: false, dirty: true,
    current: () => !env.disposed && env.template.id === env.sourceID,
    htmlTemplateFields, htmlValuesForSubmission, htmlProfileSectionValues, isApprovedHTMLTemplate,
    getTemplate: (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind: 'get', args, resolve, reject })),
    window: { confirm: () => false },
  };
  env.controller = {
    canCreate: () => true, effectiveValues: () => ({ ...env.values, ...env.proposed }),
    create: async () => { calls.push({ kind: 'create', candidate: env.actions.candidate() }); },
    invalidate: () => { calls.push({ kind: 'invalidate' }); }, inputChanged: () => { env.populationState.confirmation = ''; calls.push({ kind: 'invalidate-input' }); },
    setTemplate: (t: any) => { calls.push({ kind: 'adopt', template: t }); }, load: async () => {}, openCreated: async () => { calls.push({ kind: 'open' }); },
    observationFresh: () => true,
  };
  Object.defineProperty(env, 'profileIssues', { get: () => env.design.html_master_json?.contract_profile
    ? htmlProfileIssues(env.design.html_master_json.contract_profile, env.controller.effectiveValues(), env.sections) : [] });
  env.actions = bind('./HtmlTemplatePopulate.svelte', ['candidate', 'inputChanged', 'mappedRequiredFilled', 'adoptDesign', 'refreshDesign', 'useUpdatedDesign', 'create', 'openCreatedDocument', 'protectNavigation', 'close'], env);
  return { env, calls, actions: env.actions };
}
test('contract populate retains conflicting printed identities and refuses creation before delegating to the request controller', async () => {
  for (const conflict of ['email', 'company', 'authority']) {
    const s = populateFixture(), t = contractTemplateFixture();
    s.env.design = t; s.env.fields = htmlTemplateFields(t); s.env.values = { ...(t.variables_json as Record<string, string>) }; s.env.sections = { scope_text: 'Reviewed scope.' };
    if (conflict === 'email') s.env.values.customer_representative_email = s.env.values.provider_representative_email;
    if (conflict === 'company') s.env.values.customer_company_id = s.env.values.provider_company_id;
    if (conflict === 'authority') s.env.values.customer_representative_authority = ' ';
    const entered = structuredClone(s.env.values); await s.actions.create(event);
    expect(s.calls).toEqual([]); expect(s.env.values).toEqual(entered); expect(s.env.error).toBeTruthy();
  }
});
test('essential wording uses its declared section key, permits preview-only blank input, and is required for creation', async () => {
  const s = populateFixture(), t = contractTemplateFixture(); t.html_master_json!.sections![0].default_text = '';
  s.actions.adoptDesign(t); s.calls.length = 0;
  expect(s.actions.candidate().sections).toEqual({ scope_text: '' });
  s.env.sections.scope_text = 'Explicit human-proposed service scope.'; await s.actions.create(event);
  expect(s.calls[0].candidate.sections).toEqual({ scope_text: 'Explicit human-proposed service scope.' }); expect(s.calls[0].candidate.sections.scope).toBeUndefined();
  s.env.sections.scope_text = ' '; await s.actions.create(event); expect(s.calls).toHaveLength(1); expect(s.env.error).toContain('scope');
  s.env.needsRefresh = true; s.env.sections.scope_text = 'Preserved prose'; await s.actions.create(event); expect(s.calls).toHaveLength(1);
});
test('required CRM-filled field passes effective preflight while raw manual candidate remains unchanged', async () => {
  const s = populateFixture(); s.env.values.customer = ''; s.env.proposed.customer = 'Observed customer';
  s.env.populationState = { mappings: [{ variable: 'customer' }], observation: { items: [{ variable: 'customer', available: true, value: 'Observed customer' }] } };
  expect(s.actions.mappedRequiredFilled(s.env.fields[0])).toBe(true); await s.actions.create(event);
  expect(s.calls[0].candidate.values.customer).toBe(''); expect(s.env.values.customer).toBe('');
  s.env.proposed = {}; await s.actions.create(event); expect(s.calls).toHaveLength(1); expect(s.env.error).toContain('required');
  s.env.controller.observationFresh = () => false; expect(s.actions.mappedRequiredFilled(s.env.fields[0])).toBe(false);
});
test('pending request and marker errors fence create, refresh, close and explicit design changes even when ordinary dirty=false', async () => {
  for (const guard of ['creationUncertain', 'markerError']) {
    const s = populateFixture(); s.env[guard] = true; s.env.dirty = false; s.env.pendingDesign = design(4); s.env.onClose = () => s.calls.push({ kind: 'close' });
    await s.actions.create(event); await s.actions.refreshDesign(); s.actions.useUpdatedDesign(); s.actions.close();
    expect(s.calls).toEqual([]); expect(s.env.design.version).toBe(3); expect(s.env.values.customer).toBe('Typed <AB> & Co');
  }
});
test('explicit design adoption preserves touched and removed entries, adopts untouched defaults, and invalidates CRM review', async () => {
  for (const edited of [false, true]) {
    const s = populateFixture(); s.env.values.customer = edited ? 'Edited company name' : 'Approved default';
    const revised = design(4); revised.variables_json.customer = 'New approved company default'; s.env.pendingDesign = revised; s.actions.useUpdatedDesign();
    expect(s.env.values.customer).toBe(edited ? 'Edited company name' : 'New approved company default'); expect(s.calls[0].kind).toBe('adopt');
  }
  const s = populateFixture(), revised = design(4); revised.html_master_json.values = [{ name: 'contact', required: true, max_chars: 200 }]; revised.variables_json = { contact: 'New default' } as any;
  s.env.pendingDesign = revised; s.actions.useUpdatedDesign(); s.calls.length = 0; await s.actions.create(event);
  expect(s.env.values.customer).toBe('Typed <AB> & Co'); expect(s.calls[0].candidate.values).toEqual({ contact: 'New default' });
});
test('refresh retains newer revision for explicit adoption, and late source reads cannot affect another selection', async () => {
  const s = populateFixture(); const reading = s.actions.refreshDesign(); const call = s.calls.find((c: any) => c.kind === 'get'); call.resolve(design(4)); await reading;
  expect(s.env.design.version).toBe(3); expect(s.env.pendingDesign.version).toBe(4); expect(s.env.values.customer).toBe('Typed <AB> & Co');
  const late = populateFixture(), pending = late.actions.refreshDesign(); late.env.template = { ...design(), id: 'other' }; late.env.error = 'Current selection error';
  late.calls.find((c: any) => c.kind === 'get').resolve(design(4)); await pending; expect(late.env.error).toBe('Current selection error'); expect(late.env.design.version).toBe(3);
});
test('input changes invalidate confirmation synchronously and canceled navigation does not cancel the ongoing operation', () => {
  const s = populateFixture(); s.env.populationState.confirmation = 'old'; s.actions.inputChanged(); expect(s.env.populationState.confirmation).toBe('');
  s.calls.length = 0; s.env.creationUncertain = true; s.env.dirty = false; let canceled = 0;
  const navigation = (path: string) => ({ cancel: () => canceled++, willUnload: false, from: { url: new URL('https://hash.invalid/templates') }, to: { url: new URL('https://hash.invalid' + path) } });
  s.actions.protectNavigation(navigation('/documents')); expect(canceled).toBe(1); expect(s.calls).toEqual([]);
  s.env.window.confirm = () => true; s.actions.protectNavigation(navigation('/documents')); expect(s.calls[0].kind).toBe('invalidate');
  s.calls.length = 0; s.env.window.confirm = () => false; s.env.navigating = true; s.env.createdDocument = { id: 'created' };
  s.actions.protectNavigation(navigation('/documents/created')); expect(canceled).toBe(1); expect(s.calls).toEqual([]);
});

function reviewFixture() {
  const calls: any[] = [], reviewed: any[] = [];
  const env: any = { document: { id: 'doc', org_id: 'org', source_kind: 'pdf', has_html_source: true, html_review_required: true,
      updated_at: 'observed', pdf_sha256: 'a'.repeat(64), status: 'draft' }, sourceID: 'doc', sourceStamp: 'observed', sourceSHA: 'a'.repeat(64), sourceCommitment: '',
    disposed: false, canReview: true, revisionBlocked: false, loading: false, rendering: false, busy: false, error: null, activePDF: {}, allPagesSeen: true, pageCountMatches: true, acknowledged: true,
    current: () => !env.disposed && env.document.id === env.sourceID && env.document.updated_at === env.sourceStamp && env.document.pdf_sha256 === env.sourceSHA,
    reviewHTMLDocument: (...args: any[]) => new Promise((resolve, reject) => calls.push({ args, resolve, reject })),
    onReviewed: (doc: any) => reviewed.push(doc) };
  return { env, calls, reviewed, actions: bind('./HtmlPDFReview.svelte', ['approve'], env) };
}

test('manual review requires rendered pages, matching retained page count, permission and acknowledgement, dispatches once and pins the observed PDF', async () => {
  for (const flag of ['canReview', 'activePDF', 'allPagesSeen', 'pageCountMatches', 'acknowledged']) {
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
  const env: any = { pendingCreation: false, creatingId: null, selectedHTMLTemplate: null, htmlFormDirty: false, selectedTemplate: null, error: null,
    createDocumentFromTemplate: (...args: any[]) => calls.push(args) };
  const actions = bind('../../routes/templates/+page.svelte', ['useTemplate'], env);
  await actions.useTemplate(design()); expect(env.selectedHTMLTemplate.id).toBe('design'); expect(calls).toEqual([]);
});
