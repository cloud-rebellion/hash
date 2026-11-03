import { expect, test } from 'bun:test';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile, parse } from 'svelte/compiler';
import { documentPurpose, requireDocumentPurpose, purposeLabel, blockTemplateNeedsSigning } from '../documentPurpose';
import { isCanonicalSignatureRole } from './BlockEditor/transform';

function bind(file: string, names: string[], env: any) {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8');
  const ast: any = parse(source, { modern: true });
  const declarations = ast.instance.content.body.flatMap((node: any) => node.type === 'ExportNamedDeclaration' ? [node.declaration] : [node]);
  const functions = names.map(name => { const node = declarations.find((node: any) => node.type === 'FunctionDeclaration' && node.id?.name === name); if (!node) throw Error('Actual callback missing: ' + name); return source.slice(node.start, node.end).replace(/^export /, ''); });
  return new Function('env', `with(env) { ${new Bun.Transpiler({ loader: 'ts' }).transformSync(functions.join('\n'))}; return { ${names.join(',')} }; }`)(env);
}
const event = { preventDefault() {} };
function componentGuard(file: string, component: string, attribute: string): (env: any) => boolean {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8'), ast: any = parse(source, { modern: true }); let expression: any;
  const visit = (node: any) => {
    if (!node || typeof node !== 'object' || expression) return;
    if (node.name === component && Array.isArray(node.attributes)) {
      const value = node.attributes.find((item: any) => item.name === attribute)?.value;
      expression = (Array.isArray(value) ? value.find((item: any) => item.type === 'ExpressionTag') : value)?.expression;
    }
    if (!expression) for (const value of Object.values(node)) { if (Array.isArray(value)) value.forEach(visit); else if (value && typeof value === 'object') visit(value); }
  };
  visit(ast.fragment); if (!expression) throw Error('Actual component guard missing');
  return new Function('env', `with(env) { return !!(${source.slice(expression.start, expression.end)}); }`) as (env: any) => boolean;
}
test('coherent download guard distinguishes readonly saved content from dirty editors and preserves unknown purpose fences', () => {
  const blocked = componentGuard('../../routes/documents/[id]/+page.svelte', 'DocumentDownload', 'blocked');
  const env: any = { doc: { status: 'draft', source_kind: 'blocks', has_html_source: false }, savedPurpose: null, blocksEditorClean: false, htmlEditorClean: false, changingPurpose: false, purposeUnconfirmed: false, senderMutationBusy: false, pdfLayoutBusy: false, pdfLayoutDirty: false, crmBusy: false, attachmentBusy: false, revising: false, supersessionBusy: false };
  expect(blocked(env)).toBe(false); env.savedPurpose = 'document'; expect(blocked(env)).toBe(true); env.blocksEditorClean = true; expect(blocked(env)).toBe(false);
  env.savedPurpose = null; for (const field of ['changingPurpose', 'purposeUnconfirmed', 'senderMutationBusy', 'pdfLayoutDirty']) { env[field] = true; expect(blocked(env)).toBe(true); env[field] = false; }
});
test('coherent library destructive controls share unknown creation and existing removal ownership barriers', () => {
  const template = componentGuard('../../routes/templates/+page.svelte', 'LibraryRemovalAction', 'disabled');
  const env: any = { t: { id: 'template' }, removalBusy: false, templateCreationUnconfirmed: false, pendingCreation: false, creatingId: null, uploading: false, seeding: null, selectedTemplate: null, selectedHTMLTemplate: null };
  expect(template(env)).toBe(false); for (const key of ['templateCreationUnconfirmed', 'removalBusy', 'pendingCreation']) { env[key] = true; expect(template(env)).toBe(true); env[key] = false; }
  const document = componentGuard('../../routes/documents/+page.svelte', 'LibraryRemovalAction', 'disabled'); expect(document({ busy: false, creationUnconfirmed: true })).toBe(true); expect(document({ busy: false, creationUnconfirmed: false })).toBe(false);
});
test('actual block-editor signature insertion refuses non-signing documents before a prompt or editor mutation', () => {
  for (const [enabled, busy] of [[false, false], [true, true], [true, false]]) {
    const inserted: unknown[] = []; let prompts = 0;
    const chain: any = { focus: () => chain, insertContent: (value: unknown) => { inserted.push(value); return chain; }, run: () => true };
    const env: any = { signingFieldsEnabled: enabled, externalBusy: busy, error: null, isCanonicalSignatureRole, window: { prompt: () => ++prompts === 1 ? 'signer' : 'Signature' }, editor: { chain: () => chain } };
    bind('./BlockEditor/Editor.svelte', ['insertSignatureField'], env).insertSignatureField();
    expect(prompts).toBe(enabled && !busy ? 2 : 0);
    expect(inserted).toEqual(enabled && !busy ? [{ type: 'signatureField', attrs: { blockId: '', recipientRole: 'signer', label: 'Signature', required: true } }] : []);
  }
});
test('actual page-size handlers change presentation only and refuse resizing an active placement or uncertain view', () => {
  const geometry = [{ num: 1, w: 760, h: 1074, scale: 1.2 }], env: any = { fitPage: true, current: () => true, paintDocumentID: 'A', pages: geometry, saving: false, loading: false, refreshingRecipients: false, draft: null, error: null };
  const designer = bind('./PdfFieldDesigner.svelte', ['setPageFit'], env).setPageFit;
  designer(false); expect(env.fitPage).toBe(false); expect(env.pages).toBe(geometry); expect(geometry[0]).toEqual({ num: 1, w: 760, h: 1074, scale: 1.2 });
  env.draft = { page: 1 }; designer(true); expect(env.fitPage).toBe(false); env.draft = null; env.error = 'unconfirmed write'; designer(true); expect(env.fitPage).toBe(false);
  const viewerEnv: any = { fitPage: true, current: () => true, loading: false, rendering: false, error: null };
  const viewer = bind('./VerifiedPDFPages.svelte', ['setPageFit'], viewerEnv).setPageFit; viewer(false); expect(viewerEnv.fitPage).toBe(false); viewerEnv.rendering = true; viewer(true); expect(viewerEnv.fitPage).toBe(false);
});
test('missing-recipient placement remains a recoverable notice and tools can be selected without a request', () => {
  const env: any = { activePage: 1, current: () => true, documentID: 'A', pageResidency: { pageReady: () => true }, pages: [{ num: 1, w: 760, h: 1000 }],
    readonly: false, generated: false, saving: false, loading: false, rendered: true, refreshingRecipients: false, recipientRefreshError: null, error: null,
    tool: 'signature', recipientID: '', notice: null, draft: null, dragStart: null, TOOLS: [{ type: 'signature' }, { type: 'text' }] };
  Object.defineProperty(env, 'placementUnavailable', { get: () => !!env.error || env.saving || env.loading || !env.rendered });
  const actions = bind('./PdfFieldDesigner.svelte', ['onPointerDown', 'chooseTool', 'pctFromEvent'], env);
  const pointer = { isPrimary: true, button: 0, pointerId: 1, clientX: 10, clientY: 10 };
  const layer = { getBoundingClientRect: () => ({ left: 0, top: 0, width: 100, height: 100 }), setPointerCapture() {} };
  actions.onPointerDown(pointer, 1, layer); expect(env.error).toBeNull(); expect(env.notice).toContain('recipient'); expect(env.draft).toBeNull(); expect(env.placementUnavailable).toBe(false);
  actions.chooseTool('text'); expect(env.tool).toBe('text'); expect(env.notice).toBeNull(); actions.onPointerDown(pointer, 2, layer); expect(env.draft).toBeNull();
  actions.onPointerDown(pointer, 1, layer); expect(env.draft).toMatchObject({ page: 1, x: 10, y: 10 });
  env.error = 'unconfirmed write'; actions.chooseTool('signature'); expect(env.tool).toBe('text'); // The write barrier is unchanged.
});
test('recipient CTA opens the actual existing form, preserves its draft and rechecks ownership before focus', async () => {
  const calls: string[] = []; let release!: () => void;
  const env: any = { captureScope: () => ({ id: 'A' }), editable: true, otherMutationBusy: false, documentChanged: false, recipientIdentityLocked: false, saving: false, busy: false,
    showForm: true, isCurrent: () => true, fName: 'Preserved draft', fEmail: 'draft@example.test', editingId: 'existing', fRole: 'signer', fLocale: 'sv', formRevision: 1, formBaseline: '',
    requiresSignature: true, roleOptions: [{ value: 'signer' }], signerRoles: ['signer'], docLocale: 'en', confirmFormReplacement: () => { calls.push('open'); return true; }, currentForm: () => 'native-form-baseline',
    tick: async () => {}, recipientNameInput: { scrollIntoView() { calls.push('scroll'); }, focus() { calls.push('focus'); } } };
  const action = bind('./SenderPanel.svelte', ['openRecipientForm', 'openAdd'], env).openRecipientForm;
  expect(await action()).toBe(true); expect(calls).toEqual(['scroll', 'focus']); // Existing form values were not reset by openAdd.
  expect(env.fName).toBe('Preserved draft'); expect(env.fEmail).toBe('draft@example.test');
  env.showForm = false;
  env.tick = () => new Promise<void>(resolve => { release = resolve; }); const opening = action(); env.recipientIdentityLocked = true; release();
  expect(await opening).toBe(false); expect(calls).toEqual(['scroll', 'focus', 'open']);
  expect(env.formRevision).toBe(2); expect(env.formBaseline).toBe('native-form-baseline');
  for (const field of ['otherMutationBusy', 'documentChanged', 'recipientIdentityLocked', 'saving', 'busy']) { env.recipientIdentityLocked = false; env[field] = true; expect(await action()).toBe(false); env[field] = false; }
});
test('purpose values are closed and malformed or missing responses never imply Signing', () => {
  for (const value of [undefined, '', null, 'signature', 'SIGNING', {}, 1]) { expect(documentPurpose(value)).toBeNull(); expect(() => requireDocumentPurpose(value)).toThrow(); }
  for (const value of ['document', 'presentation', 'signing']) expect(documentPurpose(value)).toBe(value);
});
test('ordinary create requires an explicit purpose and an unconfirmed native result cannot be replayed by a second click', async () => {
  const calls: any[] = [], env: any = { busy: false, disposed: false, creationUnconfirmed: false, blankPurpose: '', newName: 'Preserved title', creating: false, error: null,
    $ui: (text: string) => text, requireDocumentPurpose, createBlocksDocument: (...args: any[]) => new Promise(resolve => calls.push({ args, resolve })), goto: async () => { throw Error('Unconfirmed result must not navigate'); } };
  const action = bind('../../routes/documents/+page.svelte', ['createBlank'], env).createBlank;
  await action(event); expect(calls).toEqual([]); expect(env.error).toContain('Choose'); env.blankPurpose = 'document';
  Object.defineProperty(env, 'busy', { get: () => env.creating }); const pending = action(event); await action(event); expect(calls).toHaveLength(1); expect(calls[0].args).toEqual(['Preserved title', 'document']);
  calls[0].resolve({ id: 'created', purpose: '' }); await pending; expect(env.creationUnconfirmed).toBe(true); expect(env.newName).toBe('Preserved title');
  await action(event); expect(calls).toHaveLength(1);
});
test('non-signing and unknown purpose cannot invoke the signature-versus-acknowledgement action', async () => {
  for (const signingPurpose of [false]) {
    const env: any = { captureDocument: () => ({ id: 'A' }), doc: { id: 'A', status: 'draft' }, signingPurpose, updateDocument: () => { throw Error('No signing request allowed'); } };
    await bind('../../routes/documents/[id]/+page.svelte', ['toggleSignatureMode'], env).toggleSignatureMode();
  }
});
test('PDF design reuse pins the observed version for every purpose and copies parties only for Signing', async () => {
  for (const purpose of ['document', 'presentation', 'signing']) {
    const calls: any[] = [], template = { id: 'template', org_id: 'org', version: 7, source_kind: 'pdf' }, draft = [{ role: 'signer', name: ' Preserved name ', email: ' signer@example.test ' }];
    const env: any = { selectedTemplate: template, creatingId: null, removalBusy: false, pendingCreation: false, templateCreationUnconfirmed: false, documentName: 'New document', documentPurpose: purpose, requireDocumentPurpose, blockTemplateNeedsSigning, bindings: draft, disposed: false,
      createDocumentFromTemplate: async (...args: any[]) => { calls.push(args); return { id: 'new', org_id: 'org', template_id: 'template', purpose }; }, goto: async (path: string) => { calls.push(path); } };
    await bind('../../routes/templates/+page.svelte', ['createBoundDocument'], env).createBoundDocument(event);
    expect(calls[0]).toEqual(['New document', 'template', 'pdf', { expected_template_version: 7, ...(purpose === 'signing' ? { parties: [{ role: 'signer', name: 'Preserved name', email: 'signer@example.test' }] } : {}) }, purpose]);
    expect(calls[1]).toBe('/documents/new'); expect(draft[0].name).toBe(' Preserved name ');
  }
});
test('actual block-template create refuses incompatible or unreadable source before dispatch and permits genuine Signing', async () => {
  for (const [purpose, body, allowed] of [['document', { version: 1, blocks: [{ type: 'signature_field' }] }, false], ['presentation', { version: 1, blocks: [{ type: 'paragraph', content: [{ type: 'text_field' }] }] }, false], ['signing', { version: 1, blocks: [{ type: 'signature_field' }] }, true], ['document', null, false], ['document', { version: 1, blocks: [{ type: 'paragraph', text: 'Ordinary wording' }] }, true]] as const) {
    const calls: unknown[] = [], template = { id: 'template', org_id: 'org', version: 7, source_kind: 'blocks', blocks_json: body };
    const env: any = { selectedTemplate: template, creatingId: null, removalBusy: false, pendingCreation: false, templateCreationUnconfirmed: false, error: null, documentName: 'New document', documentPurpose: purpose, requireDocumentPurpose, blockTemplateNeedsSigning, bindings: [], disposed: false,
      createDocumentFromTemplate: async (...args: unknown[]) => { calls.push(args); return { id: 'new', org_id: 'org', template_id: 'template', purpose }; }, goto: async () => {} };
    await bind('../../routes/templates/+page.svelte', ['createBoundDocument'], env).createBoundDocument(event);
    expect(calls.length).toBe(allowed ? 1 : 0); expect(env.templateCreationUnconfirmed).toBe(false); if (!allowed) expect(env.error).toBeTruthy();
  }
});
test('purpose-only action preserves CAS, waits for the native response and fences drift or an unknown outcome', async () => {
  for (const mode of ['success', 'wrong-purpose', 'drift', 'error'] as const) {
    const calls: any[] = [], doc = { id: 'A', org_id: 'org', sender_id: 'owner', purpose: 'signing', status: 'draft', source_kind: 'blocks', updated_at: 'exact' };
    const env: any = { doc, htmlSource: null, savedPurpose: 'signing', signingPurpose: true, purposeUnconfirmed: false, changingPurpose: false, selectedPurpose: 'document', purposeError: null,
      viewerRole: 'owner', viewerUserID: 'owner', crmBusy: false, crmLocalIntent: false, senderMutationBusy: false, senderDraftDirty: false, attachmentBusy: false, attachmentDirty: false,
      pdfLayoutBusy: false, pdfLayoutDirty: false, savingMode: false, savingTemplate: false, revising: false, resolvingId: null, savingApprovalMode: false, amendmentBusy: false, amendmentDirty: false,
      supersessionBusy: false, supersessionPending: false, blocksEditorClean: true, htmlEditorClean: true, htmlRevisionBlocked: false, requireDocumentPurpose,
      captureDocument: () => ({ id: 'A' }), isCurrentDocument: () => true,
      updateDocument: (...args: any[]) => new Promise((resolve, reject) => calls.push({ args, resolve, reject })),
      receiveDocument: (updated: any) => { env.doc = updated; return true; } };
    const action = bind('../../routes/documents/[id]/+page.svelte', ['changePurpose'], env).changePurpose;
    const pending = action(event); await action(event); expect(calls).toHaveLength(1); expect(calls[0].args).toEqual(['A', { expected_updated_at: 'exact', purpose: 'document' }]);
    expect(env.doc).toBe(doc); expect(env.doc.purpose).toBe('signing');
    if (mode === 'drift') env.isCurrentDocument = (_scope: unknown, unchanged = false) => !unchanged;
    if (mode === 'error') calls[0].reject(new Error('unconfirmed response')); else calls[0].resolve({ ...doc, purpose: mode === 'wrong-purpose' ? 'presentation' : 'document' });
    await pending; expect(env.purposeUnconfirmed).toBe(mode !== 'success'); expect(env.doc.purpose).toBe(mode === 'success' ? 'document' : 'signing');
    if (mode !== 'success') { await action(event); expect(calls).toHaveLength(1); }
  }
});
test('dirty content, live workflow ownership and incompatible purpose refuse a purpose write before dispatch', async () => {
  for (const guard of ['purposeUnconfirmed', 'changingPurpose', 'crmBusy', 'crmLocalIntent', 'senderMutationBusy', 'senderDraftDirty', 'attachmentBusy', 'attachmentDirty', 'pdfLayoutBusy', 'pdfLayoutDirty', 'savingMode', 'savingTemplate', 'revising', 'savingApprovalMode', 'amendmentBusy', 'amendmentDirty', 'supersessionBusy', 'supersessionPending', 'dirty', 'unknown']) {
    const env: any = { doc: { id: 'A', sender_id: 'owner', status: 'draft', source_kind: 'blocks' }, savedPurpose: 'signing', viewerRole: 'owner', viewerUserID: 'owner', selectedPurpose: 'document',
      purposeUnconfirmed: false, changingPurpose: false, crmBusy: false, crmLocalIntent: false, senderMutationBusy: false, senderDraftDirty: false, attachmentBusy: false, attachmentDirty: false, pdfLayoutBusy: false, pdfLayoutDirty: false, savingMode: false, savingTemplate: false, revising: false, resolvingId: null, savingApprovalMode: false, amendmentBusy: false, amendmentDirty: false, supersessionBusy: false, supersessionPending: false,
      blocksEditorClean: true, captureDocument: () => ({ id: 'A' }), updateDocument: () => { throw new Error('unexpected request'); }, requireDocumentPurpose };
    if (guard === 'dirty') env.blocksEditorClean = false; else if (guard === 'unknown') env.savedPurpose = null; else env[guard] = true;
    await bind('../../routes/documents/[id]/+page.svelte', ['changePurpose'], env).changePurpose(event);
  }
});

let renderer: Promise<any> | undefined;
function blockToolbarFixture(): string {
  const source = readFileSync(new URL('./BlockEditor/Editor.svelte', import.meta.url), 'utf8'), ast: any = parse(source, { modern: true });
  const props = ast.instance.content.body.find((node: any) => node.type === 'VariableDeclaration' && node.declarations.some((decl: any) => decl.id?.type === 'ObjectPattern' && decl.id.properties.some((property: any) => property.key?.name === 'signingFieldsEnabled')));
  let conditional: any;
  const visit = (node: any) => { if (!node || typeof node !== 'object' || conditional) return; if (node.type === 'IfBlock' && node.test?.name === 'signingFieldsEnabled') { conditional = node; return; } for (const value of Object.values(node)) { if (Array.isArray(value)) value.forEach(visit); else if (value && typeof value === 'object') visit(value); } };
  visit(ast.fragment); if (!props || !conditional) throw Error('Actual signature toolbar boundary missing');
  return `<script lang="ts">import {ui} from '$lib/staffPreferences'; import {Signature} from 'lucide-svelte'; ${source.slice(props.start, props.end)} const insertSignatureField=()=>{throw Error('SSR must not dispatch');};</script>${source.slice(conditional.start, conditional.end)}`;
}
async function views() {
  return renderer ??= (async () => {
    const lib = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    const build = await Bun.build({ entrypoints: ['editor-view-entry'], target: 'bun', plugins: [{ name: 'actual-editor-views', setup(builder) {
      builder.onResolve({ filter: /^editor-view-entry$/ }, () => ({ path: 'entry', namespace: 'test' }));
      builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: `export {default as Select} from ${JSON.stringify(resolve(lib, 'components/DocumentPurposeSelect.svelte'))}; export {default as Strip} from ${JSON.stringify(resolve(lib, 'components/PDFPageStrip.svelte'))}; export {default as Toolbar} from 'editor-toolbar'; export {render} from 'svelte/server'; export {setStaffLocale} from ${JSON.stringify(resolve(lib, 'staffPreferences.ts'))};`, loader: 'ts', resolveDir: process.cwd() }));
      builder.onResolve({ filter: /^editor-toolbar$/ }, () => ({ path: 'toolbar', namespace: 'actual-toolbar' }));
      builder.onLoad({ filter: /.*/, namespace: 'actual-toolbar' }, () => ({ contents: compile(blockToolbarFixture(), { filename: resolve(lib, 'components/BlockEditor/ToolbarFixture.svelte'), generate: 'server' }).js.code, loader: 'js', resolveDir: process.cwd() }));
      builder.onResolve({ filter: /^\$lib\/pdf$/ }, () => ({ path: 'browser-only-pdf', namespace: 'no-ssr-pdf' }));
      builder.onLoad({ filter: /.*/, namespace: 'no-ssr-pdf' }, () => ({ contents: `throw new Error('Server rendering must not load the browser-only PDF renderer');`, loader: 'js' }));
      builder.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
      builder.onLoad({ filter: /\.svelte$/ }, async args => ({ contents: compile(await Bun.file(args.path).text(), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!build.success) throw Error(build.logs.map(String).join('\n'));
    const tmp = mkdtempSync(join(tmpdir(), 'hash-editor744-'));
    try { const path = join(tmp, 'views.mjs'); writeFileSync(path, await build.outputs[0].text()); return await import(pathToFileURL(path).href); } finally { rmSync(tmp, { recursive: true, force: true }); }
  })();
}
test('actual compiled signature toolbar hides non-signing actions while default template authoring retains its control', async () => {
  const view = await views(); view.setStaffLocale('en');
  expect(view.render(view.Toolbar, { props: { document: {}, signingFieldsEnabled: false } }).body).not.toContain('Sig field');
  for (const props of [{ document: {}, signingFieldsEnabled: true }, { document: {} }]) expect(view.render(view.Toolbar, { props }).body).toContain('Sig field');
});
test('actual compiled page strip renders five real blank-until-painted canvases with accessible selection and bounded controls', async () => {
  const view = await views(); const html = view.render(view.Strip, { props: { doc: { numPages: 500 }, activePage: 250, paint: async () => { throw Error('SSR must not paint'); }, onSelect() {} } }).body;
  expect((html.match(/<canvas/g) ?? [])).toHaveLength(5); expect((html.match(/width="0"/g) ?? [])).toHaveLength(5);
  expect(html).toContain('aria-current="page"'); expect(html).toContain('Show page 250'); expect(html).toContain('visibility: hidden'); expect(html).not.toContain('data:image');
  for (const [page, label] of [[1, 'Previous page'], [500, 'Next page']] as const) { const edge = view.render(view.Strip, { props: { doc: { numPages: 500 }, activePage: page, paint: async () => ({ width: 1, height: 1 }), onSelect() {} } }).body; expect(edge).toMatch(new RegExp(`<button[^>]*disabled[^>]*>${label}</button>`)); }
});
test('actual purpose selector has no implicit choice, localized labels and no acknowledgement substitution', async () => {
  const view = await views(); view.setStaffLocale('sv'); const html = view.render(view.Select, { props: { value: '', onChange() {} } }).body;
  expect(html).toContain('Välj användning'); expect(html).toContain('value="document"'); expect(html).toContain('value="presentation"'); expect(html).toContain('value="signing"'); expect(html).not.toContain('acknowledgement'); view.setStaffLocale('en');
});
test('actual new and changed components compile for both targets without accessibility regressions', () => {
  for (const file of ['PDFPageStrip.svelte', 'DocumentPurposeSelect.svelte', 'PdfFieldDesigner.svelte', 'VerifiedPDFPages.svelte', 'SenderPanel.svelte']) {
    const filename = fileURLToPath(new URL(file, import.meta.url)), source = readFileSync(filename, 'utf8');
    for (const generate of ['client', 'server'] as const) expect(compile(source, { filename, generate }).warnings).toEqual([]);
  }
});
