import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { translateStaffText } from './staffPreferences';

const documentSource = readFileSync(new URL('../routes/documents/[id]/+page.svelte', import.meta.url), 'utf8');
const assetSource = readFileSync(new URL('./components/HtmlTemplateEditor.svelte', import.meta.url), 'utf8');
function handler(source: string, name: string) {
  const tree: any = parse(source, { modern: true });
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(node.start, node.end));
  return new Function('env', `with(env) { ${code}; return ${name}; }`);
}
function attributeValues(attribute: any): any[] { return Array.isArray(attribute?.value) ? attribute.value : attribute?.value ? [attribute.value] : []; }
function buttonDisabled(source: string, callback: string, env: any): boolean {
  const tree: any = parse(source, { modern: true }); let expression: any;
  function walk(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.name === 'button' && node.attributes?.some((attribute: any) => attribute.name === 'onclick' && attributeValues(attribute).some((value: any) => value.expression?.name === callback))) {
      expression = attributeValues(node.attributes.find((attribute: any) => attribute.name === 'disabled'))[0]?.expression;
    }
    for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(walk); else if (value && typeof value === 'object') walk(value);
  }
  walk(tree); if (!expression) throw new Error('Actual action disabled predicate missing');
  return new Function('env', `with(env) { return (${source.slice(expression.start, expression.end)}); }`)(env);
}
function documentFixture(status = 'draft', clean = true) {
  const calls: any[] = [], focus: string[] = [];
  const env: any = { doc: { id: 'doc', name: 'Contract', status, source_kind: 'blocks', blocks_json: { text: 'latest saved' }, variables_json: { company: 'Example' } },
    crmBusy: false, savingTemplate: false, blocksEditorClean: clean, error: null, savedTemplateFlash: false, templateFlashTimer: null,
    showTemplateName: false, templateName: '', templateNameError: null, templateSource: null,
    routeRevision: 1, documentRevision: 1, disposed: false, $page: { params: { id: 'doc' } },
    templateNameInput: { focus() { focus.push('input'); }, select() { focus.push('select'); } },
    templateNameTrigger: { focus() { focus.push('trigger'); } }, tick: async () => {},
    window: { prompt() { throw new Error('Native prompts must not be used'); } },
    createBlocksTemplate: async (...args: any[]) => { calls.push(args); }, clearTimeout() {}, setTimeout() { return 1; } };
  for (const name of ['isCurrentRoute', 'captureDocument', 'isCurrentDocument', 'templateSourceCurrent', 'closeTemplateName']) env[name] = handler(documentSource, name)(env);
  return { env, calls, focus, save: handler(documentSource, 'saveAsTemplate')(env),
    submit: handler(documentSource, 'submitTemplateName')(env), keydown: handler(documentSource, 'templateNameKeydown')(env) };
}
const submitEvent = () => ({ preventDefault() {} }) as Event;

test('dirty block drafts cannot open the name form or create a template, and the actual button is disabled', async () => {
  const f = documentFixture('draft', false); await f.save();
  expect(f.calls).toHaveLength(0); expect(f.env.showTemplateName).toBe(false); expect(f.env.error).toContain('finish saving');
  expect(buttonDisabled(documentSource, 'saveAsTemplate', f.env)).toBe(true);
});

test('canonical save acknowledgement opens and focuses a normal form without creating anything', async () => {
  const f = documentFixture('draft', false);
  f.env.doc = { ...f.env.doc, blocks_json: { text: 'edited and acknowledged' } }; f.env.blocksEditorClean = true;
  expect(buttonDisabled(documentSource, 'saveAsTemplate', f.env)).toBe(false); await f.save();
  expect(f.calls).toHaveLength(0); expect(f.env.showTemplateName).toBe(true); expect(f.env.templateName).toBe('Contract');
  expect(f.focus).toEqual(['input', 'select']);
  f.env.templateName = '  Reusable agreement  '; await f.submit(submitEvent());
  expect(f.calls).toEqual([['Reusable agreement', { blocks_json: { text: 'edited and acknowledged' }, variables_json: { company: 'Example' } }]]);
  expect(f.env.savingTemplate).toBe(false); expect(f.env.savedTemplateFlash).toBe(true);
  expect(f.env.showTemplateName).toBe(false); expect(f.focus.at(-1)).toBe('trigger');
});

test('document, revision, clean-state and route changes refuse stale content before the create request', async () => {
  for (const change of ['document', 'revision', 'dirty', 'route', 'disposed']) {
    const f = documentFixture(); await f.save(); f.env.templateName = 'Keep my entered name';
    if (change === 'document') f.env.doc = { ...f.env.doc, blocks_json: { text: 'another revision' } };
    if (change === 'revision') f.env.documentRevision++;
    if (change === 'dirty') f.env.blocksEditorClean = false;
    if (change === 'route') f.env.routeRevision++;
    if (change === 'disposed') f.env.disposed = true;
    expect(f.env.templateSourceCurrent()).toBe(false);
    await f.submit(submitEvent()); expect(f.calls).toHaveLength(0); expect(f.env.savingTemplate).toBe(false);
    expect(f.env.templateName).toBe('Keep my entered name'); expect(f.env.templateNameError).toContain('document changed');
  }
});

test('saved completed block documents and existing busy guards retain their behavior', async () => {
  const completed = documentFixture('completed', false);
  expect(buttonDisabled(documentSource, 'saveAsTemplate', completed.env)).toBe(false); await completed.save();
  await completed.submit(submitEvent()); expect(completed.calls).toHaveLength(1);
  for (const busy of ['crmBusy', 'savingTemplate']) {
    const f = documentFixture(); f.env[busy] = true; await f.save(); expect(f.calls).toHaveLength(0); expect(f.env.showTemplateName).toBe(false);
    expect(buttonDisabled(documentSource, 'saveAsTemplate', f.env)).toBe(true);
  }
});

test('Cancel and Escape close without creating and return focus to the action', async () => {
  for (const escape of [false, true]) {
    const f = documentFixture(); await f.save(); let prevented = false;
    if (escape) { f.keydown({ key: 'Escape', preventDefault() { prevented = true; } }); await Promise.resolve(); }
    else await f.env.closeTemplateName();
    expect(prevented).toBe(escape); expect(f.calls).toHaveLength(0); expect(f.env.showTemplateName).toBe(false);
    expect(f.env.templateSource).toBeNull(); expect(f.focus.at(-1)).toBe('trigger');
  }
});

test('blank and oversized names remain editable with a field error and no API call', async () => {
  for (const name of ['  ', 'a'.repeat(201)]) {
    const f = documentFixture(); await f.save(); f.env.templateName = name;
    await f.submit(submitEvent()); expect(f.calls).toHaveLength(0); expect(f.env.showTemplateName).toBe(true);
    expect(f.env.templateName).toBe(name); expect(f.env.templateNameError).toContain('200'); expect(f.focus.at(-1)).toBe('input');
  }
});

test('reopening cannot discard the entered name and busy work cannot double-submit or cancel', async () => {
  const f = documentFixture(); await f.save(); f.env.templateName = 'My draft name'; await f.save();
  expect(f.env.templateName).toBe('My draft name');
  let finish!: () => void;
  f.env.createBlocksTemplate = async (...args: any[]) => { f.calls.push(args); await new Promise<void>(resolve => { finish = resolve; }); };
  const pending = f.submit(submitEvent()); expect(f.env.savingTemplate).toBe(true);
  await f.submit(submitEvent()); await f.env.closeTemplateName(); f.keydown({ key: 'Escape', preventDefault() {} });
  expect(f.calls).toHaveLength(1); expect(f.env.showTemplateName).toBe(true);
  finish(); await pending; expect(f.env.savingTemplate).toBe(false); expect(f.env.savedTemplateFlash).toBe(true);
});

test('API rejection retains the entered name and source, with the genuine API message', async () => {
  const f = documentFixture(); await f.save(); const source = f.env.templateSource;
  f.env.templateName = 'Keep this'; f.env.createBlocksTemplate = async () => { throw new Error('Permission denied'); };
  await f.submit(submitEvent()); expect(f.env.templateName).toBe('Keep this'); expect(f.env.templateSource).toBe(source);
  expect(f.env.templateNameError).toBe('Permission denied'); expect(f.env.showTemplateName).toBe(true);
  expect(f.env.savingTemplate).toBe(false); expect(f.env.savedTemplateFlash).toBe(false);
});

test('a route change during create cannot alter the next route or steal its focus', async () => {
  const f = documentFixture(); await f.save(); let finish!: () => void;
  f.env.createBlocksTemplate = () => new Promise<void>(resolve => { finish = resolve; });
  const pending = f.submit(submitEvent()); f.env.routeRevision++; f.env.savedTemplateFlash = false;
  f.env.templateName = 'Next route name'; const nextSource = {}; f.env.templateSource = nextSource;
  f.env.savingTemplate = true; f.focus.length = 0;
  finish(); await pending;
  expect(f.env.savedTemplateFlash).toBe(false); expect(f.env.templateName).toBe('Next route name');
  expect(f.env.templateSource).toBe(nextSource); expect(f.env.savingTemplate).toBe(true); expect(f.focus).toEqual([]);
});

test('delayed opening and Cancel focus never target a replaced route', async () => {
  const f = documentFixture(); let settled!: () => void;
  f.env.tick = () => new Promise<void>(resolve => { settled = resolve; });
  const opened = f.save(); f.env.routeRevision++; settled(); await opened; expect(f.focus).toEqual([]);
  const closed = f.env.closeTemplateName(); f.env.routeRevision++; settled(); await closed; expect(f.focus).toEqual([]);
});

test('staff copy follows the chosen language without changing template content or field names', () => {
  const help = 'Use Settings to manage your team, branding, integrations and evidence controls. Language is in the account menu; appearance controls are next to it.';
  expect(translateStaffText('en', help)).toBe(help);
  expect(translateStaffText('sv', help)).toContain('utseendekontrollerna');
  expect(translateStaffText('sv', 'Document information')).toBe('Dokumentuppgifter');
  expect(translateStaffText('sv', 'Enter a template name of up to 200 characters.')).toContain('200 tecken');
  const source = readFileSync(new URL('./components/HtmlTemplatePopulate.svelte', import.meta.url), 'utf8');
  const tree: any = parse(source, { modern: true }); const expressions: any[] = [];
  function walk(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.name === '$ui' && node.arguments[0]?.type === 'MemberExpression'
      && node.arguments[0].object?.name === 'group' && node.arguments[0].property?.name === 'label') expressions.push(node);
    for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(walk); else if (value && typeof value === 'object') walk(value);
  }
  walk(tree); expect(expressions).toHaveLength(2);
  for (const node of expressions) {
    const render = new Function('group', '$ui', `return ${source.slice(node.start, node.end)};`);
    expect(render({ label: 'Document information' }, (text: string) => translateStaffText('sv', text))).toBe('Dokumentuppgifter');
    expect(render({ label: 'My approved wording' }, (text: string) => translateStaffText('sv', text))).toBe('My approved wording');
  }
  let previewTranslate: any;
  function findPreview(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'Component' && node.name === 'VerifiedPDFPages') previewTranslate = attributeValues(node.attributes.find((attribute: any) => attribute.name === 'translate'))[0]?.expression;
    for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(findPreview); else if (value && typeof value === 'object') findPreview(value);
  }
  findPreview(parse(assetSource, { modern: true })); expect(previewTranslate).toBeDefined();
  let locale: 'en' | 'sv' = 'en';
  const translate = new Function('$ui', `return (${assetSource.slice(previewTranslate.start, previewTranslate.end)});`)((text: string) => translateStaffText(locale, text));
  expect(translate('Previous page')).toBe('Previous page'); locale = 'sv';
  expect(translate('Previous page')).toBe('Föregående sida'); expect(translate('Next page')).toBe('Nästa sida');
  expect(translate('Page')).toBe('Sida'); expect(translate('of')).toBe('av');
});

test('Add local asset requires a chosen file in its actual button and keeps the existing capacity guard', () => {
  expect(buttonDisabled(assetSource, 'addAsset', { pendingAssetFile: null, draft: { assets: [] } })).toBe(true);
  expect(buttonDisabled(assetSource, 'addAsset', { pendingAssetFile: {}, draft: { assets: [] } })).toBe(false);
  expect(buttonDisabled(assetSource, 'addAsset', { pendingAssetFile: {}, draft: { assets: Array(16).fill({}) } })).toBe(true);
});

test('actual asset callback still refuses missing files and adds only the selected validated result', async () => {
  const file = {}, asset = { name: 'logo', sha256: 'opaque' }, calls: any[] = [];
  const env: any = { current: () => true, canWrite: true, busy: null, loading: false, pendingAssetFile: null, operation: 0,
    draft: { assets: [] }, assetName: 'logo', assetFile: { value: 'selected' }, error: null,
    htmlAuthorFingerprint: () => 'same', invalidatePreview() {}, recordError(error: unknown) { throw error; },
    htmlAssetFromFile: async (...args: any[]) => { calls.push(args); return asset; } };
  const add = handler(assetSource, 'addAsset')(env); await add(); expect(calls).toHaveLength(0);
  env.pendingAssetFile = file; await add(); expect(calls).toEqual([[file, 'logo', []]]);
  expect(env.draft.assets).toEqual([asset]); expect(env.pendingAssetFile).toBeNull(); expect(env.assetName).toBe(''); expect(env.busy).toBeNull();
});
