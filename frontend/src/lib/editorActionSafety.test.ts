import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';

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
  const calls: any[] = [], prompts: any[] = []; const scope = {};
  const env: any = { doc: { id: 'doc', name: 'Contract', status, source_kind: 'blocks', blocks_json: { text: 'latest saved' }, variables_json: { company: 'Example' } },
    crmBusy: false, savingTemplate: false, blocksEditorClean: clean, error: null, savedTemplateFlash: false, templateFlashTimer: null,
    captureDocument: () => scope, isCurrentDocument: (value: object) => value === scope,
    window: { prompt: (...args: any[]) => { prompts.push(args); return 'Template'; } },
    createBlocksTemplate: async (...args: any[]) => { calls.push(args); }, clearTimeout() {}, setTimeout() { return 1; } };
  return { env, calls, prompts, save: handler(documentSource, 'saveAsTemplate')(env) };
}

test('dirty block drafts cannot create a template or open a prompt, and the actual button is disabled', async () => {
  const f = documentFixture('draft', false); await f.save();
  expect(f.calls).toHaveLength(0); expect(f.prompts).toHaveLength(0); expect(f.env.error).toContain('finish saving');
  expect(buttonDisabled(documentSource, 'saveAsTemplate', f.env)).toBe(true);
});

test('canonical save acknowledgement enables the action and copies the latest saved document exactly', async () => {
  const f = documentFixture('draft', false);
  f.env.doc = { ...f.env.doc, blocks_json: { text: 'edited and acknowledged' } }; f.env.blocksEditorClean = true;
  expect(buttonDisabled(documentSource, 'saveAsTemplate', f.env)).toBe(false); await f.save();
  expect(f.calls).toEqual([['Template', { blocks_json: { text: 'edited and acknowledged' }, variables_json: { company: 'Example' } }]]);
  expect(f.env.savingTemplate).toBe(false); expect(f.env.savedTemplateFlash).toBe(true);
});

test('prompt-time document or clean-state changes refuse stale content before the create request', async () => {
  for (const change of ['document', 'dirty', 'route', 'cancel']) {
    const f = documentFixture();
    f.env.window.prompt = () => {
      if (change === 'document') f.env.doc = { ...f.env.doc, blocks_json: { text: 'another revision' } };
      if (change === 'dirty') f.env.blocksEditorClean = false;
      if (change === 'route') f.env.isCurrentDocument = () => false;
      return change === 'cancel' ? null : 'Template';
    };
    await f.save(); expect(f.calls).toHaveLength(0); expect(f.env.savingTemplate).toBe(false);
  }
});

test('saved completed block documents and existing busy guards retain their behavior', async () => {
  const completed = documentFixture('completed', false);
  expect(buttonDisabled(documentSource, 'saveAsTemplate', completed.env)).toBe(false); await completed.save(); expect(completed.calls).toHaveLength(1);
  for (const busy of ['crmBusy', 'savingTemplate']) {
    const f = documentFixture(); f.env[busy] = true; await f.save(); expect(f.calls).toHaveLength(0); expect(f.prompts).toHaveLength(0);
    expect(buttonDisabled(documentSource, 'saveAsTemplate', f.env)).toBe(true);
  }
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
