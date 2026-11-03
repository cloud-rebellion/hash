import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';

const source = readFileSync(new URL('../../routes/templates/+page.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const names = ['refresh', 'seedStarter', 'newBlankTemplate', 'toggleUpload'];
const functions = names.map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  if (!node) throw new Error('Actual template library callback missing');
  return source.slice(node.start, node.end);
});
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions.join('\n'));
const bind = new Function('env', `with(env) { ${code}; return { refresh, seedStarter, newBlankTemplate, toggleUpload }; }`);

function fixture(response: unknown) {
  const calls: string[] = [];
  const env: any = {

    $ui: (text: string) => text, $staffLocale: 'en', disposed: false, removalBusy: false, starterTemplatesAvailable: false, loading: true, pendingCreation: false, uploading: false, showUpload: false, seeding: null, error: null, listError: null, templates: [],
    listTemplates: async () => response,
    createStarterTemplate: async (key: string) => { calls.push(`starter:${key}`); },
    createBlocksTemplate: async () => { calls.push('blank'); }
  };
  return { env, calls, ...bind(env) };
}

test('the actual library requires an explicit server true capability before offering a starter', async () => {
  for (const value of [false, undefined, null, 'true', 1]) {
    const f = fixture({ templates: [], starter_templates_available: value });
    await f.refresh();
    expect(f.env.starterTemplatesAvailable).toBe(false);
    await f.seedStarter();
    expect(f.calls).toEqual([]);
  }
  const f = fixture({ templates: [], starter_templates_available: true });
  await f.refresh();
  expect(f.env.starterTemplatesAvailable).toBe(true);
  await f.seedStarter();
  expect(f.calls).toEqual(['starter:services-agreement-sv']);
});

test('refresh revokes a previous capability before awaiting the response and keeps it revoked on failure', async () => {
  const f = fixture({ templates: [], starter_templates_available: true });
  await f.refresh();
  let reject!: (error: Error) => void;
  f.env.listTemplates = () => new Promise((_, fail) => { reject = fail; });
  const pending = f.refresh();
  expect(f.env.loading).toBe(true);
  expect(f.env.starterTemplatesAvailable).toBe(false);
  await f.seedStarter();
  expect(f.calls).toEqual([]);
  reject(new Error('Template listing unavailable'));
  await pending;
  expect(f.env.loading).toBe(false);
  expect(f.env.starterTemplatesAvailable).toBe(false);
  expect(f.env.listError).toBe('Template listing unavailable');
});

test('unavailable starters do not prevent a custom blank template, and pending recovery still prevents either write', async () => {
  const f = fixture({ templates: [], starter_templates_available: false });
  await f.refresh();
  await f.newBlankTemplate();
  expect(f.calls).toEqual(['blank']);
  f.env.pendingCreation = true;
  f.env.starterTemplatesAvailable = true;
  await f.seedStarter();
  await f.newBlankTemplate();
  expect(f.calls).toEqual(['blank']);
});

function actualButton(callback: string): any {
  const found: any[] = [];
  function walk(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.name === 'button' && node.attributes?.some((attr: any) => attr.name === 'onclick' && (Array.isArray(attr.value) ? attr.value[0] : attr.value)?.expression?.name === callback)) found.push(node);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === 'object') walk(value);
    }
  }
  walk(tree.fragment);
  expect(found).toHaveLength(1);
  return found[0];
}

test('the actual starter button is disabled for unavailable or unknown capability while custom creation stays available', () => {
  const starter = actualButton('seedStarter'), upload = actualButton('toggleUpload');
  const disabled = (button: any, env: any) => {
    const value = button.attributes.find((attr: any) => attr.name === 'disabled').value;
    const expression = (Array.isArray(value) ? value[0] : value).expression;
    return new Function('env', `with(env) { return (${source.slice(expression.start, expression.end)}); }`)(env);
  };
  const env = { loading: false, starterTemplatesAvailable: false, seeding: null, pendingCreation: false, removalBusy: false };
  expect(disabled(starter, env)).toBe(true);
  expect(disabled(upload, { ...env, uploading: false })).toBe(false);
  expect(source).toContain('href="/templates/html/new"');
  expect(source).not.toContain('onclick={newBlankTemplate}');
  expect(disabled(starter, { ...env, starterTemplatesAvailable: true })).toBe(false);
  expect(disabled(starter, { ...env, loading: true, starterTemplatesAvailable: true })).toBe(true);
  expect(starter.attributes.find((attr: any) => attr.name === 'aria-describedby').value[0].data).toBe('starter-template-availability');
  const containingConditions: any[] = [];
  function containing(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    let includes = node === starter;
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) { for (const child of value) includes = containing(child) || includes; }
      else if (value && typeof value === 'object') includes = containing(value) || includes;
    }
    if (includes && node.type === 'IfBlock') containingConditions.push(node.test);
    return includes;
  }
  containing(tree.fragment);
  const section = containingConditions.find(node => source.slice(node.start, node.end) === '!loading && starterTemplatesAvailable');
  expect(section).toBeDefined();
  const shown = new Function('env', `with(env) { return (${source.slice(section.start, section.end)}); }`);
  expect(shown(env)).toBe(false);
  expect(shown({ ...env, starterTemplatesAvailable: true })).toBe(true);
  expect(shown({ ...env, starterTemplatesAvailable: true, loading: true })).toBe(false);
  expect(source).toContain("aria-label={$ui('Upload a PDF template')}");
});


test('PDF upload is an explicit secondary action, retains the form while hidden, and cannot collapse in flight', () => {
  const f = fixture({ templates: [], starter_templates_available: false });
  expect(f.env.showUpload).toBe(false);
  f.toggleUpload(); expect(f.env.showUpload).toBe(true);
  f.env.uploading = true; f.toggleUpload(); expect(f.env.showUpload).toBe(true);
  f.env.uploading = false; f.toggleUpload(); expect(f.env.showUpload).toBe(false);
  f.env.pendingCreation = true; f.toggleUpload(); expect(f.env.showUpload).toBe(false);
  const button = actualButton('toggleUpload');
  expect(button.attributes.find((attr: any) => attr.name === 'aria-controls').value[0].data).toBe('template-pdf-upload-panel');
  expect(source).toContain('id="template-pdf-upload-panel" hidden={!showUpload}');
  expect(source).not.toContain('{#if showUpload}');
});
