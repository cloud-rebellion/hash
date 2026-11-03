import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile, parse } from 'svelte/compiler';
import { LibraryRemovalError } from '../api/libraryRemoval';
import { translateStaffText } from '../staffPreferences';

const source = readFileSync(new URL('./LibraryRemovalAction.svelte', import.meta.url), 'utf8');
const ast: any = parse(source, { modern: true }), transpiler = new Bun.Transpiler({ loader: 'ts' });
const functions = ast.instance.content.body.filter((node: any) => node.type === 'FunctionDeclaration').map((node: any) => source.slice(node.start, node.end)).join('\n');
const lifecycle = ast.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression?.callee?.name === 'onDestroy').expression.arguments[0];
const bind = new Function('env', `with(env){${transpiler.transformSync(functions)};return{openConfirmation,cancelConfirmation,remove,destroy:(${source.slice(lifecycle.start, lifecycle.end)})};}`);
function fixture() {
  const calls: string[] = [], timers: Array<() => void> = [];
  const env: any = { kind: 'document', item: { id: 'doc', org_id: 'org', name: 'Draft', status: 'draft', updated_at: 'stamp' }, canWrite: true, disabled: false, confirming: false, busy: false, uncertain: false, done: false, error: null, disposed: false, revision: 0, controller: null, deadline: undefined, rejectPending: undefined,
    LibraryRemovalError, AbortController, Promise, JSON, tick: async () => {}, trigger: { focus() { calls.push('trigger-focus'); } }, cancelButton: { focus() { calls.push('cancel-focus'); } },
    setTimeout(callback: () => void, ms: number) { expect(ms).toBe(25000); timers.push(callback); return timers.length; }, clearTimeout() { calls.push('timer-cleared'); },
    beforeRemove: undefined, removeLibraryItem: async (kind: string, id: string, signal: AbortSignal) => { calls.push(`REMOVE:${kind}:${id}`); expect(signal).toBe(env.controller.signal); },
    onbusy: (busy: boolean) => calls.push(`BUSY:${busy}`), onremoved: async () => { calls.push('REFRESH'); },
  };
  Object.defineProperty(env, 'eligible', { get: () => env.canWrite && (env.kind === 'template' || env.item.status === 'draft') });
  return { env, calls, timers, ...bind(env) };
}
test('actual handlers require a writable draft or reusable template and explicit confirmation before native dispatch', async () => {
  for (const barrier of ['viewer', 'sent', 'completed', 'disabled', 'not-confirmed']) {
    const f = fixture(); if (barrier === 'viewer') f.env.canWrite = false; if (barrier === 'sent' || barrier === 'completed') f.env.item.status = barrier; if (barrier === 'disabled') f.env.disabled = true;
    if (barrier !== 'not-confirmed') await f.openConfirmation(); await f.remove(); expect(f.calls.filter(call => call.startsWith('REMOVE:'))).toEqual([]);
  }
  const f = fixture(); await f.openConfirmation(); expect(f.env.confirming).toBe(true); expect(f.calls).toContain('cancel-focus'); await f.cancelConfirmation(); expect(f.calls).toContain('trigger-focus'); expect(f.env.confirming).toBe(false);
});
test('confirmed action calls the real transport once, acknowledges204, then refreshes the current library', async () => {
  for (const kind of ['document', 'template']) { const f = fixture(); f.env.kind = kind; await f.openConfirmation(); await f.remove(); expect(f.calls.filter(call => call.startsWith('REMOVE:'))).toEqual([`REMOVE:${kind}:doc`]); expect(f.calls).toContain('REFRESH'); expect(f.env.done).toBe(true); expect(f.env.confirming).toBe(false); expect(f.env.busy).toBe(false); expect(f.env.error).toBeNull(); }
});
test('one unresolved delete owns the action; cancelling or double clicking cannot submit another one', async () => {
  const f = fixture(); let finish!: () => void; f.env.removeLibraryItem = () => { f.calls.push('REMOVE'); return new Promise<void>(resolve => { finish = resolve; }); };
  await f.openConfirmation(); const pending = f.remove(); await f.remove(); await f.cancelConfirmation(); expect(f.calls.filter(call => call === 'REMOVE')).toHaveLength(1); expect(f.env.busy).toBe(true); expect(f.env.done).toBe(false); finish(); await pending; expect(f.env.done).toBe(true);
});
test('native refusal retains confirmation and never removes the card or reports success', async () => {
  const f = fixture(); f.env.removeLibraryItem = async () => { throw new LibraryRemovalError('refused', 'Retained evidence', 409); }; await f.openConfirmation(); await f.remove(); expect(f.env.done).toBe(false); expect(f.env.uncertain).toBe(false); expect(f.env.error).toBe('Retained evidence'); expect(f.env.confirming).toBe(true); expect(f.calls).not.toContain('REFRESH');
});
test('unknown outcomes fence repeat writes until a fresh library reload', async () => {
  const f = fixture(); let writes = 0; f.env.removeLibraryItem = async () => { writes++; throw new Error('network lost'); }; await f.openConfirmation(); await f.remove(); await f.remove(); await f.cancelConfirmation(); expect(writes).toBe(1); expect(f.env.uncertain).toBe(true); expect(f.env.done).toBe(false); expect(f.env.confirming).toBe(true); expect(f.env.error).toContain('Reload the library'); expect(f.calls).not.toContain('REFRESH');
});
test('the finite deadline aborts transport and fences a late success without a false refresh', async () => {
  const f = fixture(); let finish!: () => void; f.env.removeLibraryItem = () => new Promise<void>(resolve => { finish = resolve; }); await f.openConfirmation(); const pending = f.remove(); const signal = f.env.controller.signal; f.timers[0](); await pending; expect(signal.aborted).toBe(true); expect(f.env.uncertain).toBe(true); finish(); await Promise.resolve(); expect(f.env.done).toBe(false); expect(f.calls).not.toContain('REFRESH');
});
test('unmount aborts and joins the local pending owner; changed identity cannot adopt the old result', async () => {
  for (const mode of ['unmount', 'replacement']) {
    const f = fixture(); let finish!: () => void; f.env.removeLibraryItem = () => new Promise<void>(resolve => { finish = resolve; }); await f.openConfirmation(); const pending = f.remove(); const signal = f.env.controller.signal;
    if (mode === 'unmount') f.destroy(); else f.env.item = { ...f.env.item, id: 'other' };
    finish(); await pending; if (mode === 'unmount') expect(signal.aborted).toBe(true); expect(f.calls).not.toContain('REFRESH'); expect(f.env.done).toBe(false); expect(f.calls.at(-1)).toBe('BUSY:false');
  }
});
test('failed preview retirement prevents archive before any network mutation', async () => {
  for (const throws of [false, true]) { const f = fixture(); f.env.kind = 'template'; f.env.beforeRemove = async () => { if (throws) throw new Error('PDF retirement refused'); return false; }; await f.openConfirmation(); await f.remove(); expect(f.env.done).toBe(false); expect(f.env.uncertain).toBe(false); expect(f.env.error).toContain('Close the preview'); expect(f.calls.some(call => call.startsWith('REMOVE:'))).toBe(false); }
});
test('a completed delete remains acknowledged when only the subsequent library refresh fails', async () => {
  const f = fixture(); f.env.onremoved = async () => { throw new Error('list unavailable'); }; await f.openConfirmation(); await f.remove(); expect(f.env.done).toBe(true); expect(f.env.error).toBe('The item was removed. Reload the library to update this view.'); await f.remove(); expect(f.calls.filter(call => call.startsWith('REMOVE:'))).toHaveLength(1);
});
test('staff copy clearly distinguishes removal from retained documents and localizes destructive confirmations', () => {
  for (const key of ['Delete draft', 'Archive template', 'Confirm draft deletion', 'Confirm template archive', 'The result could not be confirmed. Reload the library before trying again.']) expect(translateStaffText('sv', key)).not.toBe(key);
  expect(translateStaffText('sv', 'Delete “{name}”?', { name: '<Contract>' })).toBe('Ta bort ”<Contract>”?');
  expect(source).not.toContain('{@html'); expect(source).not.toContain('window.confirm'); expect(source).toContain('aria-busy={busy}');
});

test('the actual template archive adapter retires its PDF preview and refuses live creation or recovery', async () => {
  const library = readFileSync(new URL('../../routes/templates/+page.svelte', import.meta.url), 'utf8');
  const tree: any = parse(library, { modern: true });
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === 'prepareTemplateRemoval');
  const bindAdapter = new Function('env', `with(env){${transpiler.transformSync(library.slice(node.start, node.end))};return prepareTemplateRemoval;}`);
  for (const barrier of ['disposed', 'pending', 'creating', 'uploading', 'seeding', 'pdf-form', 'html-form', 'none']) {
    let retired = 0; const env: any = { disposed: false, pendingCreation: false, creatingId: null, uploading: false, seeding: null, selectedTemplate: null, selectedHTMLTemplate: null, previewTemplate: { id: 'template' }, closePreview: async () => { retired++; return true; } };
    if (barrier === 'disposed') env.disposed = true; if (barrier === 'pending') env.pendingCreation = true; if (barrier === 'creating') env.creatingId = 'any'; if (barrier === 'uploading') env.uploading = true; if (barrier === 'seeding') env.seeding = 'any'; if (barrier === 'pdf-form') env.selectedTemplate = { id: 'template' }; if (barrier === 'html-form') env.selectedHTMLTemplate = { id: 'template' };
    expect(await bindAdapter(env)('template')).toBe(barrier === 'none'); expect(retired).toBe(barrier === 'none' ? 1 : 0);
  }
});

test('a document removal refreshes server pagination and the existing folder-count owner', async () => {
  const page = readFileSync(new URL('../../routes/documents/+page.svelte', import.meta.url), 'utf8'), tree: any = parse(page, { modern: true });
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === 'afterRemoval');
  const calls: string[] = [], action = new Function('env', `with(env){${transpiler.transformSync(page.slice(node.start, node.end))};return afterRemoval;}`)({ refresh: async () => calls.push('documents'), foldersOwner: { refreshCounts: async () => calls.push('folders') } });
  await action(); expect(calls).toEqual(['documents', 'folders']);
});

test('actual compiled view renders clear localized actions only for writable eligible items', async () => {
  const filename = fileURLToPath(new URL('./LibraryRemovalAction.svelte', import.meta.url)), lib = resolve(dirname(filename), '..');
  const built = await Bun.build({ entrypoints: ['removal-render-entry'], target: 'bun', plugins: [{ name: 'actual-removal-view', setup(build) {
    build.onResolve({ filter: /^removal-render-entry$/ }, () => ({ path: 'entry', namespace: 'removal-test' }));
    build.onLoad({ filter: /.*/, namespace: 'removal-test' }, () => ({ contents: `import View from ${JSON.stringify(filename)}; import { render } from 'svelte/server'; import { setStaffLocale } from ${JSON.stringify(resolve(lib, 'staffPreferences.ts'))}; export { View, render, setStaffLocale };`, loader: 'ts', resolveDir: process.cwd() }));
    build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
    // Keep the real SSR store implementation; avoid Bun's combined-cohort default-reader EISDIR for this regular file.
    build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, async args => ({ contents: await Bun.file(args.path).text(), loader: 'js', resolveDir: dirname(args.path) }));
    build.onLoad({ filter: /\.svelte$/ }, async args => ({ contents: compile(await Bun.file(args.path).text(), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
  } }] });
  expect(built.success).toBe(true);
  const temporary = mkdtempSync(join(tmpdir(), 'hash-removal-render-'));
  try {
    const file = join(temporary, 'view.mjs'); writeFileSync(file, await built.outputs[0].text()); const module = await import(pathToFileURL(file).href);
    const item = { id: 'doc', org_id: 'org', name: '<Agreement>', status: 'draft', updated_at: 'stamp' };
    for (const locale of ['en', 'sv']) {
      module.setStaffLocale(locale);
      const draft = module.render(module.View, { props: { kind: 'document', item, canWrite: true, onremoved() {} } }).body;
      expect(draft).toContain(locale === 'sv' ? 'Ta bort utkast' : 'Delete draft'); expect(draft).not.toContain('<Agreement>');
      const template = module.render(module.View, { props: { kind: 'template', item, canWrite: true, onremoved() {} } }).body;
      expect(template).toContain(locale === 'sv' ? 'Arkivera mall' : 'Archive template');
      for (const status of ['sent', 'completed', 'voided']) expect(module.render(module.View, { props: { kind: 'document', item: { ...item, status }, canWrite: true, onremoved() {} } }).body).not.toContain('<button');
      expect(module.render(module.View, { props: { kind: 'document', item, canWrite: false, onremoved() {} } }).body).not.toContain('<button');
    }
    module.setStaffLocale('en');
  } finally { rmSync(temporary, { recursive: true, force: true }); }
  for (const generate of ['client', 'server'] as const) expect(compile(source, { filename, generate }).warnings).toEqual([]);
});
