import { expect, test } from 'bun:test';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { compile, parse } from 'svelte/compiler';
import { documentDownloadName } from '../documentDownload';

const source = readFileSync(new URL('./DocumentAIAccessSettings.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const functions = ['load', 'toggle'].map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  return source.slice(node.start, node.end);
}).join('\n');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions);
const bind = new Function('env', `with(env) { ${code}; return {load,toggle}; }`);
function fixture() {
  const calls: any[] = [], timers = new Map<number, () => void>(); let counter = 0;
  const env: any = { open:false, loading:false, documents:[], total:0, offset:0, selected:'', error:null, limit:25, disposed:false, revision:0, controller:null, AbortController,
    setTimeout:(callback:()=>void)=>{const id=++counter;timers.set(id,callback);return id;}, clearTimeout:(id:number)=>timers.delete(id),
    listDocuments:(page:any,signal:AbortSignal)=>new Promise((resolve,reject)=>{ calls.push({page,signal,resolve,reject}); signal.addEventListener('abort',()=>reject(new Error('PRIVATE abort')),{once:true}); }),
  };
  return {env,calls,timers,...bind(env)};
}
test('advanced access loads a bounded document page and clears the old token context on page change', async () => {
  const f=fixture(), pending=f.load(25);expect(f.calls[0].page).toEqual({limit:25,offset:25});
  f.calls[0].resolve({documents:[{id:'document-two',name:'Second'}],total:51});await pending;
  expect(f.env.offset).toBe(25);expect(f.env.documents[0].id).toBe('document-two');expect(f.timers.size).toBe(0);
  f.env.selected='document-two';const next=f.load(50);expect(f.env.selected).toBe('');expect(f.env.documents).toEqual([]);
  f.calls[1].resolve({documents:[{id:'document-three'}],total:51});await next;expect(f.env.offset).toBe(50);
});
test('closing advanced settings aborts pending loading and cannot reveal an old document token panel', async () => {
  const f=fixture();f.env.open=true;const pending=f.load();f.toggle();await pending;
  expect(f.calls[0].signal.aborted).toBe(true);expect(f.env.selected).toBe('');expect(f.env.documents).toEqual([]);expect(f.env.error).toBeNull();expect(f.env.loading).toBe(false);
});
test('late and failed page responses cannot select a document or display a private error', async () => {
  const f=fixture(), first=f.load(), second=f.load(25);await first;
  f.calls[1].reject(new Error('PRIVATE database detail'));await second;
  expect(f.env.error).toBe('Unable to load documents.');expect(f.env.documents).toEqual([]);expect(f.env.selected).toBe('');
  const timed=f.load();[...f.timers.values()][0]();await timed;expect(f.env.error).toContain('timed out');expect(f.timers.size).toBe(0);
});
test('editor has a download action, while optional document tokens are keyed and managed only in settings', () => {
  const editor=readFileSync(new URL('../../routes/documents/[id]/+page.svelte',import.meta.url),'utf8');
  const settings=readFileSync(new URL('../../routes/settings/api-keys/+page.svelte',import.meta.url),'utf8');
  expect(editor).toContain('<DocumentDownload document={doc}');expect(editor).not.toContain('AgentTokensPanel');expect(editor).not.toContain('Attach AI');
  expect(settings).toContain('<DocumentAIAccessSettings');expect(source).toContain('{#key selected}<AgentTokensPanel documentID={selected}');
  for (const name of ['DocumentAIAccessSettings','DocumentDownload']) {
    const component=readFileSync(new URL(`./${name}.svelte`,import.meta.url),'utf8');
    for(const generate of ['client','server'] as const)expect(compile(component,{filename:`${name}.svelte`,generate}).warnings.filter(w=>w.code.startsWith('a11y'))).toEqual([]);
  }
});

const downloadFile = fileURLToPath(new URL('./DocumentDownload.svelte', import.meta.url));
const downloadSource = readFileSync(downloadFile, 'utf8'), downloadTree: any = parse(downloadSource, { modern: true });
function downloadFixture() {
  const calls: any[] = [], effects: any[] = [], timers = new Map<number, () => void>(); let timerID = 0;
  const env: any = { document: { id: 'doc', name: 'Contract', status: 'completed', updated_at: 'exact', pdf_sha256: 'a'.repeat(64) }, blocked: false,
    busy: false, downloadKind: 'pdf', error: null, disposed: false, revision: 0, controller: null, urls: new Set<string>(),
    documentDownloadName, fetch: () => { throw Error('Only the download port may fetch'); }, AbortController,
    fetchDocumentDownload: (...args: any[]) => new Promise((resolve, reject) => calls.push({ args, resolve, reject })),
    setTimeout: (callback: () => void, milliseconds: number) => { const id = ++timerID; timers.set(id, callback); return id; }, clearTimeout: (id: number) => timers.delete(id),
    URL: { createObjectURL: (blob: Blob) => { effects.push(['url', blob.type]); return 'blob:owned'; }, revokeObjectURL: (url: string) => effects.push(['revoke', url]) },
    window: { document: { body: { append: (link: any) => effects.push(['append', link.download]) }, createElement: () => ({ href: '', download: '', click() { effects.push(['click', this.download]); }, remove() { effects.push(['remove']); } }) } },
  };
  const functions = ['identity', 'download'].map(name => {
    const node = downloadTree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
    return downloadSource.slice(node.start, node.end);
  }).join('\n');
  const destroy = downloadTree.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression?.callee?.name === 'onDestroy').expression.arguments[0];
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions + '\nconst retire = ' + downloadSource.slice(destroy.start, destroy.end));
  const actions = new Function('env', `with(env) { ${code}; return {download,retire}; }`)(env);
  return { env, calls, effects, timers, ...actions };
}
test('actual package download callback uses the validated extension, dispatches once and retires its object URL', async () => {
  for (const type of ['application/pdf', 'application/zip']) {
    const f = downloadFixture(), pending = f.download('package'); await f.download('pdf');
    expect(f.calls).toHaveLength(1); expect(f.calls[0].args[3]).toBe('package'); expect(f.calls[0].args[1]).toBe(f.env.controller.signal);
    f.calls[0].resolve(new Blob(['fixture'], { type })); await pending;
    expect(f.effects).toContainEqual(['click', type === 'application/zip' ? 'Contract-evidence.zip' : 'Contract-evidence.pdf']);
    expect(f.env.busy).toBe(false); expect(f.env.urls.size).toBe(1);
    for (const retire of [...f.timers.values()]) retire();
    expect(f.env.urls.size).toBe(0); expect(f.effects).toContainEqual(['revoke', 'blob:owned']);
  }
});
test('package download retains blocked, changed-document, timeout and unmount fences without saving stale bytes', async () => {
  for (const state of ['blocked', 'different document', 'different parent', 'unmount', 'timeout']) {
    const f = downloadFixture(), pending = f.download('package');
    if (state === 'blocked') f.env.blocked = true;
    if (state === 'different document') f.env.document = { ...f.env.document, id: 'other' };
    if (state === 'different parent') f.env.document = { ...f.env.document, parent_envelope_id: 'parent' };
    if (state === 'unmount') f.retire();
    if (state === 'timeout') [...f.timers.values()][0]();
    f.calls[0].resolve(new Blob(['fixture'], { type: 'application/zip' })); await pending;
    expect(f.effects).toEqual([]); expect(f.env.urls.size).toBe(0);
    if (state === 'unmount' || state === 'timeout') expect(f.calls[0].args[1].aborted).toBe(true);
  }
  const blocked = downloadFixture(); blocked.env.blocked = true; await blocked.download('package'); expect(blocked.calls).toEqual([]);
  const retained = downloadFixture(), pending = retained.download('package'); retained.calls[0].resolve(new Blob(['fixture'], { type: 'application/zip' })); await pending;
  retained.retire(); expect(retained.env.urls.size).toBe(0); expect(retained.effects).toContainEqual(['revoke', 'blob:owned']);
});
test('actual EN/SV completed-root view exposes package export beside the existing signed PDF and certificate actions', async () => {
  const lib = resolve(dirname(downloadFile), '..');
  const built = await Bun.build({ entrypoints: ['download-view-entry'], target: 'bun', plugins: [{ name: 'actual-download-view', setup(build) {
    build.onResolve({ filter: /^download-view-entry$/ }, () => ({ path: 'entry', namespace: 'download-view' }));
    build.onLoad({ filter: /.*/, namespace: 'download-view' }, () => ({ contents: `import View from ${JSON.stringify(downloadFile)}; import {render} from 'svelte/server'; import {setStaffLocale} from ${JSON.stringify(join(lib, 'staffPreferences.ts'))}; export {View,render,setStaffLocale};`, loader: 'ts', resolveDir: process.cwd() }));
    build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
    build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
    build.onLoad({ filter: /\.svelte$/ }, args => ({ contents: compile(readFileSync(args.path, 'utf8'), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
  } }] });
  if (!built.success) throw Error(built.logs.map(String).join('\n'));
  const temporary = mkdtempSync(join(tmpdir(), 'hash-download-view-'));
  try {
    const file = join(temporary, 'view.mjs'); writeFileSync(file, await built.outputs[0].text()); const view = await import(pathToFileURL(file).href);
    for (const locale of ['en', 'sv']) {
      view.setStaffLocale(locale);
      const document = { id: 'doc', name: 'Contract', status: 'completed', updated_at: 'exact', requires_signature: true };
      const label = locale === 'sv' ? 'Exportera bevispaket' : 'Export evidence package';
      for (const parent_envelope_id of [undefined, null]) {
        const html = view.render(view.View, { props: { document: { ...document, parent_envelope_id } } }).body;
        expect(html).toContain(label); expect(html).toContain(locale === 'sv' ? 'Ladda ner signerad PDF' : 'Download signed PDF');
        expect(html).toContain(locale === 'sv' ? 'Ladda ner bevisrapport' : 'Download evidence report');
      }
      const blocked = view.render(view.View, { props: { document, blocked: true } }).body;
      const button = blocked.match(/<button\b[^>]*>[\s\S]*?<\/button>/g)?.find((html: string) => html.includes(label));
      expect(button).toContain('disabled');
      for (const status of ['draft', 'sent', 'finalizing', 'declined', 'voided', 'unknown']) expect(view.render(view.View, { props: { document: { ...document, status } } }).body).not.toContain(label);
      expect(view.render(view.View, { props: { document: { ...document, parent_envelope_id: 'parent' } } }).body).not.toContain(label);
    }
    view.setStaffLocale('en');
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
