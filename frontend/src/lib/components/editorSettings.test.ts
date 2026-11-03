import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { compile, parse } from 'svelte/compiler';

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
