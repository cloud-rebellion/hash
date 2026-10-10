import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../../api/client';
const source = readFileSync(new URL('./Editor.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  async function runImport()');
const end = source.indexOf('</script>', start);
const code = new Bun.Transpiler({loader:'ts'}).transformSync(source.slice(start,end));
const bind = new Function('env', `with(env){${code};return runImport;}`);
function fixture() {
 const calls:any[]=[];
 const env:any={saving:false,saveConflict:false,disposed:false,externalBusy:false,showImport:'html',saveTimer:null,editRevision:1,saveQueued:false,error:null,dirty:true,importText:'input',doc:{id:'d',updated_at:'old'},APIError,clearTimeout,
 changes:0,contents:[],disconnected:0,scheduled:0,toProseMirror:(v:any)=>v,
 editor:{commands:{setContent:(v:any)=>env.contents.push(v)}},provider:{disconnect:()=>env.disconnected++},onChange:()=>env.changes++,scheduleSave:()=>env.scheduled++,
 importHTML:(...args:any[])=>new Promise((resolve,reject)=>calls.push({args,resolve,reject}))};
 return {env,calls,run:bind(env) as ()=>Promise<void>};
}
test('import serializes requests and preserves edits made in flight',async()=>{
 const {env,calls,run}=fixture();const pending=run();await run();expect(calls.length).toBe(1);
 env.editRevision++;calls[0].resolve({updated_at:'new',blocks_json:'import'});await pending;
 expect(env.contents.length).toBe(0);expect(env.dirty).toBe(true);expect(env.saveConflict).toBe(true);expect(env.disconnected).toBe(1);expect(env.importText).toBe('input');
});
test('acknowledged import updates document and clears dirty state',async()=>{
 const {env,calls,run}=fixture();const pending=run();expect(calls[0].args).toEqual(['d','input','old']);
 calls[0].resolve({updated_at:'new',blocks_json:'import'});await pending;
 expect(env.contents).toEqual(['import']);expect(env.dirty).toBe(false);expect(env.changes).toBe(1);expect(env.saving).toBe(false);
});
test('disposed import receipt cannot replace editor or notify parent',async()=>{
 const {env,calls,run}=fixture();const pending=run();env.disposed=true;
 calls[0].resolve({updated_at:'new',blocks_json:'import'});await pending;
 expect(env.contents.length).toBe(0);expect(env.changes).toBe(0);expect(env.doc.updated_at).toBe('old');
});

test('stale import retains input and draft without scheduling queued writes',async()=>{
 const {env,calls,run}=fixture();const pending=run();env.saveQueued=true;
 calls[0].reject(new APIError(412,'Document changed'));await pending;
 expect(env.saveConflict).toBe(true);expect(env.disconnected).toBe(1);
 expect(env.importText).toBe('input');expect(env.showImport).toBe('html');
 expect(env.dirty).toBe(true);expect(env.doc.updated_at).toBe('old');
 expect(env.contents).toEqual([]);expect(env.scheduled).toBe(0);expect(env.saving).toBe(false);
 await run();expect(calls).toHaveLength(1);
});

test('failed import preserves source input and resumes a queued ordinary save',async()=>{
 const {env,calls,run}=fixture();const pending=run();env.saveQueued=true;
 calls[0].reject(new APIError(503,'Import unavailable'));await pending;
 expect(env.error).toBe('Import unavailable');expect(env.saveConflict).toBe(false);
 expect(env.importText).toBe('input');expect(env.doc.updated_at).toBe('old');
 expect(env.contents).toEqual([]);expect(env.scheduled).toBe(1);expect(env.saving).toBe(false);
});

test('rejected import after disposal neither reports error nor schedules saves',async()=>{
 const {env,calls,run}=fixture();const pending=run();env.disposed=true;env.saveQueued=true;
 calls[0].reject(new APIError(412,'Document changed'));await pending;
 expect(env.error).toBe(null);expect(env.disconnected).toBe(0);expect(env.scheduled).toBe(0);
});

test('external CRM lock prevents imports and late replacement adoption without discarding source input',async()=>{
 const locked=fixture();locked.env.externalBusy=true;await locked.run();expect(locked.calls).toEqual([]);expect(locked.env.importText).toBe('input');
 const late=fixture();const pending=late.run();late.env.externalBusy=true;late.calls[0].resolve({updated_at:'new',blocks_json:'replacement'});await pending;
 expect(late.env.contents).toEqual([]);expect(late.env.changes).toBe(0);expect(late.env.dirty).toBe(true);expect(late.env.importText).toBe('input');
});
