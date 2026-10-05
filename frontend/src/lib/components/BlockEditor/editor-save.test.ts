import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../../api/client';

// Run the production function to verify async ordering without copying its logic.
const source = readFileSync(new URL('./Editor.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  async function persist()');
const end = source.indexOf('  function downloadLocalDraft()', start);
if (start < 0 || end < 0) throw new Error('persist function missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with (env) { ${code}; return persist; }`);
function fixture() {
 const calls: any[] = [];
 const env: any = {
  disposed:false, saveConflict:false, saving:false, saveQueued:false,
  editRevision:1, dirty:true, error:null, APIError,
  doc:{id:'document',updated_at:'first'}, latest:{text:'one'}, canonicalGeneration:'1',
  requestCheckpoint:async()=>({peerID:'peer',token:'token',generation:env.canonicalGeneration}),
  editor:{getJSON:()=>env.latest}, fromProseMirror:(value:any)=>value,
  changes:0, scheduled:0, disconnected:0,
  provider:{params:{expected_updated_at:'first'},disconnect:()=>env.disconnected++},
  onChange:()=>env.changes++, scheduleSave:()=>env.scheduled++,
  saveCollaborativeDocument:(id:string,patch:any)=>new Promise((resolve,reject)=>calls.push({id,patch,resolve,reject}))
 };
 return {env,calls,persist:bind(env) as ()=>Promise<void>};
}
test('in-flight edits retain dirty state and next save uses acknowledged timestamp',async()=>{
 const {env,calls,persist}=fixture(); const first=persist();await Promise.resolve();
 expect(calls[0].patch.expected_updated_at).toBe('first');
 env.latest={text:'two'};env.editRevision++;
 await persist();expect(calls).toHaveLength(1);
 calls[0].resolve({document:{id:'document',updated_at:'second'},generation:'2'});await first;
 expect(env.dirty).toBe(true);expect(env.changes).toBe(0);
 expect(env.provider.params.expected_updated_at).toBe('second');
 const second=persist();await Promise.resolve();
 expect(calls[1].patch).toEqual({peer_id:'peer',checkpoint:'token',generation:'2',expected_updated_at:'second',blocks_json:{text:'two'}});
 calls[1].resolve({document:{id:'document',updated_at:'third'},generation:'3'});await second;
 expect(env.dirty).toBe(false);expect(env.changes).toBe(1);
});
test('412 preserves local draft, disconnects and blocks future saves',async()=>{
 const {env,calls,persist}=fixture();const pending=persist();await Promise.resolve();
 calls[0].reject(new APIError(412,'Document changed'));await pending;
 expect(env.saveConflict).toBe(true);expect(env.disconnected).toBe(1);
 expect(env.dirty).toBe(true);expect(env.latest.text).toBe('one');
 expect(env.doc.updated_at).toBe('first');await persist();expect(calls).toHaveLength(1);
});
test('receipt after disposal neither updates timestamp nor notifies parent',async()=>{
 const {env,calls,persist}=fixture();const pending=persist();await Promise.resolve();env.disposed=true;
 calls[0].resolve({document:{id:'document',updated_at:'late'},generation:'2'});await pending;
 expect(env.doc.updated_at).toBe('first');expect(env.changes).toBe(0);expect(env.scheduled).toBe(0);
});

test('checkpoint replay precedes serialization and disposal during capture prevents HTTP save',async()=>{
 const {env,calls,persist}=fixture();let resolve:any;
 env.requestCheckpoint=()=>new Promise(r=>resolve=r);
 const pending=persist();expect(calls).toHaveLength(0);
 env.latest={text:'replayed'};env.editRevision++;
 resolve({peerID:'peer',token:'token',generation:'1'});await Promise.resolve();
 expect(calls[0].patch.blocks_json).toEqual({text:'replayed'});
 calls[0].resolve({document:{id:'document',updated_at:'second'},generation:'2'});await pending;
 expect(env.dirty).toBe(false);
 const second=fixture();second.env.requestCheckpoint=()=>new Promise(r=>resolve=r);
 const disposed=second.persist();second.env.disposed=true;
 resolve({peerID:'peer',token:'token',generation:'1'});await disposed;
 expect(second.calls).toHaveLength(0);
});

test('older HTTP save receipt cannot overwrite newer peer acknowledgement',async()=>{
 const {env,calls,persist}=fixture();const pending=persist();await Promise.resolve();
 env.canonicalGeneration='3';env.doc.updated_at='newer';env.provider.params.expected_updated_at='newer';env.editRevision++;
 calls[0].resolve({document:{id:'document',updated_at:'older'},generation:'2'});await pending;
 expect(env.doc.updated_at).toBe('newer');expect(env.canonicalGeneration).toBe('3');expect(env.dirty).toBe(true);
 expect(env.provider.params.expected_updated_at).toBe('newer');
});

test('malformed acknowledgement preserves local draft',async()=>{
 const {env,calls,persist}=fixture();const pending=persist();await Promise.resolve();
 calls[0].resolve({document:{id:'other',updated_at:'second'},generation:'2'});await pending;
 expect(env.dirty).toBe(true);expect(env.doc.updated_at).toBe('first');expect(env.error).toContain('Invalid canonical save receipt');
});

async function waitForCall(calls:any[],count:number){
 for(let i=0;i<12 && calls.length<count;i++)await Promise.resolve();
 if(calls.length!==count)throw new Error(`Expected ${count} save dispatches, got ${calls.length}`);
}

test('checkpoint conflict captures fresh state and retries without discarding draft',async()=>{
 const {env,calls,persist}=fixture();let captures=0;
 env.requestCheckpoint=async()=>({peerID:'peer',token:`checkpoint-${++captures}`,generation:'1'});
 const pending=persist();await waitForCall(calls,1);
 env.latest={text:'newer replay'};env.editRevision++;
 calls[0].reject(new APIError(409,'checkpoint advanced'));await waitForCall(calls,2);
 expect(calls[1].patch.checkpoint).toBe('checkpoint-2');
 expect(calls[1].patch.blocks_json).toEqual({text:'newer replay'});
 calls[1].resolve({document:{id:'document',updated_at:'second'},generation:'2'});await pending;
 expect(captures).toBe(2);expect(env.dirty).toBe(false);expect(env.disconnected).toBe(0);expect(env.saveConflict).toBe(false);
});

test('checkpoint conflict retry is bounded and exhaustion retains visible draft',async()=>{
 const {env,calls,persist}=fixture();const pending=persist();
 for(let i=0;i<3;i++){await waitForCall(calls,i+1);calls[i].reject(new APIError(409,'checkpoint advanced'));}
 await pending;
 expect(calls).toHaveLength(3);expect(env.dirty).toBe(true);expect(env.latest.text).toBe('one');
 expect(env.disconnected).toBe(0);expect(env.error).toBe('checkpoint advanced');expect(env.scheduled).toBe(0);
});
