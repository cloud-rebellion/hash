import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APIError } from '../../api/client';

const source=readFileSync(new URL('./Editor.svelte',import.meta.url),'utf8');
const start=source.indexOf("    provider.on('connection-close', async");
const end=source.indexOf("    provider.awareness.on('change'",start);
if(start<0 || end<0)throw new Error('Production connection-close handler missing');
const code=new Bun.Transpiler({loader:'ts'}).transformSync(source.slice(start,end));
const bind=new Function('env',`with(env){${code}}`);
function fixture(getMe:any){
 const env:any={disposed:false,externalBusy:false,accessCheckPending:false,doc:{id:'doc',org_id:'tenant',updated_at:'observed'},saveConflict:false,collaborationRejected:false,connected:true,APIError,getMe,
 getDocument:async()=>({id:'doc',org_id:'tenant',source_kind:'blocks',status:'draft',updated_at:'observed'}),queued:[],queueCollaborationReconnect:(id:string)=>env.queued.push(id),
 canceled:0,disconnected:0,checkpointRequests:{cancel:()=>env.canceled++},provider:{shouldConnect:true,params:{expected_updated_at:'observed'},on:(_name:string,fn:any)=>env.callback=fn,disconnect:()=>env.disconnected++}};
 bind(env);return env;
}
test('concealed upgrade failure rechecks current role/tenant and preserves recovery warning',async()=>{
 for(const current of [{org_id:'tenant',role:'viewer'},{org_id:'other',role:'sender'}]){
 const env=fixture(async()=>current);await env.callback({code:1006});
 expect(env.collaborationRejected).toBe(true);expect(env.disconnected).toBe(1);expect(env.connected).toBe(false);expect(env.canceled).toBe(1);
 }
 for(const status of [401,403]){const env=fixture(async()=>{throw new APIError(status,'revoked')});await env.callback({code:1006});expect(env.collaborationRejected).toBe(true);}
});
test('authorized roles and transient outages retain reconnect behavior',async()=>{
 for(const role of ['owner','sender']){const env=fixture(async()=>({org_id:'tenant',role}));await env.callback({code:1006});expect(env.disconnected).toBe(0);expect(env.queued).toEqual(['doc']);}
 for(const error of [new TypeError('offline'),new APIError(500,'unavailable')]){const env=fixture(async()=>{throw error});await env.callback(null);expect(env.disconnected).toBe(0);expect(env.collaborationRejected).toBe(false);expect(env.queued).toEqual(['doc']);}
});

test('changed canonical observation is terminal without adopting the refreshed timestamp',async()=>{
 const env=fixture(async()=>({org_id:'tenant',role:'owner'}));
 env.getDocument=async()=>({id:'doc',org_id:'tenant',source_kind:'blocks',status:'draft',updated_at:'replacement'});
 await env.callback({code:1006});
 expect(env.collaborationRejected).toBe(true);expect(env.disconnected).toBe(1);expect(env.queued).toEqual([]);
 expect(env.doc.updated_at).toBe('observed');expect(env.provider.params.expected_updated_at).toBe('observed');
});

test('paused reconnect requires a matching fresh document and verified provider observation',async()=>{
 for(const changed of [{id:'other'},{org_id:'other'},{source_kind:'pdf'},{status:'sent'}]){
  const env=fixture(async()=>({org_id:'tenant',role:'owner'}));
  env.getDocument=async()=>({id:'doc',org_id:'tenant',source_kind:'blocks',status:'draft',updated_at:'observed',...changed});
  await env.callback({code:1006});expect(env.collaborationRejected).toBe(true);expect(env.queued).toEqual([]);
 }
 const unverified=fixture(async()=>({org_id:'tenant',role:'owner'}));
 unverified.doc.updated_at='adopted';unverified.getDocument=async()=>({id:'doc',org_id:'tenant',source_kind:'blocks',status:'draft',updated_at:'adopted'});
 await unverified.callback({code:1006});expect(unverified.collaborationRejected).toBe(true);
 expect(unverified.provider.params.expected_updated_at).toBe('observed');expect(unverified.queued).toEqual([]);
});

test('canonical lookup failures distinguish revoked documents from transient outages',async()=>{
 for(const status of [401,403,404,500]){
  const env=fixture(async()=>({org_id:'tenant',role:'owner'}));
  env.getDocument=async()=>{throw new APIError(status,'unavailable')};await env.callback({code:1006});
  expect(env.collaborationRejected).toBe(status!==500);expect(env.queued).toEqual(status===500?['doc']:[]);
 }
});

test('connection remains paused while document observation is pending and cannot resume after conflict',async()=>{
 let resolve:any;const env=fixture(async()=>({org_id:'tenant',role:'sender'}));
 env.getDocument=()=>new Promise(r=>resolve=r);
 const pending=env.callback({code:1006});for(let i=0;i<3;i++)await Promise.resolve();
 expect(env.provider.shouldConnect).toBe(false);expect(env.queued).toEqual([]);
 env.saveConflict=true;resolve({id:'doc',org_id:'tenant',source_kind:'blocks',status:'draft',updated_at:'observed'});await pending;
 expect(env.queued).toEqual([]);expect(env.disconnected).toBe(0);
});
test('policy refusal is terminal and late access check cannot mutate disposed editor',async()=>{
 const policy=fixture(()=>{throw new Error('must not fetch')});await policy.callback({code:1008});expect(policy.disconnected).toBe(1);
 let resolve:any;const late=fixture(()=>new Promise(r=>resolve=r));const pending=late.callback({code:1006});late.disposed=true;resolve({org_id:'tenant',role:'viewer'});await pending;expect(late.disconnected).toBe(0);expect(late.collaborationRejected).toBe(false);
});

test('repeated failed connections share one current access check',async()=>{
 let calls=0;let resolve:any;const env=fixture(()=>{calls++;return new Promise(r=>resolve=r)});
 const first=env.callback({code:1006});await env.callback({code:1006});expect(calls).toBe(1);
 resolve({org_id:'tenant',role:'sender'});await first;expect(env.accessCheckPending).toBe(false);
 const second=env.callback({code:1006});expect(calls).toBe(2);resolve({org_id:'tenant',role:'viewer'});await second;expect(env.disconnected).toBe(1);
});

test('intentional CRM pause does not trigger access reads, policy rejection or reconnect',async()=>{
 const env=fixture(()=>{throw new Error('must not read during CRM update')});env.externalBusy=true;await env.callback({code:1006});
 expect(env.queued).toEqual([]);expect(env.collaborationRejected).toBe(false);expect(env.disconnected).toBe(0);
});
