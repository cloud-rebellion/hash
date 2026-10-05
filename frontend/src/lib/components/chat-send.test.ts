import {expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../../routes/documents/[id]/+page.svelte',import.meta.url),'utf8');
const start=source.indexOf('  async function sendComment()');
const end=source.indexOf('  async function loadChangeRequests',start);
const guards=source.slice(source.indexOf('  function isCurrentRoute('),source.indexOf('  async function toggleSignatureMode()'));
const code=new Bun.Transpiler({loader:'ts'}).transformSync(guards+source.slice(start,end));
const bind=new Function('env',`with(env){${code};return sendComment;}`);
function fixture(){
 const calls:any[]=[];const env:any={doc:{id:'d'},$page:{params:{id:'d'}},routeRevision:1,documentRevision:1,disposed:false,commentBody:'first',postingComment:false,error:null,loaded:[],
 postComment:(...args:any[])=>new Promise((resolve,reject)=>calls.push({args,resolve,reject})),loadComments:async(id:string)=>env.loaded.push(id)};
 return{env,calls,send:bind(env) as ()=>Promise<void>};
}
test('chat serializes sends and keeps text typed while posting',async()=>{
 const{env,calls,send}=fixture();const pending=send();await send();expect(calls).toHaveLength(1);
 env.commentBody='next draft';calls[0].resolve({});await pending;
 expect(env.commentBody).toBe('next draft');expect(env.loaded).toEqual(['d']);expect(env.postingComment).toBe(false);
});
test('chat failure preserves draft and reports error',async()=>{
 const{env,calls,send}=fixture();const pending=send();calls[0].reject(new Error('Unavailable'));await pending;
 expect(env.commentBody).toBe('first');expect(env.error).toBe('Unavailable');expect(env.loaded).toEqual([]);
});
