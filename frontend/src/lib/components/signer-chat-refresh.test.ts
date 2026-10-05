import {expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../../routes/sign/[token]/+page.svelte',import.meta.url),'utf8');
const start=source.indexOf('  async function loadComments(');const end=source.indexOf('  async function sendComment()',start);
const code=new Bun.Transpiler({loader:'ts'}).transformSync(source.slice(start,end));
const bind=new Function('env',`with(env){${code};return loadComments;}`);
function fixture(){const calls:any[]=[];const env:any={$page:{params:{token:'t'}},ctx:{recipient:{id:'r'}},commentLoadRevision:0,comments:['retained'],commentRefreshError:null,fetch:()=>new Promise((resolve,reject)=>calls.push({resolve,reject}))};return{env,calls,load:bind(env) as (token?:string,signal?:AbortSignal)=>Promise<void>};}
test('signer refresh failure retains thread and displays HTTP error',async()=>{const{env,calls,load}=fixture();const pending=load();calls[0].resolve({ok:false,status:503});await pending;expect(env.comments).toEqual(['retained']);expect(env.commentRefreshError).toContain('HTTP 503');});
test('older signer refresh cannot replace newer thread',async()=>{const{env,calls,load}=fixture();const old=load();const fresh=load();calls[1].resolve({ok:true,json:async()=>({comments:['new']})});await fresh;calls[0].resolve({ok:true,json:async()=>({comments:['old']})});await old;expect(env.comments).toEqual(['new']);});
test('aborted signer refresh cannot report error',async()=>{const{env,calls,load}=fixture();const controller=new AbortController();const pending=load('t',controller.signal);controller.abort();calls[0].reject(new Error('aborted'));await pending;expect(env.commentRefreshError).toBe(null);expect(env.comments).toEqual(['retained']);});
