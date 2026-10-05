import {expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../../routes/documents/[id]/+page.svelte',import.meta.url),'utf8');
const start=source.indexOf('  async function loadComments(');const end=source.indexOf('  async function sendComment()',start);
const guards=source.slice(source.indexOf('  function isCurrentRoute('),source.indexOf('  async function toggleSignatureMode()'));
const code=new Bun.Transpiler({loader:'ts'}).transformSync(guards+source.slice(start,end));
const bind=new Function('env',`with(env){${code};return loadComments;}`);
function fixture(){const calls:any[]=[];const env:any={doc:{id:'d'},$page:{params:{id:'d'}},routeRevision:1,documentRevision:1,disposed:false,commentLoadRevision:0,comments:['retained'],commentRefreshError:null,listComments:()=>new Promise((resolve,reject)=>calls.push({resolve,reject}))};return{env,calls,load:bind(env) as (id:string)=>Promise<void>};}
test('failed chat refresh retains existing thread and reports failure',async()=>{const{env,calls,load}=fixture();const pending=load('d');calls[0].reject(new Error('Unavailable'));await pending;expect(env.comments).toEqual(['retained']);expect(env.commentRefreshError).toContain('could not be refreshed');});
test('older refresh cannot overwrite newer history or report stale failure',async()=>{for(const fail of [false,true]){const{env,calls,load}=fixture();const older=load('d');const newer=load('d');calls[1].resolve({comments:['new']});await newer;if(fail)calls[0].reject(new Error('old failure'));else calls[0].resolve({comments:['old']});await older;expect(env.comments).toEqual(['new']);expect(env.commentRefreshError).toBe(null);}});
test('late refresh cannot replace another document thread',async()=>{const{env,calls,load}=fixture();const pending=load('d');env.doc.id='other';calls[0].resolve({comments:['wrong document']});await pending;expect(env.comments).toEqual(['retained']);});
