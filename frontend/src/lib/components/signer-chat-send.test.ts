import {expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../../routes/sign/[token]/+page.svelte',import.meta.url),'utf8');
const start=source.indexOf('  async function sendComment()');
const end=source.indexOf('  function onDocMouseUp()',start);
const code=new Bun.Transpiler({loader:'ts'}).transformSync(source.slice(start,end));
const bind=new Function('env',`with(env){${code};return sendComment;}`);
function fixture(){
 const calls:any[]=[];
 const env:any={ctx:{recipient:{id:'recipient'},privacy:{notice_digest:'digest'}},$page:{params:{token:'token'}},commentBody:'first',postingComment:false,noticeAcknowledged:true,signError:null,loaded:[],
 signerNoticeHeaders:(digest:string,accepted:boolean)=>({digest,accepted}),fetch:(url:string,options:any)=>new Promise((resolve,reject)=>calls.push({url,options,resolve,reject})),loadComments:async(token:string)=>env.loaded.push(token)};
 return{env,calls,send:bind(env) as ()=>Promise<void>};
}
test('signer chat serializes and preserves newer draft with exact notice headers',async()=>{
 const{env,calls,send}=fixture();const pending=send();await send();expect(calls).toHaveLength(1);
 expect(calls[0].options.headers).toEqual({digest:'digest',accepted:true});expect(JSON.parse(calls[0].options.body)).toEqual({body:'first'});
 env.commentBody='next';calls[0].resolve({ok:true});await pending;
 expect(env.commentBody).toBe('next');expect(env.loaded).toEqual(['token']);expect(env.postingComment).toBe(false);
});
test('signer HTTP failure is visible and preserves draft',async()=>{
 const{env,calls,send}=fixture();const pending=send();calls[0].resolve({ok:false,status:503});await pending;
 expect(env.signError).toContain('HTTP 503');expect(env.commentBody).toBe('first');expect(env.loaded).toEqual([]);expect(env.postingComment).toBe(false);
});
test('late response cannot mutate another recipient route',async()=>{
 for(const ok of [true,false]){
  const{env,calls,send}=fixture();const pending=send();env.$page.params.token='new';env.ctx.recipient.id='new';env.commentBody='new draft';env.signError='new error';env.postingComment=true;
  calls[0].resolve({ok,status:503});await pending;
  expect(env.commentBody).toBe('new draft');expect(env.signError).toBe('new error');expect(env.postingComment).toBe(true);expect(env.loaded).toEqual([]);
 }
});
test('unacknowledged notice blocks message dispatch',async()=>{
 const{env,calls,send}=fixture();env.noticeAcknowledged=false;await send();
 expect(calls).toHaveLength(0);expect(env.commentBody).toBe('first');expect(env.signError).toContain('privacy notice');
});
