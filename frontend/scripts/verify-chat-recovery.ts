// Rendered frontend acceptance with synthetic API fixtures; no real user/backend.
import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';
const base = process.env.HASH_PREVIEW_URL ?? 'http://127.0.0.1:5179';
const id='11111111-1111-4111-8111-111111111111';
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage();
 let reads=0;let posts=0;
 let releaseSend!:()=>void;
 const pendingSend=new Promise<void>(resolve=>{releaseSend=resolve;});
 await page.route('**/api/v1/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  let body:any={};let status=200;
  if(path===`/api/v1/documents/${id}/comments`){
   if(route.request().method()==='POST'){
    posts++;
    if(posts===1){status=503;body={error:'Synthetic send unavailable'};}
    else {await pendingSend;body={id:'posted',body:'submitted message'};}
   }
   else {reads++;if(reads===1){status=503;body={error:'Synthetic refresh unavailable'};}else body={comments:[{id:'comment',author_name:'Recipient',author_side:'signer',body:'Previously posted message',created_at:'2026-10-05T00:00:00Z'}]};}
  }else if(path===`/api/v1/documents/${id}`) body={id,name:'Synthetic negotiation',status:'sent',source_kind:'blocks',blocks_json:{version:1,blocks:[]},variables_json:{},requires_signature:true,default_locale:'en',created_at:'2026-10-05T00:00:00Z',updated_at:'2026-10-05T00:00:00.000001Z'};
  else if(path==='/api/v1/me')body={user_id:id,org_id:id,email:'fixture@example.test',role:'owner'};
  else if(path.endsWith('/preview')) {await route.fulfill({contentType:'text/html',body:'<p>Synthetic document preview</p>'});return;}
  else body={recipients:[],events:[],comments:[],requests:[],tokens:[],fields:[]};
  await route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
 });
 await page.goto(`${base}/documents/${id}`);
 await page.getByRole('heading',{name:'Synthetic negotiation',exact:true}).waitFor();
 const retry=page.getByRole('button',{name:'Retry message refresh'});
 await retry.waitFor();await retry.click();
 await page.getByText('Previously posted message',{exact:true}).waitFor();
 const draft=page.getByPlaceholder('Skriv en kommentar…');
 await draft.fill('Keep this draft after failure');
 await page.getByRole('button',{name:'Skicka kommentar',exact:true}).click();
 await page.getByRole('alert').filter({hasText:'Something went wrong on our side'}).waitFor();
 if(await draft.inputValue()!=='Keep this draft after failure')throw new Error('Failed send lost draft');
 if(!await page.getByText('Previously posted message',{exact:true}).isVisible())throw new Error('Failure hid loaded history');
 if(!await page.getByRole('heading',{name:'Synthetic negotiation',exact:true}).isVisible())throw new Error('Failure unmounted document');
 if(posts!==1||reads!==2)throw new Error(`Unexpected dispatch counts ${posts}/${reads}`);
 await draft.fill('submitted message');
 const submitted=page.waitForRequest(request=>request.method()==='POST'&&request.url().endsWith('/comments'));
 await page.getByRole('button',{name:'Skicka kommentar',exact:true}).click();
 await submitted;
 const posting=page.getByRole('button',{name:'Skickar…',exact:true});
 if(!await posting.isDisabled())throw new Error('Pending send permits duplicate submission');
 await draft.fill('next message draft');
 releaseSend();
 await page.getByRole('button',{name:'Skicka kommentar',exact:true}).waitFor();
 if(await draft.inputValue()!=='next message draft')throw new Error('Successful receipt erased newer draft');
 if(posts!==2||reads!==3)throw new Error(`Unexpected final dispatch counts ${posts}/${reads}`);
 console.log('PASS: rendered chat refresh/failure recovery and pending-send newer-draft retention');
} finally {await browser.close();}
