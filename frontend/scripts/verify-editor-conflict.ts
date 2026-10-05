// Synthetic REST conflict fixture; no backend/authentication/CRDT transport proof.
import {chromium} from '../../../brightcrm/tests/e2e/node_modules/playwright';
const base=process.env.HASH_PREVIEW_URL??'http://127.0.0.1:5179';
const id='22222222-2222-4222-8222-222222222222';
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage();let writes=0;let observation:string|undefined;
 await page.route('**/api/v1/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  let body:any={recipients:[],events:[],tokens:[],fields:[]};let status=200;
  if(path===`/api/v1/documents/${id}`){
   if(route.request().method()==='PATCH'){writes++;observation=route.request().postDataJSON().expected_updated_at;status=412;body={error:'Document changed since observation'};}
   else body={id,name:'Conflict fixture',status:'draft',source_kind:'blocks',blocks_json:{version:1,blocks:[]},variables_json:{},requires_signature:true,default_locale:'en',created_at:'2026-10-05T00:00:00Z',updated_at:'2026-10-05T00:00:00.000001Z'};
  }else if(path==='/api/v1/me')body={user_id:id,org_id:id,email:'fixture@example.test',role:'owner'};
  await route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
 });
 await page.goto(`${base}/documents/${id}`);
 const editor=page.locator('.tiptap[contenteditable="true"]');await editor.waitFor();
 await editor.fill('Retain this unsaved draft');
 await page.getByRole('alert').filter({hasText:'The document changed since your last save'}).waitFor();
 if(!await editor.innerText().then(text=>text.includes('Retain this unsaved draft')))throw new Error('Conflict lost editor text');
 if(writes!==1||observation!=='2026-10-05T00:00:00.000001Z')throw new Error('Conflict submission incorrect');
 const download=page.waitForEvent('download');
 await page.getByRole('button',{name:'Download local draft',exact:true}).first().click();
 const artifact=await download;
 await artifact.saveAs('/private/tmp/hash-rendered-conflict-draft.json');
 const raw=await Bun.file('/private/tmp/hash-rendered-conflict-draft.json').text();
 if(!raw.includes('Retain this unsaved draft'))throw new Error('Recovery download missing draft');
 const leaveDialog=page.waitForEvent('dialog');
 const leaveClick=page.getByRole('link',{name:'Back to documents'}).click();
 const prompt=await leaveDialog;
 if(prompt.type()!=='confirm'||!prompt.message().includes('unsaved document changes'))throw new Error('Missing unsaved-draft prompt');
 await prompt.dismiss();await leaveClick;
 if(new URL(page.url()).pathname!==`/documents/${id}`)throw new Error('Declining prompt navigated away');
 if(!await editor.innerText().then(text=>text.includes('Retain this unsaved draft')))throw new Error('Declining prompt lost draft');
 console.log('PASS: rendered editor412 recovery/download and rejected navigation retain draft');
} finally {await browser.close();}
