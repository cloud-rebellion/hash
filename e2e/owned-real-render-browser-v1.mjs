// Trusted owned-fixture driver. Run from the candidate e2e directory with its
// frozen Bun/Playwright dependencies. Bootstrap arrives only on stdin:
// { packet:<fresh private backend packet>, donePath:<absolute host path>,
//   artifacts:<absolute0700 host directory> }. Never pass ceremony tokens in argv.
import { chromium, expect } from '@playwright/test';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const validID=value=>typeof value==='string'&&UUID.test(value)&&value!=='00000000-0000-0000-0000-000000000000';
const token=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{32,256}$/.test(value);
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const fail=()=>{throw new Error('invalid owned browser handoff');};

// Pure validation runs before filesystem writes or browser/network dispatch.
export function validateOwnedRealRenderHandoffV1(bootstrap){
 if(!bootstrap||typeof bootstrap!=='object'||Array.isArray(bootstrap))fail();
 const p=bootstrap.packet;
 if(!p||typeof p!=='object'||Array.isArray(p))fail();
 let base;try{base=new URL(p.base);}catch{fail();}
 if(base.protocol!=='https:'||base.hostname!=='127.0.0.1'||!base.port||base.pathname!=='/'||base.search||base.hash||base.username||base.password||base.origin!==p.base)fail();
 for(const value of [bootstrap.donePath,bootstrap.artifacts])if(typeof value!=='string'||!path.isAbsolute(value)||path.normalize(value)!==value||value===path.parse(value).root)fail();
 if(bootstrap.donePath===bootstrap.artifacts)fail();
 if(!validID(p.documentID)||!SHA.test(p.pdfSHA256)||!SHA.test(p.sourceCommitment)||!Number.isInteger(p.pageCount)||p.pageCount<2||p.pageCount>12||p.materializationRevision!==1||p.rendererVersion!=='8.36.0-hash.5'||!/^sha256:[0-9a-f]{64}$/.test(p.rendererImageID))fail();
 if(!Array.isArray(p.parties)||p.parties.length!==2)fail();
 const seen=new Set();
 for(const party of p.parties){if(!party||!token(party.token)||!validID(party.recipientID)||!validID(party.fieldID)||typeof party.name!=='string'||!party.name||party.name.length>300||seen.has(party.token)||seen.has(party.recipientID)||seen.has(party.fieldID))fail();seen.add(party.token);seen.add(party.recipientID);seen.add(party.fieldID);}
 const legacy=p.legacy;
 if(!legacy||!token(legacy.token)||!validID(legacy.documentID)||legacy.documentID===p.documentID||!validID(legacy.recipientID)||!validID(legacy.textFieldID)||!validID(legacy.signatureFieldID)||legacy.textFieldID===legacy.signatureFieldID||legacy.pageCount!==p.pageCount||!SHA.test(legacy.pdfSHA256)||typeof legacy.name!=='string'||!legacy.name||seen.has(legacy.token)||seen.has(legacy.recipientID))fail();
 for(const [list,expected] of [[p.fieldGeometry,2],[p.legacyGeometry,2]]){
  if(!Array.isArray(list)||list.length!==expected)fail();
  const ids=new Set();for(const field of list){if(!field||!validID(field.id)||!validID(field.recipient_id)||ids.has(field.id)||!Number.isInteger(field.page)||field.page<1||field.page>p.pageCount||!['text','signature'].includes(field.type))fail();ids.add(field.id);for(const key of ['x_pct','y_pct','w_pct','h_pct'])if(typeof field[key]!=='number'||!Number.isFinite(field[key]))fail();if(field.x_pct<0||field.y_pct<0||field.w_pct<=0||field.h_pct<=0||field.x_pct+field.w_pct>100||field.y_pct+field.h_pct>100)fail();}
 }
 for(const party of p.parties){const own=p.fieldGeometry.filter(f=>f.id===party.fieldID&&f.recipient_id===party.recipientID&&f.type==='signature');if(own.length!==1)fail();}
 for(const [id,type]of [[legacy.textFieldID,'text'],[legacy.signatureFieldID,'signature']])if(p.legacyGeometry.filter(f=>f.id===id&&f.recipient_id===legacy.recipientID&&f.type===type).length!==1)fail();
 return bootstrap;
}

async function readBootstrap(){let size=0;const chunks=[];for await(const chunk of process.stdin){size+=chunk.length;if(size>65536)fail();chunks.push(chunk);}return validateOwnedRealRenderHandoffV1(JSON.parse(Buffer.concat(chunks).toString('utf8')));}

export async function runOwnedRealRenderBrowserV1(bootstrap){
 validateOwnedRealRenderHandoffV1(bootstrap);
 const {packet:p,donePath,artifacts}=bootstrap;
 // Output is fresh; no prior success packet can satisfy the backend rendezvous.
 try{await fs.lstat(donePath);throw new Error('completion path already exists');}catch(error){if(error?.code!=='ENOENT')throw error;}
 await fs.mkdir(artifacts,{recursive:true,mode:0o700});await fs.chmod(artifacts,0o700);
 const deadline=Date.now()+145000;let browser;let timedOut=false;
 const timer=setTimeout(()=>{timedOut=true;void browser?.close().catch(()=>{});},145000);
 const observations=[];const runtimeErrors=[];let foreignRequests=0;let closed=false;let verified=false;
 const remaining=(limit=20000)=>{const value=Math.min(limit,deadline-Date.now());if(value<=0)throw new Error('owned browser deadline');return value;};
 const boundedExpect=locator=>expect(locator);
 try{
  browser=await chromium.launch({headless:true,timeout:remaining(30000)});
  const browserVersion=browser.version();
  async function visit(party,label,geometry,manual=false){
   // HTTPS errors are tolerated only for this exact synthetic loopback origin.
   // This does not establish production TLS trust or change the renderer client.
   const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1200},locale:'en-US'});
   context.setDefaultTimeout(remaining());
   await context.addInitScript(()=>{window.__hashOwnedCSP=[];window.addEventListener('securitypolicyviolation',event=>window.__hashOwnedCSP.push(event.violatedDirective));});
   await context.route('**/*',async route=>{const u=new URL(route.request().url());if(['http:','https:'].includes(u.protocol)&&u.origin!==p.base){foreignRequests++;await route.abort();return;}await route.continue();});
   const page=await context.newPage();
   page.on('pageerror',()=>runtimeErrors.push(label+':pageerror'));
   page.on('console',message=>{if(message.type()==='error')runtimeErrors.push(label+':console-error');});
   const signPath='/sign/'+party.token;
   const observedPDF=page.waitForResponse(response=>new URL(response.url()).pathname===signPath+'/pdf'&&response.request().method()==='GET',{timeout:remaining()});observedPDF.catch(()=>{});
   await page.goto(p.base+signPath,{waitUntil:'domcontentloaded',timeout:remaining()});
   const notice=page.getByRole('dialog',{name:'Before you respond: how we handle your data'});
   await boundedExpect(notice).toBeVisible({timeout:remaining()});
   await boundedExpect(notice).toContainText('fixed 7-year evidence-retention policy');
   await boundedExpect(notice).not.toContainText(/statutory|legal obligation|legally[- ]binding/i);
   await notice.getByRole('button',{name:'I understand, continue'}).click();
   await boundedExpect(notice).toBeHidden({timeout:remaining()});
   const response=await observedPDF;const headers=response.headers();const pdf=await response.body();
   if(response.status()!==200||!headers['content-type']?.startsWith('application/pdf')||!headers['cache-control']?.includes('no-store')||pdf.subarray(0,5).toString()!=='%PDF-')throw new Error('actual browser PDF response contract');
   if(manual&&(sha(pdf)!==p.legacy.pdfSHA256||headers['x-hash-pdf-sha256']!==p.legacy.pdfSHA256))throw new Error('actual manual source/PDF witness mismatch');
   if(!manual&&(sha(pdf)!==p.pdfSHA256||headers['x-hash-pdf-sha256']!==p.pdfSHA256||headers['x-hash-pdf-pages']!==String(p.pageCount)||headers['x-hash-html-source-commitment']!==p.sourceCommitment||headers['x-hash-materialization-revision']!=='1'))throw new Error('actual browser HTML/source/PDF witness mismatch');
   const ready=page.locator('.pdf-signer');
   await boundedExpect(ready).toHaveAttribute('data-pdf-ready','true',{timeout:remaining()});
   await boundedExpect(ready).toHaveAttribute('data-pdf-page-count',String(p.pageCount));
   await boundedExpect(ready.locator('canvas')).toHaveCount(p.pageCount);
   await page.evaluate(()=>document.fonts.ready);
   const raster=await ready.locator('canvas').evaluateAll(nodes=>nodes.map(canvas=>{const small=document.createElement('canvas');small.width=128;small.height=128;const context=small.getContext('2d');if(!context)return 0;context.fillStyle='white';context.fillRect(0,0,128,128);context.drawImage(canvas,0,0,128,128);const data=context.getImageData(0,0,128,128).data;let ink=0;for(let i=0;i<data.length;i+=4)if(data[i+3]>0&&(data[i]<245||data[i+1]<245||data[i+2]<245))ink++;return ink;}));
   if(raster.length!==p.pageCount||raster.some(ink=>ink<5))throw new Error('actual PDF page raster is blank');
   const expected=geometry.filter(field=>field.recipient_id===party.recipientID);
   const seenFields=await ready.locator('[data-field-id]').evaluateAll(nodes=>nodes.map(n=>({id:n.getAttribute('data-field-id'),recipient:n.getAttribute('data-recipient-id')})));
   if(seenFields.length!==expected.length||seenFields.some(field=>!expected.some(want=>want.id===field.id&&want.recipient_id===field.recipient)))throw new Error('browser field/party scope mismatch');
   const boxes=[];
   for(const field of expected){const element=page.locator('[data-field-id="'+field.id+'"]');await element.scrollIntoViewIfNeeded();const measured=await element.evaluate(node=>{const r=node.getBoundingClientRect();const canvas=node.closest('.page')?.querySelector('canvas');const c=canvas?.getBoundingClientRect();return c?{field:{x:r.x,y:r.y,w:r.width,h:r.height},canvas:{x:c.x,y:c.y,w:c.width,h:c.height},ink:canvas.width>0&&canvas.height>0,page:Array.from(document.querySelectorAll('.pdf-signer .page')).indexOf(node.closest('.page'))+1}:null;});if(!measured?.ink||measured.page!==field.page)throw new Error('actual PDF canvas/page unavailable');const x=(measured.field.x-measured.canvas.x)/measured.canvas.w*100,y=(measured.field.y-measured.canvas.y)/measured.canvas.h*100,w=measured.field.w/measured.canvas.w*100,h=measured.field.h/measured.canvas.h*100;if(Math.abs(x-field.x_pct)>0.5||Math.abs(y-field.y_pct)>0.5||Math.abs(w-field.w_pct)>0.5||Math.abs(h-field.h_pct)>0.5)throw new Error('visible field/canvas geometry changed');boxes.push({id:field.id,page:field.page,x_pct:x,y_pct:y,w_pct:w,h_pct:h});}
   await page.screenshot({path:path.join(artifacts,label+'-before.png'),fullPage:true});
   if(await page.evaluate(tokens=>Object.keys(localStorage).some(key=>tokens.some(token=>key.includes(token))),[party.token]))throw new Error('ceremony token persisted in browser key');
   await boundedExpect(page.getByPlaceholder('Type your full name')).toHaveValue(party.name);
   if(manual){
    const input=page.locator('input[data-field-id="'+p.legacy.textFieldID+'"]');const signature=page.locator('button[data-field-id="'+p.legacy.signatureFieldID+'"]');
    await boundedExpect(signature).toBeDisabled();
    const saved=page.waitForResponse(response=>new URL(response.url()).pathname===signPath+'/fields'&&response.request().method()==='POST',{timeout:remaining()});saved.catch(()=>{});
    await input.fill('Agreed browser reference ÅÄÖ');await input.press('Tab');
    const saveResponse=await saved;const savedJSON=await saveResponse.json();
    if(saveResponse.status()!==200||savedJSON.updated?.length!==1||savedJSON.updated[0].id!==p.legacy.textFieldID||savedJSON.updated[0].value!=='Agreed browser reference ÅÄÖ'||savedJSON.updated[0].recipient_id!==party.recipientID)throw new Error('actual server autosave confirmation missing');
    await boundedExpect(input).toHaveAttribute('aria-busy','false',{timeout:remaining()});await boundedExpect(signature).toBeEnabled({timeout:remaining()});
   }
   const adopted=page.getByRole('button',{name:'Adopt and sign',exact:true});await boundedExpect(adopted).toBeEnabled({timeout:remaining()});await adopted.click();
   await boundedExpect(page.getByRole('heading',{name:'Adopt your signature',exact:true})).toBeVisible({timeout:remaining()});
   const font=label==='party-2'?'Dancing Script':'Caveat';const choice=page.locator('.font-option').filter({hasText:font});await boundedExpect(choice).toHaveCount(1);await choice.click();
   await boundedExpect(choice).toHaveClass(/selected/);await page.evaluate(()=>document.fonts.ready);
   const faceLoaded=await page.evaluate(family=>Array.from(document.fonts).some(face=>face.family.replaceAll('"','').replaceAll("'",'')===family&&face.status==='loaded'),font);
   if(!faceLoaded)throw new Error('selected first-party browser signature font not loaded');
   const signed=page.waitForResponse(response=>new URL(response.url()).pathname===signPath+'/sign'&&response.request().method()==='POST',{timeout:remaining(65000)});signed.catch(()=>{});
   await page.getByRole('button',{name:'Sign with this signature',exact:true}).click();
   const signResponse=await signed;const result=await signResponse.json();
   if(signResponse.status()!==200||typeof result.completed!=='boolean')throw new Error('actual native browser signature response missing');
   await boundedExpect(page.getByRole('heading',{name:'Signed',exact:true})).toBeVisible({timeout:remaining(65000)});
   const terminal=manual||label==='party-2';if(result.completed!==terminal)throw new Error('actual native party completion order differs');
   let finalHash=null;
   if(terminal){const link=page.getByRole('link',{name:'Download signed PDF',exact:true});await boundedExpect(link).toHaveAttribute('href',/^\/sign\/[A-Za-z0-9_-]+\/final-pdf$/);const href=await link.getAttribute('href');if(href===signPath+'/final-pdf')throw new Error('completed artifact credential did not rotate');const final=await context.request.get(p.base+href,{timeout:remaining()});const raw=await final.body();if(final.status()!==200||raw.subarray(0,5).toString()!=='%PDF-')throw new Error('actual completed PDF download missing');finalHash=sha(raw);if((await context.request.get(p.base+signPath+'/final-pdf',{timeout:remaining()})).status()!==404)throw new Error('old ceremony credential retained final artifact authority');}
   else await boundedExpect(page.getByRole('link',{name:'Download signed PDF',exact:true})).toHaveCount(0);
   if((await page.evaluate(()=>window.__hashOwnedCSP)).length!==0)throw new Error('actual browser CSP violation');
   await page.screenshot({path:path.join(artifacts,label+'-signed.png'),fullPage:true});
   observations.push({label,document_id:manual?p.legacy.documentID:p.documentID,recipient_id:party.recipientID,font,source_pdf_sha256:sha(pdf),pages:p.pageCount,page_thumbnail_ink_pixels:raster,field_geometry:boxes,autosave_confirmed:manual,completed:result.completed,final_pdf_sha256:finalHash});
   await context.close();
  }
  await visit({...p.legacy,fieldID:p.legacy.signatureFieldID},'manual-autosave',p.legacyGeometry,true);
  for(let i=0;i<2;i++)await visit(p.parties[i],'party-'+(i+1),p.fieldGeometry);
  // After the second party completes, the first party's old mutation-capable
  // invitation cannot become a final-artifact credential either.
  const stale=await browser.newContext({ignoreHTTPSErrors:true});
  if((await stale.request.get(p.base+'/sign/'+p.parties[0].token+'/final-pdf',{timeout:remaining()})).status()!==404)throw new Error('first original invitation retained terminal artifact access');
  await stale.close();
  if(timedOut||foreignRequests!==0||runtimeErrors.length!==0)throw new Error('browser runtime/security observations failed');
  await browser.close();closed=true;
  await fs.writeFile(path.join(artifacts,'browser-receipt.json'),JSON.stringify({schema:1,result:'pass',scope:'Actual built SPA/PDF.js/browser HTTP; synthetic local fixture only. Backend four-artifact and outer actual image/process/visual receipts remain separately required.',browser_version:browserVersion,renderer_version:p.rendererVersion,renderer_image_id_supplied_by_root:p.rendererImageID,observations,foreign_request_attempts:foreignRequests,browser_error_count:runtimeErrors.length,browser_close_returned:closed},null,2)+'\n',{mode:0o600,flag:'wx'});
  verified=true;
 }finally{
  clearTimeout(timer);if(browser&&!closed)await browser.close().catch(()=>{});
  // The backend requires this exact terminal contract. Success is written only
  // after browser observations and close returned; it is no process-group proof.
  await fs.writeFile(donePath,JSON.stringify({exit_code:verified?0:1,verified})+'\n',{mode:0o600,flag:'wx'});
 }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 try{await runOwnedRealRenderBrowserV1(await readBootstrap());}
 catch(error){process.stderr.write('owned real-render browser acceptance failed ('+(error?.name==='TimeoutError'?'timeout':'refused')+')\n');process.exitCode=1;}
}
