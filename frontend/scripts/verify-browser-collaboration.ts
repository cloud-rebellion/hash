// Rendered editors, actual Go HTTPS/WebSocket routes and PostgreSQL; synthetic sessions.
import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';
const fixture = JSON.parse(await Bun.stdin.text()) as { base:string; documentID:string; cookieName:string; cookies:string[]; userIDs:string[] };
async function waitForContent(page:any,expected:string) {
  await page.waitForFunction((text:string) => {
    const root=document.querySelector('.tiptap');
    if(!root)return false;
    const content=root.cloneNode(true) as HTMLElement;
    content.querySelectorAll('.collaboration-carets__caret,.collaboration-carets__label').forEach(node=>node.remove());
    return content.textContent===text;
  },expected);
}
const browser = await chromium.launch({ headless:true });
const errors:string[]=[];
let pages:any[]=[];
let stage="initialization";
try {
  const contexts = await Promise.all([0,1].map(async (index) => {
    const context = await browser.newContext({ ignoreHTTPSErrors:true });
    await context.addCookies([{ name:fixture.cookieName,value:fixture.cookies[index],url:fixture.base,httpOnly:true,secure:true,sameSite:'Lax' }]);
    return context;
  }));
  for (const [index,context] of contexts.entries()) {
    const response=await context.request.get(`${fixture.base}/api/v1/me`);
    const me=await response.json();
    if(!response.ok() || me.user_id!==fixture.userIDs[index] || me.role!==['owner','sender'][index]) throw new Error('Distinct authenticated identity/role missing');
  }
  pages = await Promise.all(contexts.map(context => context.newPage()));
  for (const page of pages) { page.setDefaultTimeout(10000); page.on('pageerror',(error:Error) => errors.push(error.message)); }
  const url = `${fixture.base}/documents/${fixture.documentID}`;
  await Promise.all(pages.map(page => page.goto(url)));
  const editors = pages.map(page => page.locator('.tiptap[contenteditable="true"]'));
  stage="canonical initialization";
  for (const editor of editors) {
    await editor.waitFor();
    await waitForContent(editor.page(),'Initial contract');
    if (await editor.locator('p').count() !== 1) throw new Error('Initial canonical seed duplicated');
  }
  stage="first edit relay";
  await editors[0].click();await editors[0].press('End');await editors[0].pressSequentially(' alpha');
  await waitForContent(pages[1],'Initial contract alpha');
  stage="second edit convergence/save";
  await editors[1].click();await editors[1].press('End');await editors[1].pressSequentially(' beta');
  for (const page of pages) {
    await waitForContent(page,'Initial contract alpha beta');
    await page.getByText('Saved',{ exact:true }).waitFor({ timeout:15000 });
  }
  stage="canonical read";
  const response = await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  if (!response.ok()) throw new Error(`Canonical read failed ${response.status()}`);
  const canonical = await response.json();
  if (canonical.blocks_json.blocks.length !== 1 || canonical.blocks_json.blocks[0].text !== 'Initial contract alpha beta') {
    throw new Error(`Canonical content differs from rendered editors: ${JSON.stringify(canonical.blocks_json)}`);
  }
  stage="reload";
  for (const page of pages) {
    await page.reload();
    await waitForContent(page,'Initial contract alpha beta');
    await page.getByText('Saved',{exact:true}).waitFor({timeout:15000});
    if (await page.locator('.tiptap p').count() !== 1) throw new Error('Reload duplicated canonical content');
    if (await page.getByRole('alert').filter({hasText:'Live collaboration was stopped'}).count()) throw new Error('Reload rejected collaboration');
  }
  stage="live role demotion";
  const demote=await contexts[0].request.patch(`${fixture.base}/api/v1/members/${fixture.userIDs[1]}/role`,{
    data:{role:'viewer'},headers:{Origin:fixture.base}
  });
  if(!demote.ok())throw new Error(`Role demotion failed ${demote.status()}: ${await demote.text()}`);
  await editors[1].click();await editors[1].press('End');await editors[1].pressSequentially(' forbidden');
  await pages[1].getByRole('alert').filter({hasText:'Live collaboration was stopped'}).waitFor();
  await waitForContent(pages[0],'Initial contract alpha beta');
  const protectedRead=await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  const protectedDocument=await protectedRead.json();
  if(protectedDocument.blocks_json.blocks[0].text!=='Initial contract alpha beta')throw new Error('Demoted editor changed canonical content');
  const demotedText=await editors[1].innerText();
  if(!demotedText.includes('forbidden'))throw new Error('Rejected write discarded local recovery draft');
  const download=pages[1].waitForEvent('download');
  await pages[1].getByRole('button',{name:'Download local draft',exact:true}).click();
  const artifact=await download;
  await artifact.saveAs('/private/tmp/hash-demoted-local-draft.json');
  if(!(await Bun.file('/private/tmp/hash-demoted-local-draft.json').text()).includes('forbidden'))throw new Error('Recovery download lost rejected local edit');

  stage="preview preserves rejected draft and navigation protection";
  await pages[1].evaluate(() => { (window as any).__previewDraftEditor=document.querySelector('.tiptap'); });
  await pages[1].getByRole('button',{name:'Preview',exact:true}).click();
  await pages[1].getByRole('note').filter({hasText:'Preview shows the saved document'}).waitFor();
  if(!await pages[1].evaluate(() => document.querySelector('.tiptap')===(window as any).__previewDraftEditor))throw new Error('Preview unmounted the rejected local draft');
  if(await editors[1].isVisible())throw new Error('Preview did not hide the mounted editor');
  await pages[1].frameLocator('iframe[title="preview"]').getByText('Initial contract alpha beta',{exact:false}).waitFor();
  const previewDialog=pages[1].waitForEvent('dialog');
  const attemptedLeave=pages[1].getByRole('link',{name:'Back to documents',exact:true}).click();
  await (await previewDialog).dismiss();
  await attemptedLeave;
  if(new URL(pages[1].url()).pathname!==`/documents/${fixture.documentID}`)throw new Error('Preview lost the unsaved draft navigation guard');
  await pages[1].getByRole('button',{name:'Edit',exact:true}).click();
  await editors[1].waitFor();
  if(!await pages[1].evaluate(() => document.querySelector('.tiptap')===(window as any).__previewDraftEditor))throw new Error('Returning to edit replaced the local editor');
  if(!(await editors[1].innerText()).includes('forbidden'))throw new Error('Preview discarded the rejected local edit');

  stage="external canonical replacement";
  const replacementText='Replacement contract';
  const replace=await contexts[0].request.patch(`${fixture.base}/api/v1/documents/${fixture.documentID}`,{
    data:{expected_updated_at:protectedDocument.updated_at,blocks_json:{version:1,blocks:[{
      id:protectedDocument.blocks_json.blocks[0].id,type:'paragraph',text:replacementText
    }]}},headers:{Origin:fixture.base}
  });
  if(!replace.ok())throw new Error(`External replacement failed ${replace.status()}: ${await replace.text()}`);
  // A frame in the old provider must observe the changed canonical generation.
  // Its local edit is retained for download and never changes the replacement.
  await editors[0].click();await editors[0].press('End');await editors[0].pressSequentially(' retained');
  await pages[0].getByRole('alert').filter({hasText:'Live collaboration was stopped'}).waitFor();
  const ownerLocalText='Initial contract alpha beta retained';
  await waitForContent(pages[0],ownerLocalText);

  stage="owner recovery review and local draft capture";
  const panel=pages[0].getByRole('region',{name:'Collaboration recovery'});
  await panel.getByText(`Current saved document: ${protectedDocument.name}`).waitFor();
  if(!(await panel.locator('pre').innerText()).includes(replacementText))throw new Error('Recovery review does not show the canonical replacement');
  const recoveryButton=panel.getByRole('button',{name:'Reset shared editing to saved document',exact:true});
  if(await recoveryButton.isEnabled())throw new Error('Recovery accepted without draft capture and acknowledgement');
  // The retained edit happened after the first review. Review the current
  // revision before capturing and acknowledging that exact local draft.
  const refreshedReview=pages[0].waitForResponse(response=>response.url().endsWith(`/api/v1/documents/${fixture.documentID}/collab/recovery`) && response.request().method()==='GET');
  await panel.getByRole('button',{name:'Refresh recovery review',exact:true}).click();
  if(!(await refreshedReview).ok())throw new Error('Current recovery review failed');
  await panel.getByRole('button',{name:'Refresh recovery review',exact:true}).waitFor();
  if(!(await panel.locator('pre').innerText()).includes(replacementText))throw new Error('Refreshed recovery review lost the canonical replacement');
  if(await recoveryButton.isEnabled())throw new Error('Refreshed review accepted without current draft capture and acknowledgement');
  const ownerDownload=pages[0].waitForEvent('download');
  await panel.getByRole('button',{name:'Download local draft for recovery',exact:true}).click();
  await (await ownerDownload).saveAs('/private/tmp/hash-owner-recovery-local-draft.json');
  const ownerDraft=await Bun.file('/private/tmp/hash-owner-recovery-local-draft.json').text();
  if(!ownerDraft.includes(ownerLocalText))throw new Error('Owner recovery draft lost the local edit');
  await panel.getByRole('checkbox').check();

  stage="owner shared editing recovery";
  await recoveryButton.click();
  await panel.getByRole('status').filter({hasText:'Shared editing was reset'}).waitFor();
  await waitForContent(pages[0],ownerLocalText);
  await panel.getByRole('heading',{name:'Recovery archives',exact:true}).waitFor();
  const archivedResponse=await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}/collab/recovery`);
  if(!archivedResponse.ok())throw new Error(`Archive metadata read failed ${archivedResponse.status()}`);
  const archived=await archivedResponse.json();
  if(!archived.archives.length || archived.archives.length>16)throw new Error('Recovery did not expose bounded retained archives');
  if(archived.document.blocks_json.blocks[0].text!==replacementText)throw new Error('Recovery changed the current canonical replacement');
  const archiveLink=panel.getByRole('link',{name:'Download archive',exact:true}).first();
  const archiveHref=await archiveLink.getAttribute('href');
  const archiveMetadata=archived.archives.find((entry:any)=>archiveHref?.endsWith(`/${encodeURIComponent(entry.id)}`));
  if(!archiveMetadata)throw new Error('Rendered download does not match retained archive metadata');
  const archiveDownload=pages[0].waitForEvent('download');
  await archiveLink.click();
  await (await archiveDownload).saveAs('/private/tmp/hash-owner-recovery-archive.bin');
  const archiveBytes=await Bun.file('/private/tmp/hash-owner-recovery-archive.bin').bytes();
  if(archiveBytes.byteLength!==archiveMetadata.size_bytes || !archiveBytes.byteLength || archiveBytes.byteLength>8*1024*1024)throw new Error('Recovery attachment lost or exceeded the bounded history payload');
  const viewerArchive=await contexts[1].request.get(`${fixture.base}${archiveHref}`);
  if(viewerArchive.status()!==403)throw new Error(`Demoted viewer can read owner recovery archive: ${viewerArchive.status()}`);

  stage="explicit recovery reload";
  // Recovery must leave the old editor open until this separately confirmed action.
  await waitForContent(pages[0],ownerLocalText);
  pages[0].once('dialog',(dialog:any)=>dialog.accept());
  await Promise.all([
    pages[0].waitForNavigation({waitUntil:'domcontentloaded'}),
    panel.getByRole('button',{name:'Reload saved document',exact:true}).click()
  ]);
  await waitForContent(pages[0],replacementText);
  await pages[0].getByText('Saved',{exact:true}).waitFor({timeout:15000});
  if(await pages[0].locator('.tiptap p').count()!==1)throw new Error('Recovery reload duplicated canonical replacement');
  if(await pages[0].getByRole('alert').filter({hasText:'Live collaboration was stopped'}).count())throw new Error('Recovered owner could not reconnect');
  const recoveredRead=await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  const recoveredDocument=await recoveredRead.json();
  if(!recoveredRead.ok() || recoveredDocument.blocks_json.blocks.length!==1 || recoveredDocument.blocks_json.blocks[0].text!==replacementText)throw new Error('Recovery reload replayed old shared content');

  stage="preview preserves an in-flight save and commits after return";
  let pauseSave=true;
  let releaseSave!:()=>void;
  let saveHeld!:()=>void;
  const saveRelease=new Promise<void>(resolve=>{releaseSave=resolve;});
  const pendingSave=new Promise<void>(resolve=>{saveHeld=resolve;});
  await pages[0].route(`**/api/v1/documents/${fixture.documentID}/collab/save`,async(route:any)=>{
    if(pauseSave && route.request().method()==='POST') {
      saveHeld();
      await saveRelease;
    }
    await route.continue();
  });
  await pages[0].evaluate(() => { (window as any).__previewDraftEditor=document.querySelector('.tiptap'); });
  const previewSuffix=' preview draft';
  await editors[0].click();await editors[0].press('End');await editors[0].pressSequentially(previewSuffix);
  await pendingSave;
  const pendingPreviewText=replacementText+previewSuffix;
  await waitForContent(pages[0],pendingPreviewText);
  await pages[0].getByRole('button',{name:'Preview',exact:true}).click();
  await pages[0].getByRole('note').filter({hasText:'Preview shows the saved document'}).waitFor();
  if(!await pages[0].evaluate(() => document.querySelector('.tiptap')===(window as any).__previewDraftEditor))throw new Error('Preview disposed the editor while its save was in flight');
  await pages[0].frameLocator('iframe[title="preview"]').getByText(replacementText,{exact:false}).waitFor();
  const savedDuringPreview=await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  if((await savedDuringPreview.json()).blocks_json.blocks[0].text!==replacementText)throw new Error('Paused save unexpectedly changed the saved preview');
  await waitForContent(pages[0],pendingPreviewText);
  await pages[0].getByRole('button',{name:'Edit',exact:true}).click();
  await editors[0].waitFor();
  if(!await pages[0].evaluate(() => document.querySelector('.tiptap')===(window as any).__previewDraftEditor))throw new Error('Edit replaced an editor with an in-flight save');
  await waitForContent(pages[0],pendingPreviewText);
  pauseSave=false;releaseSave();
  await pages[0].getByText('Saved',{exact:true}).waitFor({timeout:15000});
  const previewCommitted=await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  if((await previewCommitted.json()).blocks_json.blocks[0].text!==pendingPreviewText)throw new Error('Preserved preview draft did not commit after saving resumed');
  // Restore the fixture's expected final text through the same real editor/save path.
  await editors[0].click();await editors[0].press('End');
  for(let index=0;index<previewSuffix.length;index++)await editors[0].press('Backspace');
  await waitForContent(pages[0],replacementText);
  await pages[0].getByText('Saved',{exact:true}).waitFor({timeout:15000});
  const finalRead=await contexts[0].request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  const finalDocument=await finalRead.json();
  if(!finalRead.ok() || finalDocument.blocks_json.blocks.length!==1 || finalDocument.blocks_json.blocks[0].text!==replacementText)throw new Error('Preview draft roundtrip did not restore the final canonical contract');

  if (errors.length) throw new Error(`Browser exceptions: ${errors.join('; ')}`);
  await pages[0].screenshot({ path:'/private/tmp/hash-browser-collaboration.png',fullPage:true });
  await Bun.write('/private/tmp/hash-browser-collaboration-receipt.json',JSON.stringify({
    result:'pass',documentID:fixture.documentID,text:replacementText,initialCollaboratedText:'Initial contract alpha beta',contexts:2,identities:fixture.userIDs,roles:['owner','sender'],liveDemotionVerified:true,demotedDraftDownloadVerified:true,
    canonicalUpdatedAt:finalDocument.updated_at,reloadVerified:true,browserErrors:errors,
    ownerRecoveryVerified:true,ownerLocalDraftPreserved:true,archiveCount:archived.archives.length,
    archiveAttachmentBytes:archiveBytes.byteLength,viewerArchiveDenied:true,explicitRecoveryReloadVerified:true,
    previewRejectedDraftPreserved:true,previewDirtyNavigationGuardVerified:true,
    previewInFlightDraftPreserved:true,previewDraftCommittedAfterResume:true,
    scope:'real rendered editors and Go HTTPS/WebSocket/PostgreSQL; synthetic distinct owner/sender sessions, live sender demotion, and owner recovery after external canonical replacement'
  },null,2));
  console.log('PASS: distinct owner/sender editors converge/save/reload; live demotion preserves local draft; owner recovery archives old history and explicitly reloads canonical replacement');
} catch (error) {
  console.error("FAILED_STAGE",stage,"PAGE_ERRORS",errors);
  for(const [index,page] of pages.entries()) {
    console.error("PAGE",index,"URL",page.url(),"TEXT",await page.locator("body").innerText());
    await page.screenshot({path:`/private/tmp/hash-browser-collaboration-failed-${index}.png`,fullPage:true});
  }
  throw error;
} finally { await browser.close(); }
