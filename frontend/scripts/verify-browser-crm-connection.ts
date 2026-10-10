// Current built Svelte against actual HTTPS Go/PG and protected synthetic CRM.
// Dynamic disposable credentials enter on private stdin only; no secret output.
const configuredModule = Bun.env.HASH_BROWSER_E2E_PLAYWRIGHT_MODULE;
const moduleURL = configuredModule ? new URL(configuredModule)
  : new URL('../../../brightcrm/tests/e2e/node_modules/playwright/index.mjs', import.meta.url);
if (moduleURL.protocol !== 'file:' || moduleURL.hostname || !moduleURL.pathname.endsWith('/playwright/index.mjs')) throw new Error('Cached local Playwright module required');
const { chromium } = await import(moduleURL.href);
const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; cookieName: string; cookie: string; foreignCookie: string; viewerCookie: string; token: string;
  orgID: string; userID: string; foreignOrgID: string; foreignUserID: string; crmTeamID: string; crmUserID: string;
  artifactDir: string; receiptPath: string;
};
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const cookie = (value: string) => typeof value === 'string' && /^[^;\s\u0000-\u001f\u007f]{16,4096}$/.test(value);
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base) || !/^[A-Za-z0-9_-]{1,64}$/.test(fixture.cookieName)
  || !cookie(fixture.cookie) || !cookie(fixture.foreignCookie) || !cookie(fixture.viewerCookie) || !/^[a-f0-9]{64}$/.test(fixture.token)
  || [fixture.orgID,fixture.userID,fixture.foreignOrgID,fixture.foreignUserID].some(id => !uuid.test(id))
  || [fixture.crmTeamID,fixture.crmUserID].some(id => !/^[A-Za-z0-9_-]{1,256}$/.test(id))
  || fixture.orgID === fixture.foreignOrgID || !fixture.artifactDir.startsWith('/private/tmp/') || !fixture.receiptPath.startsWith('/private/tmp/')) throw new Error('Disposable private CRM browser packet required');
const api = '/api/v1/settings/crm/connection', ui = '/settings/integrations/brightcrm';
const browser = await chromium.launch({ headless:true });
const context = await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1280,height:1000}});
await context.addCookies([{name:fixture.cookieName,value:fixture.cookie,url:fixture.base,httpOnly:true,secure:true,sameSite:'Strict'}]);
const page = await context.newPage(); page.setDefaultTimeout(20000);
let stage='initialization';
const pageErrors:string[]=[],failedAssets:string[]=[],secretResponses:string[]=[],pendingResponseChecks:Promise<void>[]=[];
const writes:{method:string;generation:string;status:number;actorBound:boolean}[]=[];
const phases:{status:string;generation:string}[]=[],screenshots:{name:string;sha256:string}[]=[];
page.on('pageerror',()=>pageErrors.push('browser exception'));
page.on('requestfailed',(request:any)=>{const path=new URL(request.url()).pathname;if((path.startsWith('/_app/')||path.startsWith('/assets/'))&&!request.failure()?.errorText?.includes('ERR_ABORTED'))failedAssets.push('built asset failure');});
page.on('response',(response:any)=>{
  const path=new URL(response.url()).pathname;
  if ((path.startsWith('/_app/')||path.startsWith('/assets/'))&&response.status()>=400) failedAssets.push('built asset HTTP failure');
  if (!path.startsWith('/api/v1/')) return;
  pendingResponseChecks.push((async()=>{try{const text=await response.text();if([fixture.token,fixture.cookie,fixture.foreignCookie,fixture.viewerCookie].some(secret=>text.includes(secret)))secretResponses.push('secret returned');}catch{/* Aborted stale reads need not return bytes. */}})());
});
const keyInput=()=>page.getByLabel('BrightCRM API key',{exact:true});
const accountCheckbox=()=>page.getByRole('checkbox',{name:'I confirm that the displayed CRM team and integration user are the intended account for this organisation.',exact:true});
const revokeCheckbox=()=>page.getByRole('checkbox',{name:'I want to revoke this organisation’s CRM connection.',exact:true});
function checkedResponse(body:any,status:string,generation:string) {
  if(body.org_id!==fixture.orgID||body.user_id!==fixture.userID||!body.available||!body.configured||body.requires_reconfiguration
    ||body.connection?.status!==status||body.connection?.generation!==generation||body.connection.crm_team_id!==fixture.crmTeamID||body.connection.crm_user_id!==fixture.crmUserID
    ||Object.keys(body).some(key=>['token','ciphertext','credential_ciphertext'].includes(key)))throw new Error('Returned connection differs from intended actor/account/generation');
  phases.push({status,generation});
}
async function actualRead() {
  const response=await context.request.get(`${fixture.base}${api}`);if(response.status()!==200)throw new Error('Owner connection readback unavailable');
  const body=await response.json();if([fixture.token,fixture.cookie,fixture.foreignCookie,fixture.viewerCookie].some(secret=>JSON.stringify(body).includes(secret)))throw new Error('Connection readback exposed credential');return body;
}
async function visibleAccount(status:string) {
  await page.locator('[data-crm-team-id]').filter({hasText:fixture.crmTeamID}).waitFor();
  await page.locator('[data-crm-user-id]').filter({hasText:fixture.crmUserID}).waitFor();
  await page.getByText(status,{exact:true}).waitFor();
}
async function screenshot(name:string) {
  const path=`${fixture.artifactDir}/${name}.png`;await page.locator('main').screenshot({path});
  screenshots.push({name,sha256:new Bun.CryptoHasher('sha256').update(new Uint8Array(await Bun.file(path).arrayBuffer())).digest('hex')});
}
async function write(button:string,method:string,suffix:string,status:string,generation:string) {
  const result=page.waitForResponse((response:any)=>new URL(response.url()).pathname===api+suffix&&response.request().method()===method);
  await page.getByRole('button',{name:button,exact:true}).click();const response=await result;
  const input=response.request().postDataJSON();
  const actorBound=input.expected_org_id===fixture.orgID&&input.expected_user_id===fixture.userID&&input.expected_generation===(BigInt(generation)-1n).toString();
  if(response.status()!==200||!actorBound)throw new Error('Owner change was refused or lost original actor expectations');
  checkedResponse(await response.json(),status,generation);writes.push({method,generation,status:response.status(),actorBound});
}
try {
  stage='owner initial built UI';await page.goto(`${fixture.base}${ui}`);await page.getByRole('heading',{name:'BrightCRM connection',exact:true}).waitFor();
  await page.getByText('Not configured',{exact:true}).waitFor();
  const initial=await actualRead();if(initial.org_id!==fixture.orgID||initial.user_id!==fixture.userID||initial.configured||initial.connection!==null)throw new Error('Initial owner witness/absent connection differs');

  stage='switched-cookie mutation original actor rejection';
  let refusedActor=false;
  const switchedPut=async(route:any)=>{
    const original=route.request().postDataJSON();
    if(original.expected_org_id!==fixture.orgID||original.expected_user_id!==fixture.userID||original.expected_generation!=='0')throw new Error('Actual UI mutation did not capture initial owner');
    const response=await route.fetch({headers:{...route.request().headers(),cookie:`${fixture.cookieName}=${fixture.foreignCookie}`}});
    if(response.status()!==409)throw new Error('Switched admitted owner was allowed to mutate another organization');
    refusedActor=true;await route.fulfill({response});
  };
  await page.route(`**${api}`,async(route:any)=>route.request().method()==='PUT'?switchedPut(route):route.continue());
  await keyInput().fill(fixture.token);await page.getByRole('button',{name:'Check account and save key',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'Refresh'}).waitFor();if(!refusedActor)throw new Error('Switched actor request did not settle');
  await page.unroute(`**${api}`);await page.getByRole('button',{name:'Refresh connection',exact:true}).click();await page.getByText('Not configured',{exact:true}).waitFor();

  stage='save disabled candidate';await keyInput().fill(fixture.token);
  await write('Check account and save key','PUT','','candidate','1');await visibleAccount('Awaiting account confirmation');
  if(await keyInput().inputValue()!==''||await accountCheckbox().isChecked()||await page.getByRole('button',{name:'Enable connection',exact:true}).isEnabled())throw new Error('Secret persisted or candidate enabled without account confirmation');
  await screenshot('crm-candidate-desktop');
  stage='explicit account enable';await accountCheckbox().check();await write('Enable connection','POST','/enable','active','2');await visibleAccount('Enabled');
  stage='replace current key';await keyInput().fill(fixture.token);await write('Check account and save key','PUT','','candidate','3');await visibleAccount('Awaiting account confirmation');
  if(await accountCheckbox().isChecked()||await page.getByRole('button',{name:'Enable connection',exact:true}).isEnabled()||await keyInput().inputValue()!=='')throw new Error('Replacement retained prior account approval or secret');
  stage='confirm replacement';await accountCheckbox().check();await write('Enable connection','POST','/enable','active','4');await visibleAccount('Enabled');await screenshot('crm-enabled-desktop');
  stage='explicit revoke and readback';await revokeCheckbox().check();await write('Revoke connection','DELETE','','revoked','5');await visibleAccount('Revoked');
  await page.getByRole('button',{name:'Refresh connection',exact:true}).click();await visibleAccount('Revoked');checkedResponse(await actualRead(),'revoked','5');

  stage='foreign response witness with original cookie restored';
  let staleReadSettled=false;
  const staleReadSettlements:Promise<void>[]=[];
  const switchedRead=(route:any)=>{
    const settlement=(async()=>{
    if(route.request().method()!=='GET'){await route.continue();return;}
    const response=await context.request.get(`${fixture.base}${api}`,{headers:{cookie:`${fixture.cookieName}=${fixture.foreignCookie}`}});
    const body=await response.json();if(response.status()!==200||body.org_id!==fixture.foreignOrgID||body.user_id!==fixture.foreignUserID)throw new Error('Actual foreign owner response witness unavailable');
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});staleReadSettled=true;
    })();staleReadSettlements.push(settlement);return settlement;
  };
  await page.route(`**${api}`,switchedRead);await page.getByRole('button',{name:'Refresh connection',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'original owner session'}).waitFor();
  await Promise.all(staleReadSettlements);
  if(!staleReadSettled||await keyInput().count())throw new Error('Foreign actor response remained actionable');
  await page.unroute(`**${api}`,switchedRead);await page.getByRole('button',{name:'Refresh connection',exact:true}).click();await visibleAccount('Revoked');

  stage='actual viewer session refusal';
  let viewerReadSettled=false;
  const viewerReadSettlements:Promise<void>[]=[];
  const viewerRead=(route:any)=>{
    const settlement=(async()=>{
    const response=await context.request.get(`${fixture.base}/api/v1/me`,{headers:{cookie:`${fixture.cookieName}=${fixture.viewerCookie}`}});
    const body=await response.json();if(response.status()!==200||body.role!=='viewer')throw new Error('Actual viewer identity unavailable');
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});viewerReadSettled=true;
    })();viewerReadSettlements.push(settlement);return settlement;
  };
  await page.route('**/api/v1/me',viewerRead);await page.getByRole('button',{name:'Refresh connection',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'original owner session'}).waitFor();
  await Promise.all(viewerReadSettlements);
  if(!viewerReadSettled||await keyInput().count())throw new Error('Viewer role retained owner controls');
  await page.unroute('**/api/v1/me',viewerRead);await page.getByRole('button',{name:'Refresh connection',exact:true}).click();await visibleAccount('Revoked');
  stage='mobile final state';await page.setViewportSize({width:390,height:844});await screenshot('crm-revoked-mobile');
  const mobile=await page.evaluate(()=>({viewport:innerWidth,scroll:document.documentElement.scrollWidth}));
  await Promise.all(pendingResponseChecks);
  if(mobile.viewport!==mobile.scroll||pageErrors.length||failedAssets.length||secretResponses.length)throw new Error('Browser errors, asset failure, secret readback or mobile overflow');
  await Bun.write(fixture.receiptPath,JSON.stringify({result:'pass',scope:'Actual built owner settings/Go HTTPS/PostgreSQL/protected synthetic CRM peer. No live provider, contract provenance, SMTP, deployment or legal acceptance.',
    phases,writes,candidateDisabledUntilExplicitAccountConfirmation:true,replacementApprovalReset:true,revokedReadbackVerified:true,
    originalMutationActorBound:true,switchedRequestCookieRejectedBeforeEnrollment:refusedActor,foreignResponseWitnessRejected:staleReadSettled,
    actualViewerSessionRefused:viewerReadSettled,actualOwnerDemotionVerified:false,secretReadbackAbsent:true,screenshots,mobile,pageErrors,failedAssets},null,2)+'\n');
  console.log('PASS: built CRM owner candidate/enable/replace/revoke journey, original actor binding, foreign response refusal and viewer access denial');
} catch {
  if(await keyInput().count())await keyInput().fill('').catch(()=>{});await page.locator('main').screenshot({path:`${fixture.artifactDir}/failed.png`}).catch(()=>{});
  console.error('FAILED_STAGE',stage,'BROWSER_ERROR_COUNT',pageErrors.length);throw new Error(`CRM connection browser verification failed at ${stage}`);
} finally {await browser.close();}
