import { expect, test } from 'bun:test';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile, parse } from 'svelte/compiler';
import { signerRoomEnglish, signerRoomSwedish, type SignerRoomText } from '../signerRoomUiMessages';
import { signerRoomError, signerRoomText, signerRoomViewerText } from '../signerRoomUi';
import { signerPackageIncorporations } from '../signerPackageIncorporation';
import { checkedSignerPackageDescriptorsV1, signerPackageLocale, signerPackageResponse } from '../signerPackage';

const lib = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (name: string) => readFileSync(resolve(lib, 'components', name + '.svelte'), 'utf8');
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function functions(name: string, names: string[]) {
  const source = read(name), ast: any = parse(source, { modern: true });
  const found = ast.instance.content.body.filter((node: any) => node.type === 'FunctionDeclaration' && names.includes(node.id?.name));
  if (found.length !== names.length) throw Error('Actual child callback not found');
  return found.map((node: any) => source.slice(node.start, node.end)).join('\n');
}
function markup(name: string) {
  const source = read(name); return source.slice(source.indexOf('</script>') + 9, source.indexOf('<style>') < 0 ? undefined : source.indexOf('<style>'));
}
function declarations(name: string, names: string[]) {
  const source=read(name), ast:any=parse(source,{modern:true});
  const found=ast.instance.content.body.filter((node:any)=>node.type==='VariableDeclaration'&&node.declarations.some((item:any)=>names.includes(item.id?.name)));
  if(found.length!==names.length)throw Error('Actual child render gate not found');
  return found.map((node:any)=>source.slice(node.start,node.end)).join('\n');
}
// Exercise actual production markup with controlled render-only state. The
// real API/proof callbacks below are separately extracted and exercised.
function fixture(name: 'SignerFields' | 'PdfSignerView' | 'SignerPackageReview') {
  const imports = `import {locale,t} from '$lib/i18n'; import {signerRoomText,signerRoomError,signerRoomFieldType,signerRoomPages,signerRoomViewerText} from '$lib/signerRoomUi'; import {signerPackageLocale} from '$lib/signerPackage';`;
  if (name === 'SignerFields') return `<script lang="ts">${imports} let {fieldsLoaded=true,loadError=null,fields=[],buf={},saving=false,saveError=null,savedAt=null}=$props(); const save=()=>{throw Error('SSR must not save');}; ${functions(name,['dropdownChoices'])}</script>${markup(name)}`;
  if (name === 'PdfSignerView') return `<script lang="ts">${imports} let {documentReady=true,loading=false,error=null,saveErrors={},pages=[{num:1,w:600,h:800}],residentPages=[1],fields=[],buf={},persisted={},saving={},fieldsLoaded=true,signed=false,readOnly=true}=$props(); let canvasEls={}; const session={current:()=>true,scope:{}}; const onSignatureClick=()=>{throw Error('SSR must not sign');}; const saveField=()=>{throw Error('SSR must not save');}; ${functions(name,['emptyValue','isFilled','recomputeFilled','fieldsOnPage','fieldName'])}</script>${markup(name)}`;
  return `<script lang="ts">${imports} import VerifiedPDFPages from ${JSON.stringify(resolve(lib, 'components/VerifiedPDFPages.svelte'))}; let {scope={key:'render-only',token:'not-rendered'},busy=false,error=null,value,loaded=true,mainReady=true,disabled=false,reviewed={},consent=false,preview={selection:null,opening:false,closing:false,blocked:false,error:null}}=$props(); ${declarations(name,['allAttachmentsReviewed','canConsent'])} let owner=null; const refresh=()=>{throw Error('SSR must not fetch');}; const open=()=>{throw Error('SSR must not fetch');}; const proof=()=>{throw Error('SSR must not grant proof');}; const controller={close(){},observeRetirement(){}};</script>${markup(name)}`;
}
let renderer: Promise<any> | undefined;
async function views() {
  return renderer ??= (async () => {
    const build = await Bun.build({ entrypoints: ['signer-child-entry'], target: 'bun', plugins: [{ name: 'actual-signer-child-views', setup(builder) {
      builder.onResolve({ filter: /^signer-child-entry$/ }, () => ({ path: 'entry', namespace: 'test' }));
      builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: `export {default as Fields} from 'child:SignerFields'; export {default as PDF} from 'child:PdfSignerView'; export {default as Package} from 'child:SignerPackageReview'; export {default as Notice} from ${JSON.stringify(resolve(lib,'components/A13Notice.svelte'))}; export {default as Amendment} from ${JSON.stringify(resolve(lib,'components/SignerAmendmentContext.svelte'))}; export {render} from 'svelte/server'; export {locale} from ${JSON.stringify(resolve(lib,'i18n.ts'))};`, loader: 'ts', resolveDir: lib }));
      builder.onResolve({ filter: /^child:/ }, args => ({ path: args.path.slice(6), namespace: 'child-markup' }));
      builder.onLoad({ filter: /.*/, namespace: 'child-markup' }, args => ({ contents: compile(fixture(args.path as any), { filename: resolve(lib,'components',args.path+'RenderFixture.svelte'), generate:'server' }).js.code, loader:'js', resolveDir:resolve(lib,'components') }));
      builder.onResolve({ filter: /^\$lib\/pdf$/ }, () => ({ path: 'browser-only-pdf', namespace:'no-pdf' }));
      builder.onLoad({ filter: /.*/, namespace:'no-pdf' }, () => ({ contents:"throw Error('SSR must not load PDF.js');", loader:'js' }));
      builder.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./'+args.path.slice(5),lib) }));
      builder.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, async args => ({ contents:await Bun.file(args.path).text(),loader:'js',resolveDir:dirname(args.path) }));
      builder.onLoad({ filter: /\.svelte$/ }, async args => ({ contents:compile(await Bun.file(args.path).text(),{filename:args.path,generate:'server'}).js.code,loader:'js',resolveDir:dirname(args.path) }));
    } }] });
    if (!build.success) throw Error(build.logs.map(String).join('\n'));
    const directory=mkdtempSync(join(tmpdir(),'hash-signer-child-ui-'));
    try { const output=join(directory,'views.mjs');writeFileSync(output,await build.outputs[0].text());return await import(pathToFileURL(output).href); }
    finally { rmSync(directory,{recursive:true,force:true}); }
  })();
}

test('the closed EN/SV interface catalogue has identical keys/placeholders and never echoes unknown exception details', () => {
  expect(Object.keys(signerRoomSwedish).sort()).toEqual(Object.keys(signerRoomEnglish).sort());
  for (const key of Object.keys(signerRoomEnglish) as SignerRoomText[]) {
    expect([...signerRoomSwedish[key].matchAll(/\{[a-zA-Z]+\}/g)].map(m=>m[0]).sort()).toEqual([...key.matchAll(/\{[a-zA-Z]+\}/g)].map(m=>m[0]).sort());
    expect(signerRoomText('en',key)).toBe(key);
  }
  expect(signerRoomError('sv','Unable to load document: The document response is not a PDF.')).toBe('Kunde inte läsa in dokumentet: Dokumentsvaret är inte en PDF.');
  expect(signerRoomError('sv','The request failed (503).')).toBe('Begäran misslyckades (503).');
  expect(signerRoomViewerText('sv','Next page')).toBe('Nästa sida');
  for (const unknown of ['secret-token-in-server-body','{"error":"private document content"}',new Error('credential-like-detail')]) expect(signerRoomError('sv',unknown)).toBe('Begäran misslyckades.');
  expect(signerRoomText('sv-SE','Select…')).toBe('Select…');
});

test('every application-owned PDF viewer label is localized for recipient review', () => {
  const labels = new Set<string>();
  function choices(node: any) {
    if (node?.type === 'Literal' && typeof node.value === 'string') labels.add(node.value);
    if (node?.type === 'ConditionalExpression') {
      choices(node.consequent); choices(node.alternate);
    }
  }
  function visit(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'translate') {
      choices(node.arguments[0]);
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  }
  for (const name of ['VerifiedPDFPages', 'PDFPageStrip']) visit(parse(read(name), { modern: true }));
  expect(labels.size).toBeGreaterThan(8);
  for (const label of labels) {
    expect(signerRoomViewerText('en', label)).toBe(label);
    if (!Object.hasOwn(signerRoomEnglish, label) || !Object.hasOwn(signerRoomSwedish, label)) {
      throw new Error('Unmapped application-owned viewer label: ' + label);
    }
    const key = label as SignerRoomText;
    expect(signerRoomViewerText('sv', label)).toBe(signerRoomSwedish[key]);
    if (label !== 'The request failed.') {
      expect(signerRoomViewerText('en', label)).not.toBe('The request failed.');
      expect(signerRoomViewerText('sv', label)).not.toBe('Begäran misslyckades.');
    }
  }
  for (const locale of ['en', 'sv'] as const) {
    expect(signerRoomViewerText(locale, 'Page review progress: private renderer detail'))
      .toBe(signerRoomText(locale, 'The request failed.'));
  }
});

test('actual child field/PDF controls, paused state, ARIA, package review gates and frozen content render in EN/SV', async () => {
  const view=await views();
  for (const selected of ['en','sv']) {
    view.locale.set(selected);
    const field={id:'field-id',type:'dropdown',required:true,label:'Customer label <unchanged>',options:{choices:['Customer choice <unchanged>']}};
    const fields=view.render(view.Fields,{props:{fields:[field]}}).body;
    expect(fields).not.toContain('<unchanged>'); expect(fields).toContain(selected==='sv'?'Välj…':'Select…');expect(fields).toContain('Customer label &lt;unchanged>');expect(fields).toContain('Customer choice &lt;unchanged>');
    const pdf=view.render(view.PDF,{props:{fields:[{...field,page:1,x_pct:1,y_pct:1,w_pct:20,h_pct:10},{...field,id:'signature',type:'signature',page:1,x_pct:1,y_pct:20,w_pct:20,h_pct:10}]}}).body;
    expect(pdf).toContain(selected==='sv'?'Dokumentsida 1':'Document page 1');expect(pdf).toContain(selected==='sv'?'Signeringen är pausad':'Signing paused');
    for (const version of Object.keys(signerPackageIncorporations) as Array<keyof typeof signerPackageIncorporations>) {
      const copy=signerPackageIncorporations[version];
      const value={revision:'7',manifest_sha256:'a'.repeat(64),legal_commitment_sha256:'b'.repeat(64),main:{title:'Main <unchanged>',pages:1},annexes:[{title:'DPA <unchanged>',category:'Category <unchanged>',pages:2}],incorporation:{version,sha256:copy.sha256,text:copy.text}};
      const pending=view.render(view.Package,{props:{value}}).body,ready=view.render(view.Package,{props:{value,reviewed:{1:true}}}).body;
      expect(pending).toContain(selected==='sv'?'Ditt avtalspaket':'Your contract package');expect(pending).toContain(copy.text);
      expect(pending).toContain('DPA &lt;unchanged>');expect(pending).toContain('Category &lt;unchanged>');
      expect(pending).toMatch(/<input[^>]*type="checkbox"[^>]*disabled/);expect(ready).not.toMatch(/<input[^>]*type="checkbox"[^>]*disabled/);
      expect(pending).toContain(signerRoomText(selected,copy.locale==='sv'?'Agreement text · Swedish':'Agreement text · English'));
      expect(pending).not.toContain('not-rendered');
    }
  }
});

test('actual amendment and privacy components preserve server/document values and label the actual canonical language', async () => {
  const view=await views();
  const privacy:any={controller:'Controller <unchanged>',controller_contact:'Contact',processor:'Processor',processor_email:'processor@example.test',purpose_summary:'Server purpose <unchanged>',legal_basis:'Server legal basis',retention_years:7,jurisdiction_dp:'Authority',policy_url:'https://example.test/privacy',dsr_endpoint:'/sign/synthetic/dsr',notice_digest:'a'.repeat(64),copy:{title:'SERVER NOTICE TITLE',intro:'SERVER NOTICE <EXACT>',retention_value:'SERVER RETENTION',fine_print:'SERVER FINE PRINT'}};
  for (const selected of ['en','sv']) {
    view.locale.set(selected);
    for (const canonical of ['en','sv',undefined]) {
      const notice=view.render(view.Notice,{props:{privacy:{...privacy,copy_locale:canonical},storageKey:'notice-scope-not-credential',onAcknowledged(){throw Error('SSR cannot acknowledge');}}}).body;
      expect(notice).not.toContain('<EXACT>'); expect(notice).not.toContain('<unchanged>'); expect(notice).toContain('SERVER NOTICE &lt;EXACT>');expect(notice).toContain('Server purpose &lt;unchanged>');
      expect(notice).toContain(signerRoomText(selected,canonical==='sv'?'Privacy notice · Swedish':'Privacy notice · English'));
    }
    for (const mode of ['signature','acknowledgement']) {
      const disclosure={mode,original_name:'Original <unchanged>',original_document_id:'original-id',original_final_pdf_sha256:'a'.repeat(64),original_report_sha256:'b'.repeat(64),original_report_pdf_sha256:'c'.repeat(64),amendment_id:'amendment-id',revision:'9',file_commitment_sha256:'d'.repeat(64)};
      const html=view.render(view.Amendment,{props:{disclosure}}).body;
      expect(html).toContain('Original &lt;unchanged>');expect(html).toContain(disclosure.file_commitment_sha256);
      expect(html).toContain(signerRoomText(selected,mode==='signature'?'New signature':'Explicit acknowledgement'));
    }
  }
});

test('actual privacy request sends unchanged scope/body and display localization grants no acknowledgement', async () => {
  const calls:any[]=[],env:any={privacy:{dsr_endpoint:'/sign/original-token/dsr',copy:{request_received:'Server confirmation verbatim'}},requestStatus:null,requestKind:'access',requestNote:'Customer note <verbatim>',fetch:async(...args:any[])=>{calls.push(args);return new Response('untrusted-body',{status:503});}};
  const submit=new Function('env',`with(env){${transpiler.transformSync(functions('A13Notice',['submitDSR']))};return submitDSR;}`)(env);
  await submit();expect(calls).toEqual([['/sign/original-token/dsr',{method:'POST',headers:{'content-type':'application/json'},body:'{"kind":"access","note":"Customer note <verbatim>"}'}]]);
  expect(signerRoomError('sv',env.requestStatus.message,'The privacy request could not be sent. Please try again.')).toBe('Integritetsbegäran kunde inte skickas. Försök igen.');
  expect(env.requestNote).toBe('Customer note <verbatim>');expect(env).not.toHaveProperty('acknowledged');
});

test('actual package callback reports only current frozen canonical language, without granting consent or adding language to proof', () => {
  const source=read('SignerPackageReview'),start=source.indexOf('  $effect(() => {\n    const ready ='),end=source.indexOf('\n\n  async function refresh()',start);
  if(start<0||end<=start)throw Error('Actual package callback missing');
  for(const version of Object.keys(signerPackageIncorporations) as Array<keyof typeof signerPackageIncorporations>){
    const copy=signerPackageIncorporations[version],value=checkedSignerPackageDescriptorsV1({package:{schema:'hash-recipient-package-v1',package_id:'10000000-0000-4000-8000-000000000001',revision:'1',manifest_sha256:'a'.repeat(64),legal_commitment_sha256:'b'.repeat(64),main:{title:'Main',category:'',pdf_sha256:'c'.repeat(64),bytes:100,pages:1},annexes:[],incorporation:{version,sha256:copy.sha256,text:copy.text}}})!;
    const frames:any[]=[],env:any={isCurrent:true,current:()=>env.isCurrent,original:{key:'current-scope'},loaded:true,busy:false,error:null,preview:{blocked:false,opening:false,closing:false},value,canConsent:false,consent:false,signerPackageLocale,signerPackageResponse,untrack:(run:()=>unknown)=>run(),onChange:(frame:unknown)=>frames.push(frame)};
    let publish!:()=>void;env.$effect=(run:()=>void)=>{publish=run;};
    new Function('env',`with(env){${transpiler.transformSync(source.slice(start,end))}}`)(env);
    publish();expect(frames.at(-1)).toEqual({key:'current-scope',ready:false,settled:true,canonicalLocale:copy.locale});
    env.canConsent=true;env.consent=true;publish();expect(frames.at(-1)).toEqual({key:'current-scope',ready:true,settled:true,response:signerPackageResponse(value),canonicalLocale:copy.locale});
    expect(frames.at(-1).response).not.toHaveProperty('locale');expect(frames.at(-1).response).not.toHaveProperty('canonicalLocale');
    env.loaded=false;publish();expect(frames.at(-1)).not.toHaveProperty('canonicalLocale');expect(frames.at(-1)).not.toHaveProperty('response');
    env.loaded=true;env.isCurrent=false;publish();expect(frames.at(-1)).not.toHaveProperty('canonicalLocale');expect(frames.at(-1).ready).toBe(false);
  }
});

test('the five production children compile without new warnings in client and server modes', () => {
  for (const name of ['SignerFields','PdfSignerView','SignerPackageReview','SignerAmendmentContext','A13Notice']) for (const generate of ['client','server'] as const) expect(compile(read(name),{filename:resolve(lib,'components',name+'.svelte'),generate}).warnings).toEqual([]);
});
