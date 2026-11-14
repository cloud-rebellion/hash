import { expect, test } from 'bun:test';
import { PDFPaintLane } from '../pdfPageStrip';
import { PdfLoad } from '../pdfLoad';
import { PdfCanvasBudget, type CanvasGeneration } from '../pdfCanvas';
const source=await Bun.file(new URL('./VerifiedPDFPages.svelte',import.meta.url)).text();
const start=source.indexOf('  const current ='),end=source.indexOf('\n</script>',start);
if(start<0||end<=start)throw Error('Actual verified viewer lifetime callbacks missing');
const code=new Bun.Transpiler({loader:'ts'}).transformSync(source.slice(start,end).replaceAll("await import('$lib/pdf')",'await pdfModule()').replace('export function retire','function retire'));
function deferred<T>(){let resolve!:(v:T)=>void,reject!:(e:unknown)=>void;const promise=new Promise<T>((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject};}
function fixture(painted=false,pages=1){const reported:unknown[][]=[];const budget=new PdfCanvasBudget();let generation!:CanvasGeneration;const parsed=deferred<any>(),retirement=deferred<void>(),started=deferred<void>();let destroys=0,owner!:{retire():Promise<void>},published:Promise<void>|null=null,mount!:()=>Promise<void>,destroy!:()=>void;
const env:any={PDFPaintLane,captureFlarePDFViewError:(...args:unknown[])=>reported.push(args),disposed:false,sourceKey:'exact',proofKey:'exact',loadedPDF:null,canvas:{width:painted?0:120,height:painted?0:180},loading:true,rendering:false,page:1,seen:[],error:null,failedPage:null,pdfLoad:null,renderRevision:0,bytes:new Uint8Array([1,2,3]),expectedPages:pages,onProof:()=>{},onOwner:(v:any)=>{owner=v},onRetirement:(p:Promise<void>)=>{published=p},untrack:(f:any)=>f(),onMount:(f:any)=>{mount=f},onDestroy:(f:any)=>{destroy=f},pdfModule:async()=>({startPdfData(){started.resolve();generation=budget.generation();return new PdfLoad({promise:parsed.promise,destroy(){destroys++;return retirement.promise}},{closing:()=>budget.closing(generation),retired:()=>budget.retired(generation),failed:()=>budget.retirementFailed(generation)})},unscaledWidth:async()=>100,renderPage:async(_doc:unknown,_page:number,canvas:HTMLCanvasElement)=>{const lease=await budget.acquire(generation,canvas,120,180);try{lease.assertCurrent();canvas.width=120;canvas.height=180;const original=Promise.resolve();lease.observe(original);await original;}finally{lease.finish();}}})};
new Function('env','with(env){'+code+';env.actions={render,nextUnopenedPage,openNextUnopenedPage,retryFailedPage};}')(env);return{env,budget,parsed,retirement,started,reported,mount:()=>mount(),destroy:()=>destroy(),owner:()=>owner,published:()=>published,destroys:()=>destroys};}
test('actual verified viewer preserves its exact retirement and does not zero a canvas that the pending parser never owned',async()=>{const f=fixture();expect(f.owner()).toBeDefined();const mounting=f.mount();await f.started.promise;const owner=f.owner(),p=owner.retire();expect(f.published()).toBe(p);expect(owner.retire()).toBe(p);f.destroy();expect(f.destroys()).toBe(1);expect(f.env.canvas.width).toBe(120);f.retirement.resolve();await p;f.parsed.reject(Error('cancelled parser'));await mounting;expect(f.env.canvas.width).toBe(120);expect(f.env.canvas.height).toBe(180);expect(f.env.loadedPDF).toBe(null);});
test('actual verified viewer preserves a rejected worker retirement through repeated route destruction',async()=>{const f=fixture();const mounting=f.mount();await f.started.promise;const p=f.owner().retire();f.retirement.reject(Error('destroy refused'));await expect(p).rejects.toThrow('destroy refused');f.destroy();expect(f.owner().retire()).toBe(p);expect(f.published()).toBe(p);expect(f.env.canvas.width).toBe(120);f.parsed.reject(Error('parser cancelled'));await mounting;expect(f.destroys()).toBe(1);});


test('actual verified viewer releases only its ledger-owned paint after its original stable retirement fulfills',async()=>{
const f=fixture(true),mounting=f.mount();await f.started.promise;f.parsed.resolve({numPages:1});await mounting;
expect(f.budget.snapshot()).toMatchObject({stores:1,pixels:120*180});expect(f.env.canvas.width).toBe(120);
const p=f.owner().retire();expect(f.published()).toBe(p);expect(f.owner().retire()).toBe(p);expect(f.env.canvas.width).toBe(120);
f.retirement.resolve();await p;expect(f.env.canvas.width).toBe(0);expect(f.env.canvas.height).toBe(0);expect(f.budget.snapshot().pixels).toBe(0);
});


test('actual verified viewer reports a current PDF parser failure without passing the error to telemetry',async()=>{
  const f=fixture(),mounting=f.mount();await f.started.promise;
  f.parsed.reject(new Error('PRIVATE parser text /sign/private-token'));f.retirement.resolve();await mounting;
  expect(f.reported).toEqual([[]]);expect(f.env.loadedPDF).toBeNull();expect(f.destroys()).toBe(1);
});
test('actual verified viewer ordinary page-count refusal and expected or stale parse cancellation stay silent',async()=>{
  for(const mode of ['count','abort','render-cancel','stale'] as const){
    const f=fixture(),mounting=f.mount();await f.started.promise;
    if(mode==='count')f.parsed.resolve({numPages:2});else{
      const failure=new Error('PRIVATE parser text');failure.name=mode==='abort'?'AbortError':mode==='render-cancel'?'RenderingCancelledException':'Error';
      if(mode==='stale')f.env.proofKey='replacement';f.parsed.reject(failure);
    }
    f.retirement.resolve();await mounting;expect(f.reported).toEqual([]);expect(f.env.loadedPDF).toBeNull();
  }
});
test('actual verified viewer paint failure is captured once and its current proof remains false',async()=>{
  const f=fixture();const module=f.env.pdfModule;f.env.pdfModule=async()=>({...await module(),renderPage:async()=>{throw Error('PRIVATE paint failure');}});
  const proofs:any[]=[];f.env.onProof=(proof:any)=>proofs.push(proof);const mounting=f.mount();await f.started.promise;f.parsed.resolve({numPages:1});await mounting;
  expect(f.reported).toEqual([[]]);expect(proofs.at(-1)).toEqual({key:'exact',allPagesSeen:false});expect(f.env.error).toBe('PRIVATE paint failure');
  const closing=f.owner().retire();f.retirement.resolve();await closing;
});
test('actual verified owner reports failed native retirement once after unmount without replacing or swallowing the original promise',async()=>{
  const f=fixture(),mounting=f.mount();await f.started.promise;
  const p=f.owner().retire();f.destroy();f.env.proofKey='replacement';const failure=Error('PRIVATE failed native cleanup');
  f.retirement.reject(failure);await expect(p).rejects.toBe(failure);
  f.parsed.reject(Object.assign(Error('expected disposed parse'),{name:'AbortError'}));await mounting;
  expect(f.owner().retire()).toBe(p);expect(f.published()).toBe(p);expect(f.destroys()).toBe(1);expect(f.reported).toEqual([[]]);
});


test('actual verified viewer manual unopened navigation counts each successful full page once',async()=>{
  const f=fixture(false,3),proofs:any[]=[];f.env.onProof=(proof:any)=>proofs.push(proof);
  const mounting=f.mount();await f.started.promise;f.parsed.resolve({numPages:3});await mounting;
  expect(f.env.seen).toEqual([1]);expect(f.env.actions.nextUnopenedPage()).toBe(2);expect(proofs.at(-1)).toEqual({key:'exact',allPagesSeen:false});
  await f.env.actions.openNextUnopenedPage();expect(f.env.seen).toEqual([1,2]);expect(f.env.actions.nextUnopenedPage()).toBe(3);
  await f.env.actions.render(1);expect(f.env.seen).toEqual([1,2]);expect(proofs.at(-1).allPagesSeen).toBe(false);
  await f.env.actions.openNextUnopenedPage();expect(f.env.seen).toEqual([1,2,3]);expect(f.env.actions.nextUnopenedPage()).toBeNull();expect(proofs.at(-1)).toEqual({key:'exact',allPagesSeen:true});
  const count=proofs.length;await f.env.actions.openNextUnopenedPage();expect(proofs).toHaveLength(count);
  const closing=f.owner().retire();f.retirement.resolve();await closing;expect(proofs.at(-1)).toEqual({key:'exact',allPagesSeen:false});
});
test('actual verified viewer retries the failed requested page instead of the previously displayed page',async()=>{
  const f=fixture(false,2),proofs:any[]=[],painted:number[]=[];f.env.onProof=(proof:any)=>proofs.push(proof);
  const module=f.env.pdfModule;let failed=false;f.env.pdfModule=async()=>{const pdf=await module();return{...pdf,renderPage:async(doc:unknown,page:number,canvas:HTMLCanvasElement)=>{painted.push(page);if(page===2&&!failed){failed=true;throw Error('Page paint failed');}return pdf.renderPage(doc,page,canvas);}};};
  const mounting=f.mount();await f.started.promise;f.parsed.resolve({numPages:2});await mounting;
  await f.env.actions.openNextUnopenedPage();expect(painted).toEqual([1,2]);expect(f.env.page).toBe(1);expect(f.env.seen).toEqual([1]);expect(f.env.failedPage).toBe(2);expect(proofs.at(-1).allPagesSeen).toBe(false);
  await f.env.actions.retryFailedPage();expect(painted).toEqual([1,2,2]);expect(f.env.page).toBe(2);expect(f.env.seen).toEqual([1,2]);expect(f.env.failedPage).toBeNull();expect(proofs.at(-1)).toEqual({key:'exact',allPagesSeen:true});
  const closing=f.owner().retire();f.retirement.resolve();await closing;
});
test('actual verified viewer manual navigation and failed-page retry refuse stale or busy generations',async()=>{
  const f=fixture(false,2),mounting=f.mount();await f.started.promise;f.parsed.resolve({numPages:2});await mounting;
  for(const mode of ['loading','rendering','stale'] as const){
    f.env.failedPage=2;if(mode==='stale')f.env.proofKey='replacement';else f.env[mode]=true;
    await f.env.actions.openNextUnopenedPage();await f.env.actions.retryFailedPage();expect(f.env.seen).toEqual([1]);expect(f.env.page).toBe(1);
    if(mode==='stale')f.env.proofKey='exact';else f.env[mode]=false;
  }
  const closing=f.owner().retire();f.retirement.resolve();await closing;
});
