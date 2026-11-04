import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { blockTemplatePreview, sameTemplatePreviewSource } from './templateLibraryPreview';
import type { TemplateResponse } from './api/client';

const template = { id:'t',org_id:'org',name:'Saved source',source_kind:'pdf',version:2,updated_at:'2026-11-02T12:00:00Z',pdf_sha256:'ab'.repeat(32),page_count:1 } as TemplateResponse;
test('template previews retain the exact observed tenant, source and revision',()=>{
 expect(sameTemplatePreviewSource(template,{...template})).toBe(true);
 for(const [key,value]of Object.entries({id:'other',org_id:'other',source_kind:'blocks',version:3,updated_at:'new',pdf_sha256:'cd'.repeat(32),content_sha256:'changed'}))expect(sameTemplatePreviewSource(template,{...template,[key]:value})).toBe(false);
});
test('block preview reads bounded plain source content without mounting or evaluating it',()=>{
 const source={version:1,blocks:[{type:'heading',text:'Agreement'},{text:'<script>not executed</script>'},{blocks:[{text:'Nested content'}]},{rows:[['A','B']]},{html:'<img src="https://outside.invalid">'}]};
 expect(blockTemplatePreview(source)).toEqual({lines:['Agreement','<script>not executed</script>','Nested content','A · B'],truncated:false});
 const cycle:any={text:'Once'};cycle.blocks=[cycle];expect(blockTemplatePreview(cycle).lines).toEqual(['Once']);
 const huge=blockTemplatePreview({blocks:[{text:'x'.repeat(210000)}]});expect(huge.truncated).toBe(true);expect(huge.lines[0].length).toBe(200000);
});

const source=readFileSync(new URL('./components/TemplateReadPreview.svelte',import.meta.url),'utf8');
const ast:any=parse(source,{modern:true});
const mount=ast.instance.content.body.find((n:any)=>n.type==='ExpressionStatement'&&n.expression?.callee?.name==='onMount').expression.arguments[0];
const retire=ast.instance.content.body.find((n:any)=>n.type==='ExportNamedDeclaration'&&n.declaration?.id?.name==='retire').declaration;
const ts=new Bun.Transpiler({loader:'ts'});
const bindMount=new Function('env',`with(env){return (${ts.transformSync('const f = '+source.slice(mount.start,mount.end)).replace(/^const f = /,'').replace(/;\s*$/,'')});}`);
const bindRetire=new Function('env',`with(env){${ts.transformSync(source.slice(retire.start,retire.end))};return retire;}`);
function fixture(fresh:TemplateResponse=template){
 const calls:string[]=[],controller=new AbortController();const env:any={expected:template,controller,disposed:false,current:null,bytes:null,loading:true,error:null,pagesOwner:null,retirement:null,sameTemplatePreviewSource,
  getTemplate:async(id:string,signal:AbortSignal)=>{calls.push('GET:'+id);expect(signal).toBe(controller.signal);return fresh;},
  fetchVerifiedTemplatePDF:async()=>{calls.push('PDF');return new Uint8Array([37,80,68,70,45]);}
 };return{env,calls,mount:bindMount(env),retire:bindRetire(env)};
}
test('actual preview callback refuses a changed source or invalid page count before fetching PDF bytes',async()=>{
 for(const fresh of [{...template,version:3},{...template,page_count:0},{...template,page_count:501}]){const f=fixture(fresh);await f.mount();expect(f.env.error).toBeTruthy();expect(f.calls).toEqual(['GET:t']);expect(f.env.bytes).toBeNull();}
});
test('actual PDF preview fetches verified bytes only after its fresh exact source and never creates a document',async()=>{
 const f=fixture();await f.mount();expect(f.calls).toEqual(['GET:t','PDF']);expect(f.env.bytes).toEqual(new Uint8Array([37,80,68,70,45]));expect(f.env.error).toBeNull();expect(f.env.loading).toBe(false);
 expect(source).not.toContain('createDocument');expect(source).not.toContain('{@html');
});
test('closing a pending metadata or PDF read aborts it and prevents late adoption',async()=>{
 for(const phase of ['metadata','pdf']){const f=fixture();let resolve!:(v:any)=>void;if(phase==='metadata')f.env.getTemplate=()=>new Promise(r=>{resolve=r});else f.env.fetchVerifiedTemplatePDF=()=>new Promise(r=>{resolve=r});const pending=f.mount();await Promise.resolve();await f.retire();expect(f.env.controller.signal.aborted).toBe(true);const body=new Uint8Array([1,2,3]);resolve(phase==='metadata'?template:body);await pending;expect(f.env.current).toBeNull();expect(f.env.bytes).toBeNull();if(phase==='pdf')expect(body).toEqual(new Uint8Array(3));}
});
test('retirement waits for the existing native PDF owner and never reports failed cleanup as success',async()=>{
 for(const fail of [false,true]){const f=fixture();let resolve!:()=>void,reject!:(e:Error)=>void;const bytes=new Uint8Array([1,2]);f.env.bytes=bytes;f.env.pagesOwner={retire:()=>new Promise<void>((a,b)=>{resolve=a;reject=b})};const pending=f.retire();expect(f.retire()).toBe(pending);expect(bytes).toEqual(new Uint8Array([1,2]));if(fail){reject(new Error('cleanup refused'));await expect(pending).rejects.toThrow('cleanup refused');expect(bytes).toEqual(new Uint8Array([1,2]));}else{resolve();await pending;expect(bytes).toEqual(new Uint8Array(2));expect(f.env.bytes).toBeNull();}}
});

const library=readFileSync(new URL('../routes/templates/+page.svelte',import.meta.url),'utf8');
const page:any=parse(library,{modern:true});
const names=['closePreview','openTemplate','useFromLibrary','usePreview'];
const functions=page.instance.content.body.filter((n:any)=>n.type==='FunctionDeclaration'&&names.includes(n.id.name)).map((n:any)=>library.slice(n.start,n.end)).join('\n');
const bindActions=new Function('env',`with(env){${ts.transformSync(functions)};return{closePreview,openTemplate,useFromLibrary,usePreview};}`);
function actions(){const calls:string[]=[],env:any={disposed:false,creatingId:null,pendingCreation:false,removalBusy:false,selectedHTMLTemplate:null,htmlFormDirty:false,selectedTemplate:null,bindings:[],selectedParties:[],previewTemplate:null,previewOwner:undefined,previewRevision:0,error:null,$ui:(s:string)=>s,window:{confirm:()=>false},tick:async()=>{},goto:async(path:string)=>{calls.push('NAV:'+path)},useTemplate:async(t:TemplateResponse)=>{calls.push('USE:'+t.id)},previewPanel:{focus(){calls.push('focus')},scrollIntoView(){calls.push('scroll')}},creationPanel:{focus(){},scrollIntoView(){}}};return{env,calls,...bindActions(env)};}
test('Open is a real separate read/navigation action for every source and honors pending/dirty barriers',async()=>{
 for(const kind of ['pdf','blocks','html']){const f=actions(),t={...template,source_kind:kind}as TemplateResponse;await f.openTemplate(t);expect(f.calls.filter(c=>c.startsWith('USE:'))).toEqual([]);if(kind==='html')expect(f.calls).toEqual(['NAV:/templates/t/html']);else expect(f.env.previewTemplate).toBe(t);}
 for(const barrier of ['pending','busy','dirty']){const f=actions();if(barrier==='pending')f.env.pendingCreation=true;if(barrier==='busy')f.env.creatingId='other';if(barrier==='dirty'){f.env.selectedHTMLTemplate=template;f.env.htmlFormDirty=true;}await f.openTemplate(template);expect(f.env.previewTemplate).toBeNull();expect(f.calls).toEqual([]);}
});
test('a failed native preview retirement blocks both replacement and Use without invoking creation',async()=>{
 const f=actions();f.env.previewTemplate=template;f.env.previewOwner={canLeave:()=>true,retire:async()=>{throw new Error('unjoined')}};await f.openTemplate({...template,id:'next'});await f.useFromLibrary(template);expect(f.calls).toEqual([]);expect(f.env.previewTemplate).toBe(template);expect(f.env.error).toBeTruthy();
});

test('same-card reopen flushes the retired component before mounting the next instance',async()=>{
 const f=actions();f.env.previewTemplate=template;let retired=0;f.env.previewOwner={canLeave:()=>true,retire:async()=>{retired++;}};
 const flushes:Array<()=>void>=[];f.env.tick=()=>new Promise<void>(resolve=>flushes.push(resolve));
 const pending=f.openTemplate(template);
 for(let i=0;i<6;i++)await Promise.resolve();
 expect(retired).toBe(1);expect(f.env.previewTemplate).toBeNull();expect(flushes.length).toBe(1);
 flushes.shift()!();for(let i=0;i<6;i++)await Promise.resolve();
 expect(f.env.previewTemplate).toBe(template);expect(flushes.length).toBe(1);
 flushes.shift()!();await pending;expect(f.calls).toEqual(['focus','scroll']);
});

test('source preview reports shortened tables and enforces shared line and Unicode-safe character bounds',()=>{
 const rows=Array.from({length:1001},()=>['cell']);const table=blockTemplatePreview({rows});expect(table.truncated).toBe(true);expect(table.lines).toHaveLength(1000);
 const many=blockTemplatePreview({blocks:[...Array.from({length:1990},()=>({text:'paragraph'})),{rows:Array.from({length:100},()=>['cell'])}]});expect(many.truncated).toBe(true);expect(many.lines).toHaveLength(2000);
 const astral=blockTemplatePreview({text:'x'.repeat(199999)+'😀more'});expect(astral.truncated).toBe(true);expect(astral.lines[0]).toBe('x'.repeat(199999));expect(/[\uD800-\uDBFF]$/.test(astral.lines[0])).toBe(false);
});


test('unsaved or unknown template policy blocks the actual library replacement and Use callbacks', async()=>{
 const f=actions();let retired=0;f.env.previewTemplate=template;f.env.previewOwner={canLeave:()=>false,retire:async()=>{retired++;}};
 await f.openTemplate({...template,id:'next'});await f.useFromLibrary(template);
 expect(retired).toBe(0);expect(f.calls).toEqual([]);expect(f.env.previewTemplate).toBe(template);
});
test('actual preview leave guard preserves busy/unknown and explicit dirty confirmation',()=>{
 const node=ast.instance.content.body.find((n:any)=>n.type==='ExportNamedDeclaration'&&n.declaration?.id?.name==='canLeave').declaration;
 const bind=new Function('env',`with(env){${ts.transformSync(source.slice(node.start,node.end))};return canLeave;}`);
 for(const key of ['reminderBusy','reminderUnconfirmed']){const env:any={reminderBusy:false,reminderUnconfirmed:false,reminderDirty:false,$ui:(s:string)=>s,window:{confirm:()=>true}};env[key]=true;expect(bind(env)()).toBe(false);}
 const env={reminderBusy:false,reminderUnconfirmed:false,reminderDirty:true,$ui:(s:string)=>s,window:{confirm:()=>false}};
 expect(bind(env)()).toBe(false);env.window.confirm=()=>true;expect(bind(env)()).toBe(true);env.reminderDirty=false;env.window.confirm=()=>false;expect(bind(env)()).toBe(true);
});
