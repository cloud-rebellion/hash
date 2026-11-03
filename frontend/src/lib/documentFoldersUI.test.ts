import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { APIError } from './api/client';
import { swedishFolderStaffMessages } from './staffFolderMessages';

const source=readFileSync(new URL('./components/DocumentFolders.svelte',import.meta.url),'utf8');
const ast:any=parse(source,{modern:true}), transpiler=new Bun.Transpiler({loader:'ts'});
const methods=ast.instance.content.body.filter((n:any)=>n.type==='FunctionDeclaration').map((n:any)=>source.slice(n.start,n.end)).join('\n');
const bind=new Function('env',`with(env){${transpiler.transformSync(methods)};return{loadFolders,selectFolder,openForm,validName,saveFolder,removeFolder,moveDocument};}`);
const row={id:'folder',name:'Customers',document_count:0,created_at:'2026-11-03',updated_at:'2026-11-03'};
function fixture(){
 const calls:string[]=[],env:any={disposed:false,revision:0,reader:null,loading:false,available:true,canWrite:true,disabled:false,busy:false,parentBusy:false,folders:[{...row}],total:1,offset:0,limit:25,selected:'folder',form:null,name:'',deleting:false,movingDocument:null,moveTarget:'choose',actionError:null,readError:null,notice:null,
   APIError,tick:async()=>{},nameInput:{focus(){calls.push('focus')}},
   listDocumentFolders:async(limit:number,offset:number)=>{calls.push(`LIST:${offset}`);return{folders:[{...row}],total:1,limit,offset};},
   createDocumentFolder:async(name:string)=>{calls.push('CREATE:'+name)},renameDocumentFolder:async(id:string,name:string)=>{calls.push('RENAME:'+id+':'+name)},deleteDocumentFolder:async(id:string)=>{calls.push('DELETE:'+id)},moveDocumentFolder:async(id:string,folder:string|null)=>{calls.push('MOVE:'+id+':'+folder);return{document_id:id,folder_id:folder}},
   onbusy:(busy:boolean)=>{env.parentBusy=busy},oncapability:(available:boolean,canWrite:boolean)=>calls.push(`CAP:${available}:${canWrite}`),onselect:(id:string)=>{calls.push('SELECT:'+id);env.selected=id},onchange:async()=>calls.push('CHANGE'),oncloseMove:()=>calls.push('CLOSE')};
 Object.defineProperties(env,{locked:{get:()=>env.disabled||env.busy},current:{get:()=>env.folders.find((f:any)=>f.id===env.selected)}});
 return{env,calls,...bind(env)};
}
const event={preventDefault(){}}as Event;

test('actual folder handlers block viewer, busy and unavailable writes before dispatch',async()=>{
 for(const barrier of ['viewer','busy','unavailable','disabled']){
  const f=fixture();f.env.form='create';f.env.name='Customer';f.env.deleting=true;f.env.movingDocument={id:'doc'};f.env.moveTarget='folder';
  if(barrier==='viewer')f.env.canWrite=false;if(barrier==='busy')f.env.busy=true;if(barrier==='unavailable')f.env.available=false;if(barrier==='disabled')f.env.disabled=true;
  await f.saveFolder(event);await f.removeFolder();await f.moveDocument(event);await f.openForm('rename');
  expect(f.calls).toEqual([]);
 }
});

test('folder reading is paginated and stale/aborted results cannot adopt another page',async()=>{
 const f=fixture();let first!:(v:any)=>void;
 f.env.listDocumentFolders=(limit:number,offset:number,signal:AbortSignal)=>offset===0?new Promise(resolve=>{first=resolve}):Promise.resolve({folders:[{...row,id:'page2'}],total:26,limit,offset});
 const old=f.loadFolders(0),oldReader=f.env.reader;await f.loadFolders(25);expect(oldReader.signal.aborted).toBe(true);
 first({folders:[row],total:1,limit:25,offset:0});await old;
 expect(f.env.offset).toBe(25);expect(f.env.folders[0].id).toBe('page2');expect(f.env.loading).toBe(false);
});

test('a server without the folder route remains truthful and can still navigate All',async()=>{
 const f=fixture();f.env.listDocumentFolders=async()=>{throw new APIError(404,'Not found.')};await f.loadFolders();
 expect(f.env.available).toBe(false);expect(f.env.readError).toBe('Folders are unavailable on this server.');
 f.calls.length=0;f.selectFolder('unfiled');expect(f.calls).toEqual([]);f.selectFolder('all');expect(f.calls).toEqual(['SELECT:all']);
});

test('actual create/rename validates Unicode names and preserves entered data on a refusal without false refresh',async()=>{
 const f=fixture();expect(f.validName('😀'.repeat(80))).toBe(true);expect(f.validName('😀'.repeat(81))).toBe(false);
 for(const value of ['', ' ', 'A\u0000B', 'A\u0085B'])expect(f.validName(value)).toBe(false);
 f.env.form='create';f.env.name=' Customers ';f.env.createDocumentFolder=async()=>{throw new APIError(409,'duplicate')};await f.saveFolder(event);
 expect(f.env.form).toBe('create');expect(f.env.name).toBe(' Customers ');expect(f.env.actionError).toBe('duplicate');expect(f.calls).toEqual([]);
 f.env.createDocumentFolder=async(name:string)=>f.calls.push('CREATE:'+name);await f.saveFolder(event);
 expect(f.calls).toContain('CREATE:Customers');expect(f.calls).toContain('LIST:0');expect(f.calls).toContain('CHANGE');expect(f.env.form).toBeNull();
});

test('one in-flight folder write blocks duplicate submit and does not announce success before its result',async()=>{
 const f=fixture();let resolve!:()=>void;f.env.form='create';f.env.name='New';f.env.createDocumentFolder=()=>{f.calls.push('CREATE');return new Promise<void>(r=>resolve=r)};
 const pending=f.saveFolder(event);await f.saveFolder(event);expect(f.calls).toEqual(['CREATE']);expect(f.env.notice).toBeNull();expect(f.env.busy).toBe(true);
 resolve();await pending;expect(f.calls.filter(x=>x==='CREATE')).toHaveLength(1);expect(f.env.busy).toBe(false);
});

test('delete is explicitly empty-only and a concurrent server409 does not remove selection or documents',async()=>{
 const f=fixture();f.env.deleting=true;f.env.folders[0].document_count=1;await f.removeFolder();expect(f.calls).toEqual([]);
 f.env.folders[0].document_count=0;f.env.deleteDocumentFolder=async()=>{f.calls.push('DELETE');throw new APIError(409,'move the documents before deleting this folder')};await f.removeFolder();
 expect(f.calls).toEqual(['DELETE']);expect(f.env.selected).toBe('folder');expect(f.env.folders).toHaveLength(1);expect(f.env.deleting).toBe(true);expect(f.env.notice).toBeNull();
});

test('a completed document move uses only sidecar IDs, confirms receipt and refreshes real counts without rewriting the document',async()=>{
 const f=fixture(),document={id:'doc',folder_id:null,status:'completed',updated_at:'original',pdf_sha256:'original',metadata:{retained:true}};const original=JSON.stringify(document);
 f.env.movingDocument=document;f.env.moveTarget='folder';await f.moveDocument(event);
 expect(f.calls).toEqual(['MOVE:doc:folder','CLOSE','LIST:0','CAP:true:true','CHANGE']);expect(JSON.stringify(document)).toBe(original);expect(f.env.notice).toBe('Document moved.');
});

test('unknown destinations, same folders and unconfirmed move receipts cannot announce a move',async()=>{
 for(const target of ['unknown','folder']){const f=fixture();f.env.movingDocument={id:'doc',folder_id:target==='folder'?'folder':null};f.env.moveTarget=target;await f.moveDocument(event);expect(f.calls).toEqual([]);}
 const f=fixture();f.env.movingDocument={id:'doc',folder_id:'folder'};f.env.moveTarget='unfiled';f.env.moveDocumentFolder=async()=>({document_id:'other',folder_id:null});await f.moveDocument(event);
 expect(f.calls).toEqual([]);expect(f.env.actionError).toContain('Refresh');expect(f.env.notice).toBeNull();
});

const pageSource=readFileSync(new URL('../routes/documents/+page.svelte',import.meta.url),'utf8');
const pageAST:any=parse(pageSource,{modern:true});
const pageMethods=pageAST.instance.content.body.filter((n:any)=>n.type==='FunctionDeclaration'&&['refresh','selectFolder','changeStatus','changePage','openMove','closeMove'].includes(n.id.name)).map((n:any)=>pageSource.slice(n.start,n.end)).join('\n');
const bindPage=new Function('env',`with(env){${transpiler.transformSync(pageMethods)};return{refresh,selectFolder,changeStatus,changePage,openMove,closeMove};}`);
function pageFixture(){const calls:any[]=[],env:any={disposed:false,listRevision:0,listController:null,loading:false,listError:null,docs:[],folder:'all',status:'all',offset:48,limit:24,total:100,search:'old query',movingDocument:null,busy:false,folderBusy:false,foldersAvailable:true,canManageFolders:true,moveTrigger:null,listDocuments:async(options:any,signal:AbortSignal)=>{calls.push({...options,signal});return{documents:[{id:'doc'}],total:100}}};return{env,calls,...bindPage(env)}}
test('changing folder/status resets server pagination and page-local search; paginating keeps the active scope',async()=>{
 const f=pageFixture();f.selectFolder('unfiled');await Promise.resolve();expect(f.calls[0]).toMatchObject({folder:'unfiled',status:'all',offset:0,limit:24});expect(f.env.search).toBe('');
 await f.refresh();f.env.status='completed';f.changeStatus();await Promise.resolve();expect(f.calls.at(-1)).toMatchObject({folder:'unfiled',status:'completed',offset:0});
 await f.refresh();f.changePage(24);await Promise.resolve();expect(f.calls.at(-1)).toMatchObject({folder:'unfiled',status:'completed',offset:24});
});
test('actual library refresh refuses stale responses and corrects an empty final page after a move',async()=>{
 const f=pageFixture();let old!:(v:any)=>void;f.env.listDocuments=()=>new Promise(resolve=>old=resolve);const pending=f.refresh();const reader=f.env.listController;
 f.env.listDocuments=async()=>({documents:[{id:'current'}],total:60});await f.refresh();expect(reader.signal.aborted).toBe(true);old({documents:[{id:'stale'}],total:200});await pending;expect(f.env.docs[0].id).toBe('current');expect(f.env.total).toBe(60);
 f.env.offset=48;f.env.listDocuments=async(options:any)=>{f.calls.push(options);return options.offset===48?{documents:[],total:48}:{documents:[{id:'last'}],total:48}};await f.refresh();expect(f.env.offset).toBe(24);expect(f.env.docs[0].id).toBe('last');
});
test('folder UI advertises page-local search, leaves real document actions intact and provides Swedish feedback',()=>{
 expect(pageSource).toContain("$ui('Search this page')");expect(pageSource).toContain("$ui('{count} matches on this page'");
 expect(pageSource).toContain('onsubmit={createBlank}');expect(pageSource).toContain('onsubmit={importProposal}');expect(pageSource).toContain('DocumentThumbnail item={doc}');expect(pageSource).not.toContain('window.prompt');
 for(const key of ['Move document','Create folder','Folders are unavailable on this server.','Search this page','The move could not be confirmed. Refresh before trying again.'])expect(swedishFolderStaffMessages[key]).toBeTruthy();
});


test('a write retains its busy owner through deferred refresh and blocks a second write until every callback settles',async()=>{
 const f=fixture();let release!:()=>void;f.env.form='create';f.env.name='First';
 f.env.listDocumentFolders=(limit:number,offset:number)=>new Promise(resolve=>{release=()=>resolve({folders:[row],total:1,limit,offset})});
 const first=f.saveFolder(event);for(let i=0;i<5;i++)await Promise.resolve();
 expect(f.env.busy).toBe(true);expect(f.env.parentBusy).toBe(true);
 f.env.form='create';f.env.name='Second';await f.saveFolder(event);
 expect(f.calls.filter(x=>x.startsWith('CREATE:'))).toEqual(['CREATE:First']);
 release();await first;expect(f.env.busy).toBe(false);expect(f.env.parentBusy).toBe(false);
});
test('parent write ownership blocks opening move-B while move-A is pending',()=>{
 const f=pageFixture();f.env.busy=true;f.env.movingDocument={id:'A'};
 f.openMove({id:'B'},{});expect(f.env.movingDocument.id).toBe('A');
 f.env.busy=false;f.openMove({id:'B'},{});expect(f.env.movingDocument.id).toBe('B');
});
