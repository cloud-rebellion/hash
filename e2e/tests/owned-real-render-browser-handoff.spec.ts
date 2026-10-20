import { test, expect } from '@playwright/test';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runOwnedRealRenderBrowserV1, validateOwnedRealRenderHandoffV1 } from '../owned-real-render-browser-v1.mjs';

// Synthetic grammar vectors only; this tuple is not runtime/image authority.
function packet() {
  const id=(n:number)=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');
  const first={token:'a'.repeat(43),recipientID:id(2),fieldID:id(3),name:'Synthetic First Party',role:'customer'};
  const second={token:'b'.repeat(43),recipientID:id(4),fieldID:id(5),name:'Synthetic Second Party',role:'provider'};
  const field=(id:string,recipient:string,type:string,y:number)=>({id,recipient_id:recipient,type,page:3,x_pct:10,y_pct:y,w_pct:70,h_pct:8});
  return {base:'https://127.0.0.1:44991',documentID:id(1),pdfSHA256:'a'.repeat(64),sourceCommitment:'b'.repeat(64),pageCount:3,materializationRevision:1,rendererVersion:'8.36.0-hash.5',rendererImageID:'sha256:'+'c'.repeat(64),parties:[first,second],fieldGeometry:[field(first.fieldID,first.recipientID,'signature',42),field(second.fieldID,second.recipientID,'signature',79)],legacy:{documentID:id(6),token:'c'.repeat(43),recipientID:id(7),name:'Synthetic Autosave Person',textFieldID:id(8),signatureFieldID:id(9),pageCount:3,pdfSHA256:'d'.repeat(64)},legacyGeometry:[field(id(8),id(7),'text',20),field(id(9),id(7),'signature',54)]};
}

test('owned real-render handoff accepts one exact synthetic grammar tuple',()=>{
  const value={packet:packet(),donePath:'/private/tmp/owned-browser-done',artifacts:'/private/tmp/owned-browser-artifacts'};
  expect(validateOwnedRealRenderHandoffV1(value)).toBe(value);
});

for(const [name,edit]of [
 ['HTTP origin',(p:any)=>{p.base='http://127.0.0.1:44991';}],
 ['foreign origin',(p:any)=>{p.base='https://crm.example.test:44991';}],
 ['URL userinfo',(p:any)=>{p.base='https://user:secret@127.0.0.1:44991';}],
 ['origin path',(p:any)=>{p.base='https://127.0.0.1:44991/path';}],
 ['old renderer version',(p:any)=>{p.rendererVersion='8.36.0-hash.1';}],
 ['previous renderer version',(p:any)=>{p.rendererVersion='8.36.0-hash.2';}],
 ['missing image pin',(p:any)=>{p.rendererImageID='';}],
 ['duplicate party',(p:any)=>{p.parties[1]=p.parties[0];}],
 ['nil document',(p:any)=>{p.documentID='00000000-0000-0000-0000-000000000000';}],
 ['unbound field',(p:any)=>{p.fieldGeometry[0].recipient_id=p.parties[1].recipientID;}],
 ['out of page',(p:any)=>{p.fieldGeometry[0].page=4;}],
 ['overflow geometry',(p:any)=>{p.fieldGeometry[0].w_pct=99;}],
 ['missing manual source pin',(p:any)=>{p.legacy.pdfSHA256='';}],
 ['unbound manual field',(p:any)=>{p.legacyGeometry[1].id=p.legacy.textFieldID;}],
]as const){
 test('invalid '+name+' fails before a browser or output producer',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'hash-owned-handoff-'));
  try{
   const p=packet();edit(p);
   const donePath=path.join(root,'done.json'),artifacts=path.join(root,'artifacts');
   await expect(runOwnedRealRenderBrowserV1({packet:p,donePath,artifacts})).rejects.toThrow('invalid owned browser handoff');
   expect(await fs.readdir(root)).toEqual([]);
  }finally{await fs.rm(root,{recursive:true,force:true});}
 });
}
