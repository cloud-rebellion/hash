import type { TemplateResponse } from './api/client';

// A preview is tied to the list observation, not whichever revision arrived last.
export function sameTemplatePreviewSource(expected: TemplateResponse, current: TemplateResponse): boolean {
 return expected.id === current.id && expected.org_id === current.org_id && expected.source_kind === current.source_kind
  && expected.version === current.version && expected.updated_at === current.updated_at
  && expected.content_sha256 === current.content_sha256 && expected.pdf_sha256 === current.pdf_sha256;
}

// Plain source content only: never interpret HTML, URLs, conditions or user code.
// This bounded reading view is not the final rendered contract.
export function blockTemplatePreview(value: unknown): { lines: string[]; truncated: boolean } {
 const pending: unknown[] = [value], seen = new WeakSet<object>(), lines: string[] = [];
 let nodes=0, characters=0, truncated=false;
 function prefix(text:string,limit:number):string {
  let end=Math.min(text.length,limit);
  if(end>0 && end<text.length && /[\uD800-\uDBFF]/.test(text[end-1]) && /[\uDC00-\uDFFF]/.test(text[end]))end--;
  return text.slice(0,end);
 }
 function append(text:string):boolean {
  if(!text.trim())return true;
  if(lines.length>=2000 || characters>=200000){truncated=true;return false;}
  const kept=prefix(text,200000-characters);
  if(kept.length){lines.push(kept);characters+=kept.length;}
  if(kept.length<text.length){truncated=true;return false;}
  return true;
 }
 while(pending.length) {
  if(nodes++ >= 20000 || characters >= 200000 || lines.length >= 2000) {truncated=true;break;}
  const node=pending.pop();if(!node || typeof node !== 'object' || seen.has(node))continue;seen.add(node);
  if(Array.isArray(node)){pending.push(...node.slice(0,10000).reverse());if(node.length>10000)truncated=true;continue;}
  const row=node as Record<string,unknown>;
  if(typeof row.text==='string' && !append(row.text))break;
  if(Array.isArray(row.rows)){
   if(row.rows.length>1000)truncated=true;
   for(const cells of row.rows.slice(0,1000)){
    if(!Array.isArray(cells))continue;
    let text='';
    if(cells.length>1000)truncated=true;
    for(const cell of cells.slice(0,1000)){
     if(typeof cell!=='string')continue;
     const addition=(text?' · ':'')+prefix(cell,200000-characters);
     const kept=prefix(addition,200000-characters-text.length);
     text+=kept;
     if(kept.length<addition.length || cell.length>200000-characters){truncated=true;break;}
    }
    if(!append(text))break;
   }
  }
  if(row.content)pending.push(row.content);if(row.blocks)pending.push(row.blocks);
 }
 return {lines,truncated};
}
