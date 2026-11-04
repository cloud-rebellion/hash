<script lang="ts">
 import { onDestroy, onMount, untrack } from 'svelte';
 import { X, ArrowUpRight, FileText } from 'lucide-svelte';
 import { getTemplate, fetchVerifiedTemplatePDF, type TemplateResponse } from '$lib/api/client';
 import { ui, staffLocale } from '$lib/staffPreferences';
 import { blockTemplatePreview, sameTemplatePreviewSource } from '$lib/templateLibraryPreview';
 import VerifiedPDFPages from './VerifiedPDFPages.svelte';
 import ReminderPolicySettings from './ReminderPolicySettings.svelte';
 let { template, onClose, onUse, disabled=false, canManageReminders=false }: { template:TemplateResponse;onClose:()=>void;onUse:()=>void;disabled?:boolean;canManageReminders?:boolean }=$props();
 let reminderBlocked=$state(true), reminderBusy=$state(false), reminderDirty=$state(false), reminderUnconfirmed=$state(false);
 export function canLeave():boolean { if (reminderBusy || reminderUnconfirmed) return false; return !reminderDirty || window.confirm($ui('Discard unsaved reminder changes?')); }
 let loading=$state(true), error=$state<string|null>(null), current=$state.raw<TemplateResponse|null>(null), bytes=$state.raw<Uint8Array|null>(null);
 const expected=untrack(()=>template), controller=new AbortController();let disposed=false;
 let pagesOwner:{retire():Promise<void>}|null=null, retirement:Promise<void>|null=null;
 const contents=$derived(blockTemplatePreview(current?.blocks_json));
 export function retire():Promise<void>{
  if(retirement)return retirement;disposed=true;controller.abort();
  retirement=(pagesOwner?.retire()??Promise.resolve()).then(()=>{bytes?.fill(0);bytes=null;current=null;});
  void retirement.catch(()=>{});return retirement;
 }
 onMount(async()=>{
  try {
   const fresh=await getTemplate(expected.id,controller.signal);
   if(disposed)return;
   if(!sameTemplatePreviewSource(expected,fresh))throw new Error('The template changed. Refresh the library before opening it.');
   current=fresh;
   if(fresh.source_kind==='pdf'){
    if(!fresh.pdf_sha256 || !Number.isInteger(fresh.page_count)||fresh.page_count!<1||fresh.page_count!>500)throw new Error('Refresh this template before opening its PDF preview.');
    const body=await fetchVerifiedTemplatePDF(fresh.id,fresh.version,fresh.pdf_sha256,controller.signal);
    if(disposed){body.fill(0);return;}bytes=body;
   }
  }catch(cause){if(!disposed)error=(cause as Error).message;}
  finally{if(!disposed)loading=false;}
 });
 onDestroy(()=>{void retire();});
</script>
<section class="read-preview" aria-label={$ui('Template preview')}>
 <header class="preview-header"><div><p class="page-eyebrow">{$ui('Template preview')}</p><h2>{template.name}</h2></div><button type="button" class="close-preview" aria-label={$ui('Close preview')} onclick={onClose}><X class="size-5" /></button></header>
 <div class="preview-description"><p>{$ui(template.source_kind==='pdf'?'This is the saved PDF, including its existing layout. Use this template to create a new document.':'Read-only template content. Use this template to create and edit a new document.')}</p><span>{$ui('Version {version}',{version:template.version})} · {new Date(template.updated_at).toLocaleDateString($staffLocale==='sv'?'sv-SE':'en-GB')}</span></div>
 {#if loading}<p class="p-8 text-sm text-text-secondary" role="status">{$ui('Loading preview…')}</p>
 {:else if error}<p class="p-6 text-sm text-danger" role="alert">{$ui(error)}</p>
 {:else if bytes && current?.source_kind==='pdf'}<div class="pdf-pages"><VerifiedPDFPages {bytes} proofKey={`${current.id}:${current.version}:${current.pdf_sha256}`} expectedPages={current.page_count!} onProof={()=>{}} ariaLabel={$ui('Template PDF')} translate={(text)=>$ui(text)} onOwner={(owner)=>{pagesOwner=owner;}} /></div>
 {:else if current?.source_kind==='blocks'}<div class="block-content"><div class="paper-content">{#if contents.lines.length}{#each contents.lines as line,index}<p class:content-heading={index===0}>{line}</p>{/each}{:else}<div class="blank-content"><FileText class="size-8" /><p>{$ui('This block template is empty.')}</p><p>{$ui('Create content in a document, then save it as a template. For a new editable design, choose Create HTML design.')}</p></div>{/if}</div>{#if contents.truncated}<p class="mt-4 text-sm text-text-secondary">{$ui('This source preview is shortened. Create a document to review all of its content.')}</p>{/if}</div>{/if}
 {#if canManageReminders}<div class="p-5"><ReminderPolicySettings scope="template" id={template.id} externalBlocked={disabled}
  onStateChange={(state)=>{reminderBlocked=state.blocked;reminderBusy=state.busy;reminderDirty=state.dirty;reminderUnconfirmed=state.unconfirmed;}} /></div>{/if}
 <footer><button type="button" class="btn btn-secondary" onclick={onClose}>{$ui('Close')}</button><button type="button" class="btn btn-primary" disabled={disabled||loading||!!error||(canManageReminders&&reminderBlocked)} onclick={onUse}>{$ui('Use template')}<ArrowUpRight class="size-4" /></button></footer>
</section>
<style>
 .read-preview{margin:0 0 28px;border:1px solid var(--t-border);border-radius:16px;overflow:hidden;background:var(--t-bg-surface);}
 .preview-header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;padding:24px;}.preview-header h2{font-size:23px;letter-spacing:-.6px;line-height:1.4;margin-top:9px;overflow-wrap:anywhere;}.close-preview{padding:8px;border:1px solid var(--t-border);border-radius:8px;cursor:pointer;}
 .preview-description{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;padding:0 24px 22px;font-size:12px;line-height:1.7;color:var(--t-text-secondary);}.preview-description p{max-width:650px;}.preview-description span{flex:none;font-family:var(--font-mono);font-size:10px;}
 .pdf-pages{max-width:840px;margin:0 auto;padding:24px;}.block-content{padding:28px;background:var(--t-bg-hover);}.paper-content{max-width:700px;min-height:300px;max-height:600px;overflow:auto;margin:0 auto;padding:42px;background:#fff;color:#202124;box-shadow:0 12px 24px -20px #00000066;}.paper-content p{font-size:14px;line-height:1.8;white-space:pre-wrap;margin-bottom:18px;overflow-wrap:anywhere;}.paper-content .content-heading{font-size:22px;font-weight:600;line-height:1.4;margin-bottom:26px;}.blank-content{padding:30px 0;text-align:center;color:#525252;}.blank-content :global(svg){margin:0 auto 20px;}.blank-content p:last-child{font-size:12px;max-width:420px;margin:0 auto;}footer{display:flex;justify-content:flex-end;gap:10px;border-top:1px solid var(--t-border);padding:18px 24px;}@media(max-width:580px){.preview-description{display:block;}.preview-description span{display:block;margin-top:12px;}.block-content{padding:16px;}.paper-content{padding:26px;}.pdf-pages{padding:12px;}}
</style>
