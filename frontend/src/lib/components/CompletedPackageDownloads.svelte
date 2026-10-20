<script lang="ts">
 import { onMount,onDestroy,untrack } from 'svelte';
 import { fetchCompletedPackage,fetchCompletedPackagePDF,serialCompletedDownloadV1,type CompletedPackage } from '$lib/completedPackage';
 let {token}:{token:string}=$props();
 const original=untrack(()=>token);
 let packet=$state.raw<CompletedPackage|null>(null),busy=$state(true),downloading=$state<number|null>(null),error=$state<string|null>(null);
 let abort:AbortController|null=null,disposed=false,epoch=0;
 const current=(mine:number)=>!disposed&&token===original&&epoch===mine;
 async function load(){
  if(disposed||downloading!==null)return;
  const mine=++epoch;abort?.abort();const request=new AbortController();abort=request;
  packet=null;busy=true;error=null;
  try{const next=await fetchCompletedPackage(original,request.signal);if(current(mine)&&!request.signal.aborted)packet=next;}
  catch{if(current(mine)&&!request.signal.aborted)error='This completion link is invalid, expired, or temporarily unavailable. Contact the sender for copies if it cannot be reloaded.';}
  finally{if(current(mine))busy=false;}
 }
 async function download(position:number){
  if(!packet?.value||busy||downloading!==null||disposed)return;
  const source=packet,mine=epoch,request=new AbortController();abort?.abort();abort=request;downloading=position;error=null;
  try{await serialCompletedDownloadV1(async()=>{
   if(!current(mine)||request.signal.aborted)return;
   const bytes=await fetchCompletedPackagePDF(source,position,request.signal);
   try{
    if(!current(mine)||request.signal.aborted)return;
    const selected=position===0?source.value!.main:source.value!.annexes[position-1];
    const blob=new Blob([bytes.buffer as ArrayBuffer],{type:'application/pdf'});
    const url=URL.createObjectURL(blob);
    try{
     const anchor=document.createElement('a');anchor.href=url;anchor.download=(selected.title.replace(/[\\/\u0000-\u001f\u007f]/g,'_').slice(0,120)||'contract-original')+'.pdf';anchor.rel='noopener';document.body.append(anchor);try{anchor.click();}finally{anchor.remove();}
     // Blob construction detached its bytes. Keep one short-lived URL owner
     // through browser dispatch, then revoke it before the next allocation.
     await new Promise<void>(resolve=>setTimeout(resolve,1000));
    }finally{URL.revokeObjectURL(url);}
   }finally{bytes.fill(0);}
  });}
  catch{if(current(mine)&&!request.signal.aborted)error='This original PDF could not be verified. Reload the archive before downloading it again.';}
  finally{if(current(mine))downloading=null;}
 }
 onMount(()=>{void load();});
 onDestroy(()=>{disposed=true;epoch++;abort?.abort();});
</script>

<section class="mx-auto max-w-3xl p-6 space-y-5" aria-label="Completed contract files">
 <h1 class="font-display text-2xl">Your completed contract</h1>
 <p class="text-sm text-text-secondary">Save the completed PDF, its separate evidence report, and any original attachments. These links expire with your completion email.</p>
 {#if busy}<p role="status">Checking your completion link…</p>{/if}
 {#if error}<p role="alert" class="text-danger">{error}</p>{/if}
 {#if packet}
  <div class="flex flex-wrap gap-3">
   <a class="btn btn-primary" href={`/sign/${packet.token}/final-pdf`} download>Download completed PDF</a>
   <a class="btn btn-secondary" href={`/sign/${packet.token}/audit-cert`} download>Download evidence report</a>
  </div>
  {#if packet.value}
   <h2 class="font-display text-lg">Original contract package</h2>
   <p class="text-sm">These are the exact original files included in the agreement. The completed PDF and report above are separate outputs.</p>
   <ol class="space-y-3">
    {#each [packet.value.main,...packet.value.annexes] as member,position (position)}
     <li class="border border-border-light rounded p-4 space-y-2">
      <p>{position===0?'Main document':`Attachment ${position}`} · {member.title}</p>
      <p class="text-xs text-text-secondary">{member.category?member.category+' · ':''}{member.pages} page{member.pages===1?'':'s'}</p>
      <button type="button" class="btn btn-secondary" disabled={downloading!==null} onclick={()=>download(position)}>{downloading===position?'Verifying original PDF…':'Download original PDF'}</button>
     </li>
    {/each}
   </ol>
   <details class="text-xs"><summary>Package fingerprints</summary><code class="block break-all">{packet.value.manifest_sha256}</code><code class="block break-all">{packet.value.legal_commitment_sha256}</code></details>
  {:else}<p class="text-sm">This agreement has no separate captured attachment package. Download the completed PDF and report above.</p>{/if}
 {/if}
 <button type="button" class="btn btn-secondary" disabled={busy||downloading!==null} onclick={load}>Reload archive</button>
</section>
