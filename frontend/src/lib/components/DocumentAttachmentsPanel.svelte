<script lang="ts">
 import { onMount, tick, untrack } from 'svelte';
 import { beforeNavigate } from '$app/navigation';
 import type { DocumentResponse } from '$lib/api/client';
 import type { PackageSendObservation } from '$lib/packageSend';
 import { attachmentTransport, fetchSelectedAttachmentPDF } from '$lib/api/documentAttachments';
 import { DocumentAttachmentsController, attachmentDocumentKey, attachmentLabel, initialAttachmentState, type AttachmentActor, type AttachmentMember, type AttachmentState } from '$lib/documentAttachments';
 import { AttachmentPreviewController, initialAttachmentPreview, type AttachmentPreviewState } from '$lib/documentAttachmentPreview';
 import VerifiedPDFPages from './VerifiedPDFPages.svelte';
 let { document: doc, actor, mainEditorClean, externalBusy = false, reconciliationBusy = false, packageReviewRequest = { revision: 0, inspect: false }, onSaved, onStateChange }: {
  document: DocumentResponse; actor: AttachmentActor; mainEditorClean: boolean; externalBusy?: boolean; reconciliationBusy?: boolean; packageReviewRequest?: { revision: number; inspect: boolean };
  onSaved: (document: DocumentResponse, expectedUpdatedAt: string, reconciliation?: boolean) => boolean;
  onStateChange: (attachmentState: { busy: boolean; dirty: boolean; blocked: boolean; message: string; packageSend?: PackageSendObservation }) => void;
 } = $props();
 let attachmentState = $state.raw<AttachmentState>(initialAttachmentState()), preview = $state.raw<AttachmentPreviewState>(initialAttachmentPreview());
 let previewOwner: { retire(): Promise<void> } | null = null;
 let reconciling = false;
 let seenPackageReview = untrack(() => packageReviewRequest.revision);
 let title = $state(''), category = $state(''), query = $state('');

 let seenDoc = untrack(() => attachmentDocumentKey(doc)), seenActor = untrack(() => JSON.stringify(actor)), candidateID = '';
 const controller = new DocumentAttachmentsController(untrack(() => doc), untrack(() => ({ ...actor })), attachmentTransport,
  next => { attachmentState = next; }, () => mainEditorClean && !(reconciling ? reconciliationBusy : externalBusy), (next, expected) => {
   if (!onSaved(next, expected, reconciling)) return false; seenDoc = attachmentDocumentKey(next); return true;
  });
 const previewController = new AttachmentPreviewController(fetchSelectedAttachmentPDF, async () => { await tick(); const owned=previewOwner; await owned?.retire(); if(previewOwner===owned) previewOwner=null; }, next => { preview = next; });
 const dirty = $derived.by(() => { attachmentState; return controller.dirty(); });
 const canEdit = $derived.by(() => { attachmentState; mainEditorClean; externalBusy; return controller.canEdit(); });
 const canSelect = $derived.by(() => { attachmentState; mainEditorClean; externalBusy; return controller.canSelect() && attachmentLabel(title) && attachmentLabel(category, true); });
 const choices = $derived((attachmentState.choices?.documents ?? []).filter(d => !query || d.name.toLocaleLowerCase().includes(query.toLocaleLowerCase())));
 const removed = $derived(attachmentState.baseline?.members.filter(m => !attachmentState.draft.some(next => next.document_id === m.document_id)) ?? []);
 const message = $derived(attachmentState.needsReadback ? 'Inspect and reconcile the saved attachments before sending.' : dirty ? 'Save or undo attachment edits before sending.' : attachmentState.baseline?.requires_reselection ? 'Some selected files need proof repair before sending.' : attachmentState.baseline?.members.length ? 'The exact saved attachments will be included in the contract package.' : 'Load and verify the saved attachments before sending.');
 $effect(() => { const pin = attachmentDocumentKey(doc), account = JSON.stringify(actor); untrack(() => {
  if (pin !== seenDoc || account !== seenActor) { seenDoc = pin; seenActor = account; void previewController.close(); if (doc.status === 'draft') controller.syncDocument(doc, actor); else controller.interrupt(); }
 }); });
 $effect(() => { attachmentState; preview; untrack(() => onStateChange({ busy: controller.mutating(), dirty: controller.barrier() || !!attachmentState.candidate, blocked: controller.sendBlocked() || preview.blocked || preview.closing, packageSend: preview.blocked || preview.closing ? undefined : controller.sendObservation(), message: preview.blocked ? 'Refresh the page to close the attachment preview before sending.' : message })); });
 $effect(() => { const candidate = attachmentState.candidate; untrack(() => { if (candidate?.id !== candidateID) { candidateID = candidate?.id ?? ''; if (candidate) { title = candidate.name; category = ''; } } }); });
 $effect(() => {
  const request = packageReviewRequest;
  untrack(() => {
   if (request.revision === seenPackageReview) return;
   seenPackageReview = request.revision;
   controller.requireSendReadback();
   if (request.inspect && !externalBusy) void controller.inspectReadback();
  });
 });
 async function refresh() {
  if (attachmentState.needsReadback) { await controller.inspectReadback(); return; }
  if ((dirty || attachmentState.candidate) && !window.confirm('Discard the unsaved attachment edits and reload the saved selection?')) return;
  await previewController.close(); if (preview.blocked) return; controller.undo(); await controller.refresh();
 }
 async function select() { await previewController.close(); if (!preview.blocked) await controller.select(title, category); }
 async function save() {
  const confirmed = !removed.length || window.confirm('Remove ' + removed.length + ' attachment(s) from this draft agreement? Their original source documents stay saved.');
  if (!confirmed) return; await previewController.close(); if (!preview.blocked) await controller.saveLayout(confirmed);
 }
 async function open(member: AttachmentMember) { if (!attachmentState.fresh || attachmentState.needsReadback || attachmentState.busy || !attachmentState.baseline) return; await previewController.open(doc.org_id, attachmentState.baseline, member); }
 async function useReadback() { if ((dirty || attachmentState.candidate) && !window.confirm('Replace unsaved attachment edits with the inspected saved agreement and attachments?')) return; await previewController.close(); if (!preview.blocked) { reconciling=true; try { controller.acceptReadback(); } finally { reconciling=false; } } }
 beforeNavigate(({ cancel, from, to, willUnload }) => {
  if (!willUnload && from?.url.pathname === to?.url.pathname) return;
  if ((dirty || attachmentState.candidate || controller.mutating()) && !window.confirm('Attachment changes are unsaved or being saved. Leave this agreement? An interrupted save may still finish.')) { cancel(); return; }
  controller.interrupt(); void previewController.close();
 });
 onMount(() => {
  void controller.refresh();
  const beforeUnload = (event: BeforeUnloadEvent) => { if (dirty || attachmentState.candidate || controller.mutating()) { event.preventDefault(); event.returnValue = ''; } };
  const hidden = () => { if (globalThis.document.visibilityState === 'hidden') { controller.interrupt(); void previewController.close(); } };
  globalThis.window.addEventListener('beforeunload', beforeUnload); globalThis.document.addEventListener('visibilitychange', hidden);
  return () => { controller.dispose(); if(previewOwner)previewController.observeRetirement(previewOwner.retire()); void previewController.dispose().catch(() => {}); globalThis.window.removeEventListener('beforeunload', beforeUnload); globalThis.document.removeEventListener('visibilitychange', hidden); onStateChange({ busy: false, dirty: false, blocked: true, message: 'Load the saved attachments before sending.' }); };
 });
</script>

<section class="card p-6 mb-6 space-y-4 min-w-0" aria-label="Contract attachments" data-document-attachments>
 <div class="flex flex-wrap justify-between items-center gap-3"><h2 class="font-display text-lg">Attachments</h2>
  <button type="button" class="btn btn-secondary" disabled={!!attachmentState.busy || externalBusy} onclick={refresh}>Refresh attachments</button></div>
 <p class="text-sm text-text-secondary">Add supporting agreements, policies, specifications or other business documents. Selected files keep their exact saved versions. Signing or acknowledging the main agreement applies to the complete listed package.</p>
 {#if attachmentState.error}<p role="alert" class="text-sm text-danger">{attachmentState.error}</p>{/if}
 {#if attachmentState.notice}<p role="status" class="text-sm">{attachmentState.notice}</p>{/if}
 {#if attachmentState.busy}<p role="status" class="text-sm">{controller.mutating() ? 'Saving attachments and checking the saved result…' : 'Checking saved documents…'}</p>{/if}
 {#if !mainEditorClean || externalBusy}<p role="note" class="text-sm text-warning">Finish or undo changes in the document, CRM information, recipients or signature locations before editing attachments. Your drafts stay in place.</p>{/if}
 {#if attachmentState.needsReadback}<div class="border border-warning rounded-md p-4 space-y-3 text-sm">
  <p>A saved version changed or a save outcome needs checking. Your local attachment edits are retained. Do not repeat the earlier save.</p>
  <button type="button" class="btn btn-secondary" disabled={!!attachmentState.busy || reconciliationBusy} onclick={() => controller.inspectReadback()}>Inspect saved attachments</button>
  {#if attachmentState.readback}<p>Saved agreement: {attachmentState.readback.document.name} · {attachmentState.readback.document.updated_at}</p>
   <ol class="space-y-1">{#each attachmentState.readback.inventory.members as member (member.document_id)}<li>{member.ordinal}. {member.title}{member.category ? ' · ' + member.category : ''} · {member.pdf_pages} pages</li>{/each}</ol>
   {#if !attachmentState.readback.inventory.members.length}<p>No attachments are saved.</p>{/if}
   <button type="button" class="btn btn-secondary" disabled={!!attachmentState.busy || reconciliationBusy || !mainEditorClean} onclick={useReadback}>Use inspected saved agreement and attachments</button>
  {/if}
 </div>{/if}
 {#if attachmentState.baseline?.requires_reselection}<p role="note" class="text-sm text-warning">Some older selections need proof repair before they can be sent. Their saved PDF versions remain available for inspection.</p>{/if}
 {#if attachmentState.baseline}<ol class="space-y-3" aria-label="Selected attachments">
  {#each attachmentState.draft as row, index (row.document_id)}{@const saved = attachmentState.baseline.members.find(m => m.document_id === row.document_id)!}
   <li class="border border-border-light rounded-md p-4 space-y-3" data-attachment-id={row.document_id}>
    <div class="grid sm:grid-cols-2 gap-3">
     <label class="text-sm">Attachment {index + 1} title<input aria-label={'Attachment ' + (index + 1) + ' title'} value={row.title} disabled={!canEdit} oninput={e => controller.labels(row.document_id, e.currentTarget.value, row.category)} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
     <label class="text-sm">Document type<input aria-label={'Attachment ' + (index + 1) + ' type'} value={row.category} list="attachment-business-types" disabled={!canEdit} oninput={e => controller.labels(row.document_id, row.title, e.currentTarget.value)} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
    </div>
    {#if !attachmentLabel(row.title) || !attachmentLabel(row.category, true)}<p role="alert" class="text-sm text-warning">Shorten the title or type and remove surrounding spaces or control characters before saving.</p>{/if}
    <p class="text-xs text-text-secondary">Saved PDF · {saved.pdf_pages} pages · {new Intl.NumberFormat().format(saved.pdf_bytes)} bytes</p>
    <div class="flex flex-wrap gap-2">
     <button type="button" class="btn btn-secondary" disabled={!attachmentState.fresh || attachmentState.needsReadback || !!attachmentState.busy || preview.blocked || externalBusy} onclick={() => open(saved)}>Preview selected PDF</button>
     <button type="button" class="btn btn-secondary" aria-label={'Move attachment ' + (index + 1) + ' up'} disabled={!canEdit || index === 0} onclick={() => controller.move(row.document_id, -1)}>Move up</button>
     <button type="button" class="btn btn-secondary" aria-label={'Move attachment ' + (index + 1) + ' down'} disabled={!canEdit || index === attachmentState.draft.length - 1} onclick={() => controller.move(row.document_id, 1)}>Move down</button>
     <button type="button" class="btn btn-secondary" disabled={!canEdit} onclick={() => controller.remove(row.document_id)}>Remove from draft</button>
    </div>
   </li>
  {/each}
 </ol>{#if !attachmentState.draft.length}<p class="text-sm">No attachments are selected in this draft.</p>{/if}{/if}
 {#if dirty}<div class="flex flex-wrap items-center gap-3">
  <button type="button" class="btn btn-primary" disabled={!canEdit || attachmentState.draft.some(m => !attachmentLabel(m.title) || !attachmentLabel(m.category, true))} onclick={save}>Save attachment changes</button>
  <button type="button" class="btn btn-secondary" disabled={!!attachmentState.busy} onclick={() => controller.undo()}>Undo unsaved attachment edits</button>
  {#if removed.length}<p class="text-sm text-warning">{removed.length} attachment(s) will be removed when you save.</p>{/if}
 </div>{/if}
 <datalist id="attachment-business-types"><option value="DPA"></option><option value="NDA"></option><option value="Statement of work"></option><option value="SLA"></option><option value="Pricing"></option><option value="Specifications"></option><option value="Policy"></option></datalist>
 <details class="space-y-3" aria-label="Add supporting document"><summary class="cursor-pointer text-sm font-medium">Add a document</summary>
  <button type="button" class="btn btn-secondary mt-3" disabled={!canEdit || dirty} onclick={() => controller.list(0)}>Browse saved PDF drafts</button>
  {#if attachmentState.choices}<label class="block text-sm">Filter this page<input aria-label="Filter attachment choices" bind:value={query} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
   <ul class="space-y-2">{#each choices as choice (choice.id)}<li data-document-id={choice.id} class="flex flex-wrap items-center justify-between gap-2"><span class="text-sm break-words">{choice.name}{choice.html_review_required ? ' · PDF review required' : ''}</span><button type="button" class="btn btn-secondary" disabled={!canEdit || dirty} onclick={() => controller.choose(choice.id)}>Choose this document</button></li>{/each}</ul>
   {#if !choices.length}<p class="text-sm">No eligible PDF drafts on this page. Check another page or create and review the source document first.</p>{/if}
   <div class="flex flex-wrap gap-2"><button type="button" class="btn btn-secondary" disabled={!canEdit || dirty || attachmentState.choices.offset === 0} onclick={() => controller.list(Math.max(0, attachmentState.choices!.offset - 20))}>Previous documents</button>
    <button type="button" class="btn btn-secondary" disabled={!canEdit || dirty || attachmentState.choices.offset + 20 >= attachmentState.choices.total} onclick={() => controller.list(attachmentState.choices!.offset + 20)}>More documents</button></div>
  {/if}
  {#if attachmentState.candidate}<div class="space-y-3 border border-border-light rounded-md p-4">
   <p class="text-sm">Source: {attachmentState.candidate.name}. Adding it stores the exact current PDF version. Later source edits will not replace the selected file.</p>
   <a class="text-sm underline" target="_blank" rel="noopener noreferrer" href={'/documents/' + attachmentState.candidate.id}>Open source for review</a>
   {#if doc.html_review_required || attachmentState.candidate.html_review_required}<p role="note" class="text-sm text-warning">Review the main document and source PDF before adding this attachment.</p>{/if}
   <label class="block text-sm">New attachment title<input aria-label="New attachment title" bind:value={title} disabled={!canEdit} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
   <label class="block text-sm">New attachment type<input aria-label="New attachment type" list="attachment-business-types" bind:value={category} disabled={!canEdit} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
   <button type="button" class="btn btn-primary" disabled={!canSelect} onclick={select}>Add exact current PDF</button>
   <button type="button" class="btn btn-secondary" disabled={!!attachmentState.busy} onclick={() => controller.clearCandidate()}>Cancel document selection</button>
  </div>{/if}
 </details>
 {#if preview.error}<p role="alert" class="text-sm text-danger">{preview.error}</p>{/if}
 {#if preview.opening || preview.closing}<p role="status" class="text-sm">{preview.closing ? 'Closing the selected PDF…' : 'Verifying the selected PDF…'}</p>{/if}
 {#if preview.selection}<div class="space-y-3 border-t border-border-light pt-4" hidden={preview.opening || preview.closing}>
  <div class="flex flex-wrap justify-between items-center gap-3"><h3 class="font-medium">Selected attachment: {preview.selection.title}</h3><button type="button" class="btn btn-secondary" onclick={() => previewController.close()}>Close attachment preview</button></div>
  {#key preview.selection.key}<VerifiedPDFPages onOwner={(owner)=>{previewOwner=owner;}} bytes={preview.selection.bytes} proofKey={preview.selection.key} expectedPages={preview.selection.pages} ariaLabel="Selected attachment" onProof={() => {}} onRetirement={(retirement)=>previewController.observeRetirement(retirement)} />{/key}
 </div>{/if}
</section>
