<script lang="ts">
 import { onMount, untrack } from 'svelte';
 import { beforeNavigate } from '$app/navigation';
 import type { DocumentResponse } from '$lib/api/client';
 import { finalPdfURL, auditCertURL } from '$lib/api/client';
 import { amendmentTransport } from '$lib/api/amendments';
 import { AmendmentWorkflow, initialAmendmentState, type AmendmentState } from '$lib/amendmentWorkflow';
 import { AMENDMENT_MODES, amendmentAllows, amendmentCopy, basisRequest, deliveryCopy, type AmendmentActor, type AmendmentBasis, type AmendmentMode, type AmendmentRecord } from '$lib/amendments';
 let { document: doc, actor, externalBusy = false, onStateChange }: {
  document: DocumentResponse; actor: AmendmentActor; externalBusy?: boolean;
  onStateChange: (state: { blocked: boolean; linked: boolean; notice: boolean; busy: boolean; dirty: boolean }) => void;
 } = $props();
 let view = $state.raw<AmendmentState>(initialAmendmentState());
 let mode = $state<AmendmentMode | ''>(''), policyID = $state('legacy');
 let reference = $state(''), clause = $state(''), condition = $state(''), allowed = $state<AmendmentMode[]>([]), emailAllowed = $state(false);
 let ownerReviewed = $state(false), coverReviewed = $state(false), formError = $state<string | null>(null);
 let subject = $state(''), noticeText = $state(''), recipientText = $state(''), editingNotice = $state(false);
 const workflow = new AmendmentWorkflow(untrack(() => $state.snapshot(doc)), untrack(() => actor), amendmentTransport, next => { view = next; }, () => !externalBusy);
 const editable = $derived.by(() => { view; externalBusy; return workflow.canWrite(); });
 const policy = $derived(view.inventory?.frozen_policies.find(row => row.frozen_policy_id === policyID));
 const permitted = $derived(policyID === 'legacy' ? allowed : policy?.allowed_modes ?? []);
 const dirty = $derived(!!view.pending || !!view.noticeReview || editingNotice || !!view.candidate || !!reference || !!clause || !!condition);
 $effect(() => { view; externalBusy; dirty; untrack(() => onStateChange({ blocked: workflow.ordinarySendBlocked(), linked: !!view.link, notice: view.link?.amendment.mode === 'agreed_notice', busy: workflow.mutating(), dirty })); });
 function resetReview() { ownerReviewed = false; coverReviewed = false; mode = ''; formError = null; }
 function toggleAllowed(value: AmendmentMode, checked: boolean) { allowed = checked ? [...allowed.filter(item => item !== value), value] : allowed.filter(item => item !== value); if (!allowed.includes('agreed_notice')) emailAllowed = false; resetReview(); }
 async function link() {
  formError = null; if (!editable || !view.inventory || !view.candidate || !mode || !permitted.includes(mode) || !coverReviewed || (policyID === 'legacy' && !ownerReviewed)) return;
  try {
   const basis: AmendmentBasis = policyID === 'legacy' ? { kind: 'reviewed_legacy_clause', clause_reference: reference, reviewed_clause: clause, allowed_modes: [...allowed], allowed_channels: emailAllowed ? ['email'] : [], effective_condition: condition } : basisRequest(policy!);
   await workflow.create({ request_id: crypto.randomUUID(), expected_head_id: view.inventory.head_id, expected_head_revision: view.inventory.head_revision, amendment_document_id: view.candidate.id, expected_document_updated_at: view.candidate.updated_at, mode, basis, cover_reviewed: true });
   if (!view.pending) { reference = ''; clause = ''; condition = ''; allowed = []; emailAllowed = false; resetReview(); }
  } catch (error) { formError = error instanceof Error ? error.message : 'Review the selected document and agreed process again.'; }
 }
 async function reviewNotice(record: AmendmentRecord) { formError = null; try { await workflow.reviewNotice(record, subject, noticeText, recipientText.split(/[\n,;]/).map(value => value.trim()).filter(Boolean)); } catch { formError = 'Review the notice and recipient email addresses again.'; } }
 async function issueNotice() { formError = null; editingNotice = false; try { await workflow.issueNotice(); } catch { formError = 'The saved amendment or notice review changed. Check saved amendments and review the notice again.'; } }
 function editNotice() { workflow.discardNoticeReview(); editingNotice = true; }
 beforeNavigate(({ cancel, from, to, willUnload }) => {
  if (!willUnload && from?.url.pathname === to?.url.pathname) return;
  if (dirty && !window.confirm('An amendment review or request is unfinished. Leave this page? A request already sent may still finish; check the saved amendments before submitting another.')) { cancel(); return; }
  workflow.interrupt();
 });
 onMount(() => {
  void workflow.refresh();
  const beforeUnload = (event: BeforeUnloadEvent) => { if (dirty || workflow.mutating()) { event.preventDefault(); event.returnValue = ''; } };
  const hidden = () => { if (window.document.hidden) workflow.interrupt(); };
  window.addEventListener('beforeunload', beforeUnload); window.document.addEventListener('visibilitychange', hidden);
  return () => { workflow.dispose(); window.removeEventListener('beforeunload', beforeUnload); window.document.removeEventListener('visibilitychange', hidden); };
 });
</script>

{#if view.inventory || view.error || view.busy || !view.fresh}
<section class="card p-5 mb-6 space-y-5" aria-label="Later amendments">
 <header class="flex flex-wrap items-start justify-between gap-3"><div><h2 class="font-display text-xl">Later amendments</h2><p class="text-sm text-text-secondary">The original signed agreement and its evidence stay saved. Each later amendment has its own document and agreed process.</p></div>
  <button type="button" class="btn btn-secondary" disabled={!!view.busy || externalBusy} onclick={() => workflow.refresh()}>Check saved amendments</button></header>
 {#if view.busy}<p role="status">{view.busy === 'create' ? 'Saving the reviewed amendment…' : view.busy === 'notice' ? 'Recording the reviewed notice…' : view.busy === 'revoke' ? 'Stopping further link access…' : 'Checking saved documents…'}</p>{/if}
 {#if view.error || formError}<p role="alert" class="text-danger">{formError ?? view.error}</p>{/if}
 {#if view.message}<p role="status">{view.message}</p>{/if}
 {#if view.pending}<div class="border border-warning rounded-md p-4 space-y-2"><p>The earlier reviewed request needs a confirmed saved result. Keep its exact content while checking.</p><button type="button" class="btn btn-secondary" disabled={!!view.busy || !view.fresh || externalBusy} onclick={() => workflow.retryReviewedRequest()}>Retry the same reviewed request</button></div>{/if}
 {#if view.inventory}
  {@const inventory = view.inventory}
  <section class="border border-border-light rounded-md p-4 space-y-2" aria-label="Original completed agreement">
   <h3 class="font-medium">Original agreement: {inventory.original.name}</h3><p class="text-sm text-text-secondary">Completed {new Date(inventory.original.completed_at).toLocaleString()}</p>
   <div class="flex flex-wrap gap-3 text-sm"><a class="underline" href={finalPdfURL(inventory.original_document_id)}>Original signed PDF</a><a class="underline" href={auditCertURL(inventory.original_document_id)}>Original evidence report</a>{#if view.link}<a class="underline" href={'/documents/' + inventory.original_document_id}>Original agreement and amendment history</a>{/if}</div>
  </section>
  {#if view.link}<p class="text-sm">This is a linked amendment. Its files, recipients and signature locations were prepared before linking. To propose different content, prepare a separate amendment document.</p>{/if}
  {#if inventory.amendments.length}<ol class="space-y-4" aria-label="Amendment history">
   {#each inventory.amendments as row (row.id)}<li class="border border-border-light rounded-md p-4 space-y-3">
    <div class="flex flex-wrap items-center justify-between gap-2"><h3 class="font-medium">{row.document_name}</h3>{#if row.id === inventory.head_id}<span class="text-xs text-accent">Latest proposed amendment</span>{/if}</div>
    <p class="text-sm">{amendmentCopy[row.mode].title} · Document status: {row.document_status} · Proposed {new Date(row.created_at).toLocaleString()}</p>
    <p class="text-sm text-text-secondary">{amendmentCopy[row.mode].description}</p>
    <details><summary class="cursor-pointer text-sm">Recorded agreement basis</summary><div class="mt-2 text-sm space-y-2"><p>{row.basis.kind === 'reviewed_legacy_clause' ? 'Agreement clause reviewed and attested by an account owner' : 'Policy saved with the original agreement'}</p><p>{row.basis.clause_reference}</p><blockquote class="whitespace-pre-wrap border-l-2 border-border-light pl-3">{row.basis.reviewed_clause}</blockquote><p>Recorded conditions: {row.basis.effective_condition}</p><p class="text-text-secondary">{row.basis.attribution} · {new Date(row.basis.reviewed_at).toLocaleString()}</p></div></details>
    <a class="btn btn-secondary" href={'/documents/' + row.document_id}>{row.mode === 'agreed_notice' ? 'Review the separate amendment document' : amendmentCopy[row.mode].action}</a>
    {#if row.notice}<section class="space-y-3" aria-label="Issued notice and email progress"><h4 class="font-medium">Recorded notice: {row.notice.subject}</h4><p class="whitespace-pre-wrap break-words text-sm">{row.notice.text}</p><p class="text-xs text-text-secondary">Issued {new Date(row.notice.issued_at).toLocaleString()}</p>
     <ul class="space-y-2">{#each row.notice.deliveries as delivery (delivery.email_delivery_id)}<li class="border-b border-border-light pb-2 text-sm space-y-2"><div class="flex flex-wrap justify-between gap-2"><span>{delivery.recipient_email}</span><span>{deliveryCopy(delivery.state)}</span></div><div class="flex flex-wrap justify-between items-center gap-2">{#if delivery.revoked_at}<span>Link access revoked {new Date(delivery.revoked_at).toLocaleString()}</span>{:else}<span class="text-text-secondary">Notice email link issued</span>{#if inventory.can_create && actor.role === 'owner'}<button type="button" class="btn btn-secondary text-xs" disabled={!editable} onclick={() => { if (window.confirm('Stop further access using this email link? Files already downloaded remain with the recipient.')) void workflow.revokeAccess(row, delivery.access_id); }}>Revoke link access</button>{/if}{/if}</div></li>{/each}</ul>
     <p class="text-sm text-text-secondary">Provider acceptance means the email service accepted the message. It does not establish delivery, recipient acceptance, signature or when a change takes effect.</p>
     {#if row.notice.verified_receipts.length}<h5 class="font-medium text-sm">Verified receipt events</h5><ul>{#each row.notice.verified_receipts as receipt (receipt.id)}<li class="text-sm">{receipt.kind} · {new Date(receipt.observed_at).toLocaleString()}</li>{/each}</ul>{:else}<p class="text-sm text-text-secondary">No verified receipt events are recorded.</p>{/if}
    </section>{:else if row.mode === 'agreed_notice' && row.id === inventory.head_id && inventory.can_create && actor.role === 'owner'}
     {#if view.noticeReview && view.noticeAmendmentID === row.id}<section class="bg-bg rounded-md p-4 space-y-3" aria-label="Review exact email notice"><h4 class="font-medium">Review the exact notice before issuing</h4><p class="font-medium">{view.noticeReview.subject}</p><p class="whitespace-pre-wrap break-words">{view.noticeReview.text}</p><p class="text-sm">To: {view.noticeReview.recipient_emails.join(', ')}</p><p class="text-sm">Accompanying document: {view.noticeDocument?.name}. The saved accompanying files are included through a separate read-only email link.</p><p class="text-sm text-text-secondary">Recorded conditions: {row.basis.effective_condition}</p><div class="flex flex-wrap gap-2"><button type="button" class="btn btn-primary" disabled={!editable} onclick={issueNotice}>Issue this email notice</button><button type="button" class="btn btn-secondary" disabled={!!view.busy || !!view.pending} onclick={editNotice}>Edit notice</button></div></section>
     {:else}<section class="space-y-3" aria-label="Prepare agreed email notice"><p class="text-sm">Prepare the notice using the channel and conditions recorded above. Review it before issuing; this does not request a signature or acknowledgement.</p><label class="block text-sm">Subject<input class="input w-full mt-1" bind:value={subject} maxlength="256" disabled={!editable} oninput={() => { editingNotice = true; workflow.discardNoticeReview(); }} /></label><label class="block text-sm">Notice text<textarea class="input w-full mt-1 min-h-32" bind:value={noticeText} maxlength="16384" disabled={!editable} oninput={() => { editingNotice = true; workflow.discardNoticeReview(); }}></textarea></label><label class="block text-sm">Recipient email addresses, one per line<textarea class="input w-full mt-1" bind:value={recipientText} disabled={!editable} oninput={() => { editingNotice = true; workflow.discardNoticeReview(); }}></textarea></label><button type="button" class="btn btn-secondary" disabled={!editable || !row.basis.allowed_channels?.includes('email')} onclick={() => reviewNotice(row)}>Review notice and recipients</button></section>{/if}
    {/if}
   </li>{/each}
  </ol>{:else}<p class="text-sm text-text-secondary">No later amendments have been linked.</p>{/if}
  {#if !view.link && inventory.can_create && actor.role === 'owner' && inventory.amendments.length < 64}
  <details class="border-t border-border-light pt-4"><summary class="cursor-pointer font-medium">Link a prepared amendment</summary><div class="mt-4 space-y-4">
   <p class="text-sm">Create a separate document first. Include an amendment cover identifying the original agreement, the changes and the agreed process. Finish its text, accompanying documents, PDF review, recipients and signature locations before linking. Linking alone does not send it.</p>
   <button type="button" class="btn btn-secondary" disabled={!editable} onclick={() => workflow.loadChoices()}>Choose a prepared draft</button>
   {#if view.choices.length}<label class="block text-sm">Separate amendment document<select class="input w-full mt-1" disabled={!editable} value={view.candidate?.id ?? ''} onchange={(event) => { resetReview(); void workflow.choose(event.currentTarget.value); }}><option value="">Choose a draft</option>{#each view.choices as choice (choice.id)}<option value={choice.id}>{choice.name}</option>{/each}</select></label><div class="flex gap-2"><button type="button" class="btn btn-secondary" disabled={!editable || view.offset === 0} onclick={() => workflow.loadChoices(Math.max(0, view.offset - 20))}>Previous drafts</button><button type="button" class="btn btn-secondary" disabled={!editable || view.offset + 20 >= view.total} onclick={() => workflow.loadChoices(view.offset + 20)}>More drafts</button></div>{/if}
   {#if view.candidate}<a class="text-sm underline" href={'/documents/' + view.candidate.id}>Review {view.candidate.name} before linking</a>{/if}
   <label class="block text-sm">Agreement basis<select class="input w-full mt-1" bind:value={policyID} disabled={!editable} onchange={resetReview}><option value="legacy">Review a clause in the original agreement</option>{#each inventory.frozen_policies as saved (saved.frozen_policy_id)}<option value={saved.frozen_policy_id}>Saved agreement policy: {saved.clause_reference ?? 'Later changes'}</option>{/each}</select></label>
   {#if policyID === 'legacy'}<div class="space-y-3"><p class="text-sm text-text-secondary">This is your review of an existing agreement clause. It is recorded as an owner attestation, not as a new approval by the other party.</p><label class="block text-sm">Clause reference<input class="input w-full mt-1" bind:value={reference} maxlength="512" disabled={!editable} oninput={resetReview} /></label><label class="block text-sm">Exact reviewed clause<textarea class="input w-full mt-1 min-h-24" bind:value={clause} maxlength="8192" disabled={!editable} oninput={resetReview}></textarea></label><fieldset class="space-y-2"><legend class="text-sm mb-2">Processes this clause permits</legend>{#each AMENDMENT_MODES as value}<label class="flex gap-2 items-start text-sm"><input type="checkbox" checked={allowed.includes(value)} disabled={!editable} onchange={(event) => toggleAllowed(value, event.currentTarget.checked)} /><span>{amendmentCopy[value].title}</span></label>{/each}</fieldset>{#if allowed.includes('agreed_notice')}<label class="flex gap-2 text-sm"><input type="checkbox" bind:checked={emailAllowed} disabled={!editable} onchange={resetReview} />The clause permits notice by email</label>{/if}<label class="block text-sm">Recorded timing and other conditions<textarea class="input w-full mt-1" bind:value={condition} maxlength="2048" disabled={!editable} oninput={resetReview}></textarea></label><label class="flex gap-2 text-sm"><input type="checkbox" bind:checked={ownerReviewed} disabled={!editable} />I reviewed this clause in the original agreement and attest that the selected processes and channel are permitted under the recorded conditions.</label></div>
   {:else if policy}<blockquote class="text-sm whitespace-pre-wrap border-l-2 pl-3 border-border-light">{policy.reviewed_clause}</blockquote><p class="text-sm">Recorded conditions: {policy.effective_condition}</p>{/if}
   <fieldset class="space-y-3"><legend class="font-medium mb-2">Process for this amendment</legend>{#each permitted as value}<label class="flex items-start gap-2 text-sm"><input type="radio" name={'amendment-mode-' + doc.id} value={value} bind:group={mode} disabled={!editable || !view.candidate || !amendmentAllows(view.candidate, value)} onchange={() => { coverReviewed = false; }} /><span><strong>{amendmentCopy[value].title}</strong><br />{amendmentCopy[value].description}</span></label>{/each}</fieldset>
   {#if view.candidate}<p class="text-sm text-text-secondary">This draft is prepared for {view.candidate.requires_signature ? 'signatures' : 'a process without signatures'}. Choose a compatible process. Change its preparation before linking if needed.</p>{/if}
   <label class="flex gap-2 text-sm"><input type="checkbox" bind:checked={coverReviewed} disabled={!editable} />I reviewed the separate amendment PDF and accompanying files, its reference to the original agreement, its recipients and the selected process.</label>
   <button type="button" class="btn btn-primary" disabled={!editable || !view.candidate || !mode || !permitted.includes(mode) || !coverReviewed || (policyID === 'legacy' && !ownerReviewed)} onclick={link}>Link this reviewed amendment</button>
  </div></details>{/if}
 {/if}
</section>{/if}
