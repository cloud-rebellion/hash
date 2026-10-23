<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { preSignTransport } from '$lib/api/presignExecution';
  import { initialPreSignState, PreSignController, readPreSignMarker, savePreSignMarker, type PreSignResult, type PreSignState } from '$lib/presignExecution';
  import { signingKey } from '$lib/signingRegistry';

  type Props = { documentID: string; sourceCommitment: string; status: string; lawfulBasis: 'contract' | ''; blocked: boolean;
    mode?: 'manual' | 'presign'; onPendingChange: (pending: boolean) => void; onBusyChange: (busy: boolean) => void;
    onDraftChange?: (dirty: boolean) => void; onCommitted?: (result: PreSignResult) => boolean | Promise<boolean> };
  let { documentID, sourceCommitment, status, lawfulBasis, blocked, mode = $bindable('manual'), onPendingChange, onBusyChange, onDraftChange, onCommitted }: Props = $props();
  let executionState = $state<PreSignState>(initialPreSignState());
  let selected = $state('');
  let closeConfirmed = $state(false);
  let mounted = false;
  let observed = '';
  let notified = '';
  let notifying = '';
  const controller = new PreSignController(preSignTransport, value => {
    executionState = value;
    untrack(() => {
      onPendingChange(!!value.marker || value.markerError);
      onBusyChange(!!value.busy);
      onDraftChange?.(!!value.preview || value.confirmed);
      if (value.outcome?.state === 'committed' && value.outcome.result.document_id === documentID && onCommitted) {
        const key = `${value.outcome.result.command_sha256}:${value.outcome.result.publication}`;
        if (key !== notified && key !== notifying) {
          notifying = key;
          void Promise.resolve(onCommitted(value.outcome.result)).then(accepted => { if (accepted) notified = key; }).catch(() => {}).finally(() => { if (notifying === key) notifying = ''; });
        }
      }
    });
  }, marker => savePreSignMarker(sessionStorage, marker));
  onMount(() => {
    mounted = true;
    observed = `${documentID}:${sourceCommitment}:${status}`;
    const saved = readPreSignMarker(sessionStorage);
    controller.restore(saved.marker, saved.invalid);
    if (!saved.invalid && !saved.marker && status === 'draft' && mode === 'presign' && sourceCommitment) void controller.refresh(documentID);
  });
  $effect(() => {
    const scope = `${documentID}:${sourceCommitment}:${status}`;
    untrack(() => {
      if (!mounted || observed === scope) return;
      observed = scope; selected = ''; closeConfirmed = false;
      controller.invalidate();
      if (!executionState.marker && !executionState.markerError && status === 'draft' && mode === 'presign' && sourceCommitment) void controller.refresh(documentID);
    });
  });
  $effect(() => {
    const basis = lawfulBasis;
    untrack(() => { if (executionState.preview && executionState.preview.intent.lawful_basis !== basis) controller.draftChanged(); });
  });
  onDestroy(() => { mounted = false; controller.dispose(); });
  function selectMode(value: 'manual' | 'presign') {
    if (executionState.marker || executionState.markerError || executionState.busy) return;
    mode = value; controller.draftChanged(); selected = ''; closeConfirmed = false;
    if (value === 'presign' && status === 'draft' && sourceCommitment) void controller.refresh(documentID);
  }
  function choose(value: string) { selected = value; controller.draftChanged(); }
  const chosen = $derived(executionState.choices.find(choice => signingKey(choice.grant.reference) === selected));
  const sourceMatches = $derived(executionState.eligibility?.eligible === true && executionState.eligibility.source.source_commitment === sourceCommitment && executionState.eligibility.document_id === documentID);
</script>

<section class="space-y-3 my-4" aria-label="Company pre-signing">
  {#if executionState.markerError}
    <p role="alert" class="text-sm text-danger">The saved pre-signing request cannot be verified. Sending is blocked. Restore the original browser session and inspect its request before continuing.</p>
  {:else if executionState.marker}
    <div class="rounded-md border border-warning p-4 space-y-3">
      <h3 class="font-medium">Resolve the original pre-signing request</h3>
      <p class="text-sm">A missing response does not show that sending failed. Another send is blocked until the original outcome is confirmed.</p>
      {#if executionState.marker.document_id !== documentID}<p class="text-sm">This request belongs to <a class="underline" href={`/documents/${executionState.marker.document_id}`}>the original document</a>.</p>{/if}
      {#if executionState.outcome?.state === 'committed'}
        <p class="text-sm" role="status">{executionState.outcome.result.publication === 'sealing' ? 'The original request committed. Hash is securing the provider-signed PDF before inviting the customer.' : executionState.outcome.result.publication === 'published' ? 'The original provider pre-signing committed and customer invitations were published.' : executionState.outcome.result.publication === 'completed' ? 'The original customer signing journey completed.' : 'The original committed signing journey expired.'}</p>
        <p class="text-xs break-all">Visible PDF SHA-256: {executionState.outcome.result.visible_pdf_sha256}</p>
        <p class="text-xs">Recorded use: {executionState.outcome.result.use_number}</p>
      {:else if executionState.outcome?.state === 'closed'}
        <p class="text-sm" role="status">The original request was closed before commitment. Acknowledge this closure before preparing another review.</p>
      {/if}
      <div class="flex flex-wrap gap-2">
        <button class="btn btn-secondary" disabled={!!executionState.busy} onclick={() => controller.inspect()}>{executionState.busy === 'inspect' ? 'Checking…' : 'Inspect original request'}</button>
        {#if executionState.outcome && (executionState.outcome.state === 'closed' || executionState.outcome.result.publication !== 'sealing')}
          <button class="btn btn-secondary" disabled={!!executionState.busy} onclick={() => controller.acknowledge()}>Acknowledge recorded outcome</button>
        {/if}
      </div>
      {#if !executionState.marker.command_sha256 && executionState.outcome?.state !== 'committed'}
        <label class="flex items-start gap-2 text-sm"><input type="checkbox" bind:checked={closeConfirmed} disabled={!!executionState.busy} /><span>Close this exact original request if it has not committed. A committed result must remain recorded.</span></label>
        <button class="btn btn-secondary" disabled={!closeConfirmed || !!executionState.busy} onclick={() => controller.close(closeConfirmed)}>Close original request</button>
      {/if}
    </div>
  {:else if status === 'draft' && sourceCommitment}
    <fieldset class="space-y-2" disabled={!!executionState.busy}>
      <legend class="text-sm font-medium">Our company’s signing method</legend>
      <label class="flex items-center gap-2 text-sm"><input type="radio" name={`company-signing-method-${documentID}`} checked={mode === 'manual'} onchange={() => selectMode('manual')} />Invite participants to sign manually</label>
      <label class="flex items-center gap-2 text-sm"><input type="radio" name={`company-signing-method-${documentID}`} checked={mode === 'presign'} onchange={() => selectMode('presign')} />Pre-sign our company’s part using my exact named authority</label>
    </fieldset>
    {#if mode === 'presign'}
      <div class="rounded-md border border-border-light p-4 space-y-3">
        <p class="text-sm">Review the exact approved agreement and named authority. This action pre-signs the provider’s part and sends the customer their own signing invitation.</p>
        <button class="btn btn-secondary" disabled={!!executionState.busy || blocked} onclick={() => { selected = ''; void controller.refresh(documentID); }}>{executionState.busy === 'refresh' ? 'Checking…' : 'Refresh document and authority'}</button>
        {#if executionState.fresh && !executionState.context?.execution_available}<p class="text-sm" role="note">Pre-signing is not available from the current service. A fresh review is required before it can be selected.</p>
        {:else if executionState.fresh && !executionState.eligibility?.eligible}<p class="text-sm" role="note">This document is not eligible for provider pre-signing. An approved standalone agreement with both declared parties and parallel signing is required.</p>
        {:else if executionState.fresh && !executionState.choices.length}<p class="text-sm" role="note">No current named self-authority matches an available approved workflow. Review <a class="underline" href="/settings/signing-authority">My signing authority</a>.</p>{/if}
        {#if executionState.choices.length}
          <label class="block text-sm">Named authority and approved workflow
            <select class="input mt-1 w-full" value={selected} onchange={event => choose(event.currentTarget.value)} disabled={!!executionState.busy || blocked}>
              <option value="">Choose exact authority…</option>
              {#each executionState.choices as choice (signingKey(choice.grant.reference))}<option value={signingKey(choice.grant.reference)}>{choice.workflow.definition.name} · {choice.grant.grant.grantor.name} · {choice.grant.grant.max_uses - choice.grant.consumed_uses} uses remaining</option>{/each}
            </select>
          </label>
          {#if chosen}<p class="text-xs">{chosen.grant.grant.grantor.company_name} · {chosen.grant.grant.grantor.company_id} · authority revision {chosen.grant.grant.revision} · expires {chosen.grant.grant.expires_at}</p>{/if}
          <button class="btn btn-secondary" disabled={blocked || !lawfulBasis || !sourceMatches || !selected || !controller.canPrepare} onclick={() => lawfulBasis && controller.preview(selected, lawfulBasis, sourceCommitment)}>{executionState.busy === 'preview' ? 'Preparing review…' : 'Review exact pre-signing'}</button>
        {/if}
        {#if executionState.preview}
          <div class="space-y-2" aria-label="Exact pre-signing confirmation">
            <p class="text-sm"><strong>Provider:</strong> {executionState.preview.provider_name} · {executionState.preview.provider_email}</p>
            <p class="text-sm"><strong>Customer:</strong> {executionState.preview.customer_name} · {executionState.preview.customer_email}</p>
            <p class="text-sm whitespace-pre-wrap">{executionState.preview.disclosure}</p>
            <p class="text-xs">{executionState.preview.remaining_uses} uses remain before this request. Review expires {executionState.preview.expires_at}.</p>
            <label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={executionState.confirmed} onchange={event => controller.confirm(event.currentTarget.checked)} disabled={blocked || !!executionState.busy} /><span>I confirm this exact document, provider identity, authority and customer. Apply the provider signature and send only the customer’s invitation.</span></label>
            <button class="btn btn-primary" disabled={blocked || !sourceMatches || !controller.canConfirm} onclick={() => controller.execute()}>{executionState.busy === 'execute' ? 'Recording pre-signing…' : 'Pre-sign and send to customer'}</button>
          </div>
        {/if}
      </div>
    {/if}
  {/if}
  {#if executionState.error}<p role="alert" class="text-sm text-danger">{executionState.error}</p>{/if}
</section>
