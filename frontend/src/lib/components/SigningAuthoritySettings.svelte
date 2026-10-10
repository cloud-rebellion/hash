<script lang="ts">
  import { onMount } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { SigningRegistryController, initialSigningRegistryState, readSigningMarker, saveSigningMarker, signingKey, signingEligibleName,
    type SigningGrantIntent, type SigningGrantPreview, type SigningGrantView, type SigningRegistryState } from '$lib/signingRegistry';
  import { signingRegistryTransport } from '$lib/api/signingRegistry';

  let registryState = $state.raw<SigningRegistryState>(initialSigningRegistryState());
  let policyID = $state('');
  let companyName = $state(''), companyID = $state(''), authorityBasis = $state(''), font = $state('');
  let notBefore = $state(''), expiresAt = $state(''), maxUses = $state('1');
  let grantID = $state(''), expectedRevision = $state(0), dirty = $state(false);
  let replaceDraft = $state(false), stopConfirmed = $state(false), revokePin = $state('');
  const controller = new SigningRegistryController(signingRegistryTransport, next => { registryState = next; }, marker => saveSigningMarker(sessionStorage, marker));
  const availablePolicies = $derived(registryState.workflows.filter(w => !w.archived && !w.retired));
  const selectedPolicy = $derived(availablePolicies.find(w => signingKey(w.policy_reference) === policyID));
  const preview = $derived(registryState.preview as SigningGrantPreview | null);
  const canWrite = $derived(registryState.fresh && !!registryState.context && !registryState.busy && !registryState.marker && !registryState.markerError);
  const canCreate = $derived(canWrite && ['owner', 'sender'].includes(registryState.context!.self.role) && signingEligibleName(registryState.context!.self.name));
  const canConfirm = $derived(canCreate && !!preview && registryState.confirmed && !!registryState.signatureFont);
  const canEdit = $derived(!registryState.busy && !registryState.marker && !registryState.markerError);

  function edited() { dirty = true; replaceDraft = false; revokePin = ''; controller.invalidate(); }
  async function refresh() { stopConfirmed = false; revokePin = ''; await controller.refresh(); if (!font && registryState.context?.fonts[0]) font = registryState.context.fonts[0].font; }
  function loadGrant(view: SigningGrantView) {
    if (!canCreate || (dirty && !replaceDraft) || view.revoked || view.current_revision >= 1_000_000 || view.grant.grantor.user_id !== registryState.context?.user_id) return;
    controller.invalidate(); const g = view.grant;
    grantID = g.id; expectedRevision = view.current_revision; policyID = signingKey(g.policy);
    companyName = g.grantor.company_name; companyID = g.grantor.company_id; authorityBasis = g.grantor.authority_basis; font = g.signature.font;
    notBefore = g.not_before; expiresAt = g.expires_at; maxUses = String(g.max_uses); dirty = true; replaceDraft = false;
  }
  function newGrant() {
    if (!canEdit || (dirty && !replaceDraft)) return;
    controller.invalidate(); grantID = ''; expectedRevision = 0; policyID = ''; companyName = ''; companyID = ''; authorityBasis = ''; notBefore = ''; expiresAt = ''; maxUses = '1'; dirty = false; replaceDraft = false;
  }
  async function review(event: SubmitEvent) {
    event.preventDefault(); if (!canCreate || !selectedPolicy || !/^[1-9][0-9]{0,6}$/.test(maxUses) || Number(maxUses) > 1_000_000) return;
    const c = registryState.context!;
    if (!grantID) grantID = crypto.randomUUID();
    const intent: SigningGrantIntent = { request_id: crypto.randomUUID(), expected_org_id: c.org_id, expected_user_id: c.user_id, grant_id: grantID, expected_revision: expectedRevision,
      policy: selectedPolicy.policy_reference, company_name: companyName, company_id: companyID, authority_basis: authorityBasis, font,
      not_before: notBefore || '0001-01-01T00:00:00Z', expires_at: expiresAt, max_uses: Number(maxUses) };
    await controller.preview(intent);
  }
  async function revoke(view: SigningGrantView) {
    if (revokePin !== signingKey(view.reference)) return;
    revokePin = ''; await controller.resource('grant.self_revoke', view.reference, true);
  }
  async function acknowledge() { await controller.acknowledge(); stopConfirmed = false; edited(); }
  beforeNavigate(({ from, to, willUnload, cancel }) => {
    if (!willUnload && from?.url.href === to?.url.href) return;
    if ((dirty || registryState.marker || registryState.busy) && !window.confirm('Leave this page? Unsaved authority inputs stay only on this page. Pending request metadata is retained for inspection.')) { cancel(); return; }
    controller.interrupt();
  });
  onMount(() => {
    try { controller.restore(readSigningMarker(sessionStorage)); } catch { controller.restore(null, true); }
    void refresh();
    const hidden = () => { if (document.visibilityState === 'hidden') controller.interrupt(); };
    const focus = () => { if (!registryState.busy) void refresh(); };
    const unload = (event: BeforeUnloadEvent) => { if (dirty || registryState.marker || registryState.busy) { event.preventDefault(); event.returnValue = ''; } };
    document.addEventListener('visibilitychange', hidden); window.addEventListener('focus', focus); window.addEventListener('beforeunload', unload);
    return () => { controller.dispose(); document.removeEventListener('visibilitychange', hidden); window.removeEventListener('focus', focus); window.removeEventListener('beforeunload', unload); };
  });
</script>

<div class="px-4 sm:px-6 py-10 max-w-4xl mx-auto space-y-6" data-signing-authority>
  <div><p class="page-eyebrow">Settings · Signing</p><h1 class="page-title">My signing authority</h1></div>
  <div class="card p-5 space-y-2 border-l-4 border-warning">
    <h2 class="font-medium">Pre-sign execution unavailable</h2>
    <p class="text-sm text-text-secondary">You can record or revoke a named, limited authority. This screen does not sign a document or send an invitation. Existing documents continue through manual signing.</p>
  </div>
  {#if registryState.error}<p role="alert" class="card p-4 text-danger text-sm">{registryState.error}</p>{/if}
  {#if registryState.notice}<p role="status" class="card p-4 text-sm">{registryState.notice}</p>{/if}
  {#if registryState.markerError}<p role="alert" class="card p-4 text-danger">Pending request metadata could not be verified. New changes remain blocked. Ask your operator to investigate.</p>{/if}
  {#if registryState.marker}
    <section class="card p-5 space-y-3" aria-label="Pending signing authority request">
      <h2 class="text-lg">Resolve the original request</h2>
      <p class="text-sm">Another change is blocked until you inspect and acknowledge this exact request. A missing response does not show that the operation failed.</p>
      <p class="text-sm font-mono break-all">{registryState.marker.operation} · {registryState.marker.request_id}</p>
      <div class="flex flex-wrap gap-2">
        <button class="btn btn-secondary" disabled={!!registryState.busy} onclick={() => controller.inspect()}>Inspect request outcome</button>
        {#if controller.canRetry}<button class="btn btn-secondary" disabled={!!registryState.busy} onclick={() => controller.retry()}>Retry the exact request</button>{/if}
      </div>
      {#if registryState.outcome}
        <p class="text-sm">Verified outcome: <strong>{registryState.outcome.state}</strong> at {registryState.outcome.occurred_at}. {#if registryState.outcome.state === 'committed'}This records the original operation; current authority may have been revoked or revised afterward.{/if}</p>
        <button class="btn btn-primary" disabled={!!registryState.busy} onclick={acknowledge}>Acknowledge verified outcome</button>
      {:else if !registryState.marker.command_sha256}
        <label class="flex items-start gap-2 text-sm"><input type="checkbox" bind:checked={stopConfirmed} /><span>I want to stop this exact request if it has not committed.</span></label>
        <button class="btn btn-secondary" disabled={!stopConfirmed || registryState.busy === 'stop'} onclick={() => controller.stop(stopConfirmed)}>Stop original request</button>
      {/if}
    </section>
  {/if}
  <button class="btn btn-secondary" disabled={!!registryState.busy} onclick={refresh}>Refresh signing authority</button>
  {#if registryState.context}
    <section class="card p-5 space-y-2" aria-label="Current signing identity">
      <h2 class="text-lg">Your current Hash identity</h2>
      <p>{registryState.context.self.name || 'No current member name'} · {registryState.context.self.email}</p>
      <p class="text-sm text-text-secondary">{registryState.context.self.role} · This identity comes from your live membership. Company and representative-authority details below are your declarations, rather than external verification.</p>
      <p class="text-sm text-text-secondary">Authority is limited to documents you originally authored, the exact approved workflow and template revision, and the selected executor. Role loss, name or email changes, organisation changes or removal permanently revoke an existing authority. Restoring the old identity requires a new self-grant.</p>
    </section>
    {#if registryState.context.self.role === 'viewer'}<p class="text-sm text-text-secondary">You can inspect and revoke your own existing authority. A sender or owner role is required to record a new authority.</p>{/if}
    {#if !signingEligibleName(registryState.context.self.name)}<p class="text-sm text-text-secondary">Your live member name needs updating before a new named authority can be recorded. Existing authority and request outcomes remain available for inspection and revocation.</p>{/if}
    <form class="card p-5 space-y-4" onsubmit={review}>
      <h2 class="text-lg">{expectedRevision ? 'Review a new authority revision' : 'Record your signing authority'}</h2>
      <label class="block text-sm space-y-1"><span>Approved workflow and policy</span><select aria-label="Approved signing policy" bind:value={policyID} onchange={edited} disabled={!canCreate} class="w-full input"><option value="">Select an exact approved policy</option>{#each availablePolicies as w (w.policy_reference.sha256)}<option value={signingKey(w.policy_reference)}>{w.definition.name} · revision {w.definition.revision} · template version {w.definition.template.version}</option>{/each}</select></label>
      {#if selectedPolicy}
        <details class="text-sm space-y-2"><summary class="cursor-pointer">Review the exact workflow rules and approval</summary>
          <p>Executor: {selectedPolicy.definition.executor.kind} · {selectedPolicy.definition.executor.user_id}</p>
          <p>Template: {selectedPolicy.definition.template.id} · version {selectedPolicy.definition.template.version}</p>
          <p>Approved by {selectedPolicy.policy.approved_by} at {selectedPolicy.policy.approved_at}. Maximum {selectedPolicy.policy.max_uses} uses over {selectedPolicy.policy.max_grant_duration_seconds} seconds.</p>
          <pre class="p-3 bg-bg-elevated rounded text-xs whitespace-pre-wrap break-all">{JSON.stringify(selectedPolicy.definition, null, 2)}</pre>
          <p class="font-mono break-all">Policy commitment: {selectedPolicy.policy_reference.sha256}</p>
        </details>
      {/if}
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="text-sm space-y-1">Company name<input class="w-full input" aria-label="Declared company name" bind:value={companyName} oninput={edited} disabled={!canCreate} required maxlength="200" /></label>
        <label class="text-sm space-y-1">Company ID<input class="w-full input" aria-label="Declared company ID" bind:value={companyID} oninput={edited} disabled={!canCreate} required maxlength="100" /></label>
      </div>
      <label class="block text-sm space-y-1">Representative authority basis<input class="w-full input" aria-label="Declared authority basis" bind:value={authorityBasis} oninput={edited} disabled={!canCreate} required maxlength="500" /></label>
      <label class="block text-sm space-y-1">Signature font<select class="w-full input" aria-label="Signature font" bind:value={font} onchange={edited} disabled={!canCreate}>{#each registryState.context.fonts as f (f.font)}<option value={f.font}>{f.font}</option>{/each}</select></label>
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="text-sm space-y-1">Not before (optional UTC time)<input class="w-full input font-mono" bind:value={notBefore} oninput={edited} disabled={!canCreate} placeholder="2026-10-10T12:00:00Z" /></label>
        <label class="text-sm space-y-1">Expires at (UTC time)<input class="w-full input font-mono" bind:value={expiresAt} oninput={edited} disabled={!canCreate} required placeholder="2026-11-10T12:00:00Z" /></label>
      </div>
      <label class="block text-sm space-y-1">Maximum uses<input class="w-full input" type="text" inputmode="numeric" pattern={'[1-9][0-9]{0,5}|1000000'} bind:value={maxUses} oninput={edited} disabled={!canCreate} required /></label>
      <p class="text-sm text-text-secondary">A revision needs a new explicit review and authorization. Revoked authority cannot be revived.</p>
      <button class="btn btn-primary" type="submit" disabled={!canCreate || !selectedPolicy}>Preview exact authority</button>
    </form>
    {#if preview && registryState.signatureFont}
      <section class="card p-5 space-y-4" aria-label="Signing authority preview">
        <h2 class="text-lg">Review your exact authorization</h2>
        <p class="text-4xl break-words" style:font-family={registryState.signatureFont}>{preview.grantor.name}</p>
        <p class="text-sm">{preview.grantor.email} · {preview.grantor.company_name} · {preview.grantor.company_id}</p>
        <p class="text-sm">Declared authority: {preview.grantor.authority_basis}</p>
        <p class="text-sm">{preview.signature.font} · bundled font verified. No document has been signed.</p>
        <p class="text-sm font-medium">Disclosure reserved for a future delegated execution:</p><p class="text-sm whitespace-pre-wrap">{registryState.context.disclosure.text}</p>
        <p class="text-xs text-text-muted">Disclosure version {preview.disclosure.version}. Preview expires {preview.expires_at}. Maximum {preview.intent.max_uses} uses; authority expires {preview.intent.expires_at}.</p>
        <label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={registryState.confirmed} onchange={event => controller.confirm(event.currentTarget.checked)} disabled={!canCreate} /><span>I authorize this exact named authority, policy, signature style, validity and use limit. I understand that pre-sign execution is currently unavailable.</span></label>
        <button class="btn btn-primary" disabled={!canConfirm} onclick={() => controller.approve()}>Confirm my signing authority</button>
      </section>
    {/if}
    <section class="space-y-3" aria-label="Recorded personal signing authorities">
      <h2 class="text-lg">Your recorded authorities</h2>
      {#if !registryState.grants.length}<p class="text-sm text-text-muted">No recorded authority.</p>{/if}
      {#if dirty}<label class="flex items-start gap-2 text-sm"><input type="checkbox" bind:checked={replaceDraft} /><span>Replace my unsaved authority inputs when I load or clear a draft.</span></label>{/if}
      <button class="btn btn-secondary" disabled={!canEdit || (dirty && !replaceDraft)} onclick={newGrant}>Clear inputs for a new authority</button>
      {#each registryState.grants as g (g.reference.sha256)}
        <article class="card p-5 space-y-3">
          <p class="font-medium">{g.grant.grantor.name} · revision {g.grant.revision} · {g.revoked ? 'Revoked' : g.expired ? 'Expired' : 'Recorded'}</p>
          <p class="text-sm">{g.grant.grantor.company_name} · {g.consumed_uses} / {g.grant.max_uses} uses · expires {g.grant.expires_at}</p>
          {#if g.revocation_reason}<p class="text-sm">Recorded revocation reason: {g.revocation_reason}</p>{/if}
          <details class="text-sm"><summary class="cursor-pointer">Exact recorded authority</summary><pre class="p-3 text-xs whitespace-pre-wrap break-all">{JSON.stringify(g.grant, null, 2)}</pre><p class="font-mono break-all">{g.reference.sha256}</p></details>
          {#if !g.revoked}
            <button class="btn btn-secondary" disabled={!canCreate || g.current_revision >= 1000000 || (dirty && !replaceDraft)} onclick={() => loadGrant(g)}>Load this authority for revision</button>
            <label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={revokePin === signingKey(g.reference)} onchange={event => { revokePin = event.currentTarget.checked ? signingKey(g.reference) : ''; }} disabled={!canWrite} /><span>Revoke this exact authority. Earlier evidence is preserved.</span></label>
            <button class="btn btn-secondary text-danger" disabled={!canWrite || revokePin !== signingKey(g.reference)} onclick={() => revoke(g)}>Revoke my authority</button>
          {/if}
        </article>
      {/each}
    </section>
  {/if}
</div>

<style>
  [data-signing-authority] { min-width: 0; overflow-wrap: anywhere; }
  .input { min-width: 0; max-width: 100%; padding: .65rem .75rem; border: 1px solid var(--color-border-light); border-radius: .375rem; background: var(--color-bg-elevated); display: block; }
</style>
