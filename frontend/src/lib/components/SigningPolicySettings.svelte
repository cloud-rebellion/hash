<script lang="ts">
  import { onMount } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { SigningRegistryController, initialSigningRegistryState, readSigningMarker, saveSigningMarker, signingKey, signingNilUUID, checkedSigningDefinition,
    type SigningRegistryState, type SigningWorkflowDefinition, type SigningWorkflowPreview, type SigningWorkflowView } from '$lib/signingRegistry';
  import { signingRegistryTransport } from '$lib/api/signingRegistry';

  let registryState = $state.raw<SigningRegistryState>(initialSigningRegistryState());
  let templateChoice = $state(''), definitionJSON = $state(''), draftError = $state('');
  let expectedRevision = $state(0), dirty = $state(false), replaceDraft = $state(false), stopConfirmed = $state(false);
  let mutationPin = $state(''), mutationKind = $state<'retire' | 'archive' | 'revoke'>('retire');
  const controller = new SigningRegistryController(signingRegistryTransport, next => { registryState = next; }, marker => saveSigningMarker(sessionStorage, marker), true);
  const preview = $derived(registryState.preview as SigningWorkflowPreview | null);
  const canWrite = $derived(registryState.fresh && registryState.context?.self.role === 'owner' && !registryState.busy && !registryState.marker && !registryState.markerError);
  const canEdit = $derived(!registryState.busy && !registryState.marker && !registryState.markerError);

  function edited() { dirty = true; replaceDraft = false; mutationPin = ''; draftError = ''; controller.invalidate(); }
  async function refresh() { mutationPin = ''; stopConfirmed = false; await controller.refresh(); }
  function startDesign() {
    if (!canWrite || (dirty && !replaceDraft)) return;
    const choice = registryState.templates.find(t => `${t.template.id}:${t.template.version}` === templateChoice), c = registryState.context;
    if (!choice || !c) return;
    const provider = choice.contract_profile.parties.find(p => p.slot === 'provider')!;
    const grantorFields = new Map([[provider.company_name, 'company_name'], [provider.company_id, 'company_id'], [provider.representative_name, 'name'], [provider.representative_email, 'email'], [provider.representative_authority, 'authority_basis']]);
    const definition: SigningWorkflowDefinition = { version: 1, id: crypto.randomUUID(), policy_id: crypto.randomUUID(), org_id: c.org_id, revision: 1, name: `${choice.name} signing workflow`, kind: 'reviewed_document_send_v1',
      template: choice.template, executor: { kind: 'member', user_id: c.user_id, credential_id: signingNilUUID }, operation: 'pre_sign_and_send',
      input_rules: { version: 1, source_schema_version: 3, standalone: true, signature_fields_only: true, author_must_be_grantor: true },
      data_rules: { version: 1, values: choice.values.map(v => grantorFields.has(v.name) ? { variable: v.name, mode: 'grantor_field', grantor_field: grantorFields.get(v.name)! } : { variable: v.name, mode: Object.hasOwn(choice.defaults, v.name) && (!v.required || !!choice.defaults[v.name].trim()) ? 'approved_default' : 'reviewed_value' }),
        sections: choice.sections.map(s => ({ section: s.name, mode: s.default_text.trim() ? 'approved_default' : 'reviewed_value' })) },
      recipient_rules: { version: 1, provider: 'named_grantor_exact', customer: 'printed_profile_exact', mode: 'parallel', provider_company_name: choice.defaults[provider.company_name] ?? '', provider_company_id: choice.defaults[provider.company_id] ?? '', provider_authority_basis: choice.defaults[provider.representative_authority] ?? '' },
      max_grant_duration_seconds: 30 * 86400, max_uses: 1 };
    controller.invalidate(); definitionJSON = JSON.stringify(definition, null, 2); expectedRevision = 0; dirty = true; replaceDraft = false; draftError = '';
  }
  function loadWorkflow(view: SigningWorkflowView) {
    if (!canWrite || (dirty && !replaceDraft) || view.archived || view.definition.revision !== view.current_revision || view.current_revision >= 1_000_000) return;
    controller.invalidate(); expectedRevision = view.current_revision;
    definitionJSON = JSON.stringify({ ...view.definition, revision: view.current_revision + 1 }, null, 2); dirty = true; replaceDraft = false; draftError = '';
  }
  async function review(event: SubmitEvent) {
    event.preventDefault(); if (!canWrite) return;
    try {
      if (new TextEncoder().encode(definitionJSON).length > 256 * 1024) throw new Error();
      const definition = checkedSigningDefinition(JSON.parse(definitionJSON)), c = registryState.context!;
      if (definition.org_id !== c.org_id || definition.executor.kind !== 'member' || definition.executor.user_id !== c.user_id || definition.executor.credential_id !== signingNilUUID || definition.revision !== expectedRevision + 1) throw new Error();
      draftError = '';
      await controller.preview({ request_id: crypto.randomUUID(), expected_org_id: c.org_id, expected_user_id: c.user_id, expected_revision: expectedRevision, definition });
    } catch { draftError = 'Enter a complete valid workflow definition for your selected approval and current member executor. Keep every declared value and section covered, and provide the provider company and authority assertions.'; controller.invalidate(); }
  }
  async function mutateWorkflow(view: SigningWorkflowView, kind: 'retire' | 'archive') {
    const reference = { id: view.definition.id, revision: view.definition.revision, sha256: view.definition_sha256 };
    if (mutationKind !== kind || mutationPin !== signingKey(reference)) return;
    mutationPin = ''; await controller.resource(kind === 'retire' ? 'workflow.retire' : 'workflow.archive', reference, true);
  }
  async function emergencyRevoke(reference: { id: string; revision: number; sha256: string }) {
    if (mutationKind !== 'revoke' || mutationPin !== signingKey(reference)) return;
    mutationPin = ''; await controller.resource('grant.owner_revoke', reference, true);
  }
  async function acknowledge() { await controller.acknowledge(); stopConfirmed = false; controller.invalidate(); mutationPin = ''; }
  beforeNavigate(({ from, to, willUnload, cancel }) => {
    if (!willUnload && from?.url.href === to?.url.href) return;
    if ((dirty || registryState.marker || registryState.busy) && !window.confirm('Leave this page? Unsaved workflow inputs stay only on this page. Pending request metadata is retained for inspection.')) { cancel(); return; }
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

<div class="px-4 sm:px-6 py-10 max-w-5xl mx-auto space-y-6" data-signing-policies>
  <div><p class="page-eyebrow">Settings · Signing</p><h1 class="page-title">Signing workflows and policies</h1></div>
  <div class="card p-5 space-y-2 border-l-4 border-warning"><h2 class="font-medium">Approved signing workflows</h2><p class="text-sm text-text-secondary">Approve exact workflow rules and manage recorded authority. Approval does not sign or send a document.</p>{#if registryState.context?.execution_available}<p class="text-sm text-text-secondary">An eligible agreement can use these rules only with current named authority and a confirmed execution.</p>{:else if registryState.context}<p class="text-sm text-text-secondary">Pre-signing is not currently available from this service.</p>{/if}</div>
  {#if registryState.error}<p role="alert" class="card p-4 text-danger text-sm">{registryState.error}</p>{/if}
  {#if registryState.notice}<p role="status" class="card p-4 text-sm">{registryState.notice}</p>{/if}
  {#if registryState.markerError}<p role="alert" class="card p-4 text-danger">Pending request metadata could not be verified. New changes remain blocked. Ask your operator to investigate.</p>{/if}
  {#if registryState.marker}
    <section class="card p-5 space-y-3" aria-label="Pending signing policy request">
      <h2 class="text-lg">Resolve the original request</h2><p class="text-sm">A missing response does not show that this operation failed. Another change remains blocked.</p>
      <p class="text-sm font-mono break-all">{registryState.marker.operation} · {registryState.marker.request_id}</p>
      <div class="flex flex-wrap gap-2"><button class="btn btn-secondary" disabled={!!registryState.busy} onclick={() => controller.inspect()}>Inspect request outcome</button>{#if controller.canRetry}<button class="btn btn-secondary" disabled={!!registryState.busy} onclick={() => controller.retry()}>Retry the exact request</button>{/if}</div>
      {#if registryState.outcome}<p class="text-sm">Verified outcome: <strong>{registryState.outcome.state}</strong> at {registryState.outcome.occurred_at}. {#if registryState.outcome.state === 'committed'}This is the recorded original operation; the current resource may have changed afterward.{/if}</p><button class="btn btn-primary" disabled={!!registryState.busy} onclick={acknowledge}>Acknowledge verified outcome</button>
      {:else if !registryState.marker.command_sha256}<label class="flex items-start gap-2 text-sm"><input type="checkbox" bind:checked={stopConfirmed} /><span>Stop this exact request if it has not committed.</span></label><button class="btn btn-secondary" disabled={!stopConfirmed || registryState.busy === 'stop'} onclick={() => controller.stop(stopConfirmed)}>Stop original request</button>{/if}
    </section>
  {/if}
  <button class="btn btn-secondary" disabled={!!registryState.busy} onclick={refresh}>Refresh signing policies</button>
  {#if registryState.context && registryState.context.self.role !== 'owner'}<p class="text-sm text-text-secondary">Owner access is required to approve, retire or archive workflows and emergency-revoke another member’s authority. Your personal authority remains available under <a class="underline" href="/settings/signing-authority">My signing authority</a>.</p>{/if}
  {#if registryState.context?.self.role === 'owner'}
    <section class="card p-5 space-y-4">
      <h2 class="text-lg">Start from an approved design</h2>
      <p class="text-sm text-text-secondary">Choose an exact approved source3 revision. The initial executor is your current authenticated member; this screen does not create API credentials. Provider identities come from the named self-grant, and only declared values and approved wording rules are allowed.</p>
      {#if registryState.templatesTruncated}<p class="text-sm text-text-secondary">The catalog is bounded to recent eligible approvals. Older approved revisions are retained in existing workflows; this list is not the complete template history.</p>{/if}
      <label class="block text-sm space-y-1"><span>Approved design revision</span><select aria-label="Approved signing design" class="w-full input" bind:value={templateChoice} disabled={!canWrite}><option value="">Select an approved design</option>{#each registryState.templates as t (`${t.template.id}:${t.template.version}`)}<option value={`${t.template.id}:${t.template.version}`}>{t.name} · version {t.template.version}</option>{/each}</select></label>
      {#if dirty}<label class="flex items-start gap-2 text-sm"><input type="checkbox" bind:checked={replaceDraft} /><span>Replace my unsaved workflow inputs when I start or load a revision.</span></label>{/if}
      <button class="btn btn-secondary" disabled={!canWrite || !templateChoice || (dirty && !replaceDraft)} onclick={startDesign}>Start from selected design</button>
    </section>
    <form class="card p-5 space-y-4" onsubmit={review}>
      <h2 class="text-lg">{expectedRevision ? 'Review the next workflow revision' : 'Review a new workflow'}</h2>
      <p class="text-sm text-text-secondary">This structured definition records readable rules, not a caller-supplied hash as approval. Review the actual values, wording, recipient assertions, validity and use limit. A CRM scalar rule must include the exact reviewed account and record-selection scope. New prose requires a human-reviewed workflow.</p>
      <details class="text-sm"><summary class="cursor-pointer">Rule modes</summary><p><strong>reviewed_value</strong>: human-reviewed document input. <strong>approved_default</strong>: approved design default. <strong>literal</strong>: this exact approved text. <strong>absent</strong>: optional value omitted. <strong>grantor_field</strong>: live named self-grant assertion. <strong>crm_scalar</strong>: declared field from the exact CRM scope.</p><p>approved_data_send_v1 cannot contain reviewed_value rules. This approval does not perform CRM reads or enable dispatch.</p></details>
      <label class="block text-sm space-y-2"><span>Workflow definition JSON</span><textarea aria-label="Workflow definition JSON" class="w-full input font-mono text-xs min-h-[24rem]" bind:value={definitionJSON} oninput={edited} disabled={!canEdit} spellcheck="false"></textarea></label>
      {#if draftError}<p role="alert" class="text-danger text-sm">{draftError}</p>{/if}
      <button class="btn btn-primary" type="submit" disabled={!canWrite || !definitionJSON}>Preview exact workflow policy</button>
    </form>
    {#if preview}
      <section class="card p-5 space-y-4" aria-label="Signing policy preview">
        <h2 class="text-lg">Review the exact approval</h2><p class="text-sm">{preview.intent.definition.name} · revision {preview.intent.definition.revision} · {preview.rules.input_mode}</p>
        <p class="text-sm">Template version {preview.intent.definition.template.version}, approved by {preview.intent.definition.template.approved_by} at {preview.intent.definition.template.approved_at}.</p>
        <pre class="p-3 bg-bg-elevated rounded text-xs whitespace-pre-wrap break-all">{JSON.stringify(preview.intent.definition, null, 2)}</pre>
        <p class="text-xs font-mono break-all">Workflow commitment: {preview.definition_sha256}</p><p class="text-xs text-text-muted">Confirmation expires {preview.expires_at}. No authority has been granted and no document has been signed.</p>
        <label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={registryState.confirmed} onchange={event => controller.confirm(event.currentTarget.checked)} disabled={!canWrite} /><span>I approve this exact template revision, executor, complete rule content, provider declarations and limits. Each execution must satisfy these rules and current named authority.</span></label>
        <button class="btn btn-primary" disabled={!canWrite || !registryState.confirmed} onclick={() => controller.approve()}>Approve workflow and policy</button>
      </section>
    {/if}
    <section class="space-y-3" aria-label="Approved signing workflows"><h2 class="text-lg">Recorded workflow approvals</h2>{#if !registryState.workflows.length}<p class="text-sm text-text-muted">No recorded workflow.</p>{/if}
      {#each registryState.workflows as w (`${w.definition.id}:${w.definition.revision}`)}
        {@const reference = { id: w.definition.id, revision: w.definition.revision, sha256: w.definition_sha256 }}
        <article class="card p-5 space-y-3"><p class="font-medium">{w.definition.name} · revision {w.definition.revision} · {w.archived ? 'Archived' : w.retired ? 'Retired revision' : 'Approved'}</p>
          <p class="text-sm">Template version {w.definition.template.version} · approved by {w.policy.approved_by} at {w.policy.approved_at}</p>
          <details class="text-sm"><summary class="cursor-pointer">Exact rules and approval pins</summary><pre class="p-3 text-xs whitespace-pre-wrap break-all">{JSON.stringify(w.definition, null, 2)}</pre><p class="font-mono break-all">Policy: {w.policy_reference.sha256}</p></details>
          {#if !w.archived}
            <button class="btn btn-secondary" disabled={!canWrite || (dirty && !replaceDraft) || w.definition.revision !== w.current_revision || w.current_revision >= 1000000} onclick={() => loadWorkflow(w)}>Load next workflow revision</button>
            {#if !w.retired}<label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={mutationKind === 'retire' && mutationPin === signingKey(reference)} onchange={event => { mutationKind = 'retire'; mutationPin = event.currentTarget.checked ? signingKey(reference) : ''; }} disabled={!canWrite} /><span>Retire this exact revision for future authority. Preserve its recorded approval and evidence.</span></label><button class="btn btn-secondary" disabled={!canWrite || mutationKind !== 'retire' || mutationPin !== signingKey(reference)} onclick={() => mutateWorkflow(w, 'retire')}>Retire workflow revision</button>{/if}
            {#if w.definition.revision === w.current_revision}<label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={mutationKind === 'archive' && mutationPin === signingKey(reference)} onchange={event => { mutationKind = 'archive'; mutationPin = event.currentTarget.checked ? signingKey(reference) : ''; }} disabled={!canWrite} /><span>Archive this workflow head and stop future use of its revisions.</span></label><button class="btn btn-secondary" disabled={!canWrite || mutationKind !== 'archive' || mutationPin !== signingKey(reference)} onclick={() => mutateWorkflow(w, 'archive')}>Archive workflow</button>{/if}
          {/if}
        </article>
      {/each}
    </section>
    <section class="space-y-3" aria-label="Organisation signing authorities"><h2 class="text-lg">Organisation authority and emergency revocation</h2><p class="text-sm text-text-secondary">Owners may revoke another member’s authority. They cannot grant consent on that member’s behalf.</p>
      {#each registryState.grants as g (g.reference.sha256)}<article class="card p-5 space-y-3"><p class="font-medium">{g.grant.grantor.name} · {g.grant.grantor.email} · {g.revoked ? 'Revoked' : g.expired ? 'Expired' : 'Recorded'}</p><p class="text-sm">{g.grant.grantor.company_name} · revision {g.grant.revision} · {g.consumed_uses} / {g.grant.max_uses} uses</p>{#if g.revocation_reason}<p class="text-sm">Recorded reason: {g.revocation_reason}</p>{/if}<details class="text-sm"><summary class="cursor-pointer">Exact named authority</summary><pre class="p-3 text-xs whitespace-pre-wrap break-all">{JSON.stringify(g.grant, null, 2)}</pre></details>{#if !g.revoked}<label class="flex items-start gap-2 text-sm"><input type="checkbox" checked={mutationKind === 'revoke' && mutationPin === signingKey(g.reference)} onchange={event => { mutationKind = 'revoke'; mutationPin = event.currentTarget.checked ? signingKey(g.reference) : ''; }} disabled={!canWrite} /><span>Emergency-revoke this exact named authority while preserving prior evidence.</span></label><button class="btn btn-secondary text-danger" disabled={!canWrite || mutationKind !== 'revoke' || mutationPin !== signingKey(g.reference)} onclick={() => emergencyRevoke(g.reference)}>Emergency-revoke authority</button>{/if}</article>{/each}
    </section>
  {/if}
</div>

<style>
  [data-signing-policies] { min-width: 0; overflow-wrap: anywhere; }
  .input { min-width: 0; max-width: 100%; padding: .65rem .75rem; border: 1px solid var(--color-border-light); border-radius: .375rem; background: var(--color-bg-elevated); display: block; }
</style>
