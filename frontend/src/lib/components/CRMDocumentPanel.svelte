<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import type { DocumentResponse } from '$lib/api/client';
  import { crmDocumentTransport } from '$lib/api/crmDocument';
  import { CRM_KINDS, CRMDocumentController, crmBaseline, crmDocumentPin, initialCRMDocumentState, validCRMSearch,
    type CRMDocumentActor, type CRMDocumentState, type CRMKind } from '$lib/crmDocument';

  let { document: doc, actor, editorClean, otherBusy = false, refreshRevision = 0, onApplied, onStateChange }: {
    document: DocumentResponse; actor: CRMDocumentActor; editorClean: boolean; otherBusy?: boolean; refreshRevision?: number;
    onApplied: (document: DocumentResponse) => boolean; onStateChange: (blocked: boolean, busy: boolean) => void;
  } = $props();
  let crmState = $state.raw<CRMDocumentState>(initialCRMDocumentState());
  let searchKind = $state<CRMKind>('crm.company'), query = $state(''), clock = $state(0);
  let mounted = false;
  const originalActor = untrack(() => ({ ...actor }));
  const controller = new CRMDocumentController(untrack(() => doc), originalActor, crmDocumentTransport,
    (next) => { crmState = next; }, () => editorClean && !otherBusy, (next) => {
      if (!onApplied(next)) return false;
      seenDocument = crmDocumentPin(next); return true;
    });
  let seenDocument = untrack(() => crmDocumentPin(doc)), seenActor = untrack(() => JSON.stringify(actor));
  let seenRefresh = untrack(() => refreshRevision);
  const context = $derived(crmState.context);
  const observation = $derived(crmState.observation);
  const canApply = $derived.by(() => { crmState; clock; editorClean; otherBusy; return controller.canApply() && !otherBusy; });
  const observationFresh = $derived.by(() => { crmState; clock; return controller.observationFresh(); });
  const canObserve = $derived.by(() => { crmState; otherBusy; return controller.canObserve() && !otherBusy; });
  const canSearch = $derived.by(() => { crmState; otherBusy; return controller.canDiscover() && !otherBusy; });
  const canEditMapping = $derived(!!context?.supported && crmState.fresh && !crmState.busy && !crmState.needsReadback && !otherBusy);
  const removed = $derived(context ? crmBaseline(context).filter((old) => !crmState.mappings.some((m) => m.variable === old.variable)) : []);
  const labels: Record<CRMKind, string> = { 'crm.deal': 'Deal', 'crm.contact': 'Contact', 'crm.company': 'Company' };
  $effect(() => {
    const pin = crmDocumentPin(doc), actorPin = JSON.stringify(actor);
    untrack(() => {
      if (pin !== seenDocument || actorPin !== seenActor) {
        seenDocument = pin; seenActor = actorPin; controller.syncDocument(doc); controller.interrupt();
        if (mounted && !crmState.needsReadback) void controller.refresh();
      }
    });
  });
  $effect(() => {
    const request = refreshRevision;
    untrack(() => { if (request !== seenRefresh) { seenRefresh = request; controller.interrupt(); if (mounted && !crmState.needsReadback) void controller.refresh(); } });
  });
  $effect(() => { crmState; untrack(() => onStateChange(controller.sendBlocked(), crmState.busy === 'apply' || crmState.busy === 'readback')); });
  function map(variable: string, value: string) {
    if (!value) { controller.map(variable); return; }
    const [kind, path] = value.split(':');
    if (CRM_KINDS.includes(kind as CRMKind) && path) controller.map(variable, { kind: kind as CRMKind, path });
  }
  async function search(event: SubmitEvent) { event.preventDefault(); if (canSearch) await controller.search(searchKind, query); }
  beforeNavigate(({ from, to, willUnload }) => { if (willUnload || from?.url.href !== to?.url.href) controller.interrupt(); });
  onMount(() => {
    mounted = true; void controller.refresh();
    const interval = setInterval(() => { clock++; controller.expire(); }, 1000);
    const hidden = () => { if (globalThis.document.visibilityState === 'hidden') controller.interrupt(); };
    globalThis.document.addEventListener('visibilitychange', hidden);
    return () => { mounted = false; clearInterval(interval); globalThis.document.removeEventListener('visibilitychange', hidden); controller.dispose(); onStateChange(true, false); };
  });
</script>

<section id="document-crm-information" class="card p-6 mb-6 space-y-4 min-w-0" aria-label="CRM information" data-crm-document-panel>
  <div class="flex flex-wrap items-center justify-between gap-3">
    <h2 class="font-display text-lg">CRM information</h2>
    <button type="button" class="btn btn-secondary" disabled={!!crmState.busy || crmState.needsReadback || otherBusy} onclick={() => controller.refresh()}>Refresh CRM information</button>
  </div>
  <p class="text-sm text-text-secondary">Choose records and review the exact values before applying them. Document wording stays in the editor below. CRM identity, job titles and tax details do not establish signing authority or legal sufficiency.</p>
  {#if crmState.error}<p role="alert" class="text-sm text-danger">{crmState.error}</p>{/if}
  {#if crmState.notice}<p role="status" class="text-sm text-text-secondary">{crmState.notice}</p>{/if}
  {#if crmState.busy}<p role="status" class="text-sm">{crmState.busy === 'apply' ? 'Applying reviewed values and preparing the updated document…' : 'Checking CRM information…'}</p>{/if}
  {#if crmState.needsReadback}
    <div class="space-y-3 text-sm border border-warning rounded-md p-4">
      <p>{crmState.readbackReason === 'stale' ? 'The saved document changed. Inspect its current source and mappings before choosing to load it. Local wording is retained.' : 'Another Apply is blocked until you inspect the saved document, its retained source and complete mappings. Local wording is retained.'}</p>
      <button type="button" class="btn btn-secondary" disabled={!!crmState.busy || otherBusy} onclick={() => controller.inspectReadback()}>Inspect saved CRM result</button>
      {#if crmState.readback}<p>Saved document: {crmState.readback.document.name} · {crmState.readback.document.updated_at}. {crmState.readback.context.mapping_review_required ? 'A fresh CRM review is still required.' : 'The saved mapping review matches this document.'}</p>
        <button type="button" class="btn btn-secondary" disabled={!!crmState.busy || !editorClean || otherBusy} onclick={() => controller.adoptReadback()}>Use inspected saved document and mappings</button>{/if}
    </div>
  {/if}
  {#if context}
    {#if context.mapping_review_required}<p role="note" class="text-sm text-warning">The current CRM mappings or content need explicit review before this document can be sent.</p>{/if}
    {#if context.connection}<details class="text-sm"><summary>CRM account and connection</summary>
      <dl class="grid grid-cols-1 sm:grid-cols-[10rem_1fr] gap-2 mt-3">
        <dt>Address</dt><dd class="break-all">{context.connection.origin}</dd>
        <dt>Team ID</dt><dd class="font-mono break-all">{context.connection.crm_team_id}</dd>
        <dt>Integration user ID</dt><dd class="font-mono break-all">{context.connection.crm_user_id}</dd>
        <dt>Connection revision</dt><dd class="font-mono break-all">{context.connection.generation} · {context.connection.status}</dd>
      </dl><p class="text-xs text-text-muted mt-2">Saved account context. Fresh reads check the account again; key scopes and expiry are not verified here.</p>
    </details>{/if}
    {#if !context.supported}<p class="text-sm" role="note">This PDF has no editable declared document source. CRM mapping cannot change its printed text.</p>
    {:else}
      {#if !context.available || context.connection?.status !== 'active'}<p class="text-sm" role="note">CRM reads require an enabled connection. An owner can manage it in <a href="/settings/integrations/brightcrm" class="underline">CRM settings</a>. Manually authored unbound documents retain their normal sending flow. Existing mappings can be explicitly reviewed and removed below.</p>{/if}
      <form onsubmit={search} class="space-y-3">
        <div class="grid grid-cols-1 sm:grid-cols-[8rem_1fr_auto] gap-3">
          <label class="text-sm">Record type<select aria-label="CRM record type" bind:value={searchKind} disabled={!canSearch} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2">{#each CRM_KINDS as kind}<option value={kind}>{labels[kind]}</option>{/each}</select></label>
          <label class="text-sm">Search<input aria-label="Search CRM records" bind:value={query} disabled={!canSearch} maxlength="200" placeholder="Leave empty for recent records" class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
          <button type="submit" class="btn btn-secondary self-end" disabled={!canSearch || !validCRMSearch(query, 0)}>Search records</button>
        </div>
        <p class="text-xs text-text-muted">Search matches complete words. Results help you select a record; they are not the values that will be applied.</p>
      </form>
      {#if crmState.search}
        <div class="space-y-2" aria-label="CRM search results">
          {#if !crmState.search.choices.length}<p class="text-sm">No records were returned. Try other complete words.</p>{/if}
          {#each crmState.search.choices as choice (choice.id)}<div class="flex flex-wrap items-start justify-between gap-3 border border-border-light rounded-md p-3 min-w-0">
            <div class="min-w-0 flex-1"><p class="text-sm break-words">{choice.label || choice.id}</p>{#if choice.secondary}<p class="text-xs break-words text-text-muted">{choice.secondary}</p>{/if}<p class="text-xs font-mono break-all text-text-muted">{choice.id}</p></div>
            <button type="button" class="btn btn-secondary text-xs" disabled={!canSearch} onclick={() => controller.select(choice)}>Use this {labels[choice.kind].toLowerCase()}</button>
          </div>{/each}
          {#if crmState.search.has_more}<button type="button" class="btn btn-secondary" disabled={!canSearch} onclick={() => crmState.search && controller.search(crmState.search.kind, crmState.search.query, crmState.search.next_offset)}>Next results</button>{/if}
        </div>
      {/if}
      {#if Object.keys(crmState.selected).length}<div class="space-y-2 text-sm" aria-label="Selected CRM records">
        {#each CRM_KINDS as kind}{@const selected = crmState.selected[kind]}{#if selected}<p class="break-words"><strong>{labels[kind]}:</strong> {selected.label} <span class="font-mono break-all text-text-muted">({selected.id})</span></p>{/if}{/each}
        <p class="text-xs text-text-muted">Selected records must have matching CRM relationships. One record per type can supply values.</p>
      </div>{/if}
      <div class="space-y-3" aria-label="CRM field mapping">
        {#each context.variables as variable (variable.name)}{@const mapping = crmState.mappings.find((m) => m.variable === variable.name)}
          <label class="block text-sm break-words">{variable.name}{variable.required ? ' (required)' : ''}
            <select aria-label={`CRM source for ${variable.name}`} value={mapping ? `${mapping.source_kind}:${mapping.source_path}` : ''} disabled={!canEditMapping}
              onchange={(event) => map(variable.name, event.currentTarget.value)} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2">
              <option value="">Keep manually supplied value</option>
              {#each CRM_KINDS as kind}{#if crmState.selected[kind]}<optgroup label={labels[kind]}>{#each context.catalog[kind] as field (field.path)}<option value={`${kind}:${field.path}`}>{field.path} · {field.type}{field.derived ? ' (derived)' : ''}</option>{/each}</optgroup>{/if}{/each}
            </select><span class="text-xs text-text-muted">Current document: <span class="whitespace-pre-wrap break-words">{variable.current_value === '' ? '(empty)' : variable.current_value}</span></span>
          </label>
        {/each}
      </div>
      {#if crmState.mappings.length || crmBaseline(context).length}<button type="button" class="btn btn-secondary" disabled={!canEditMapping} onclick={() => controller.unlink()}>Remove all CRM mappings for review</button>{/if}
      {#if removed.length}<div role="note" class="text-sm space-y-1"><p>These CRM mappings will be removed only after review and Apply. Their current document values stay in place:</p>{#each removed as old (old.variable)}<p class="break-all">{old.variable} · {old.source_kind} · {old.source_ref} · {old.source_path}</p>{/each}</div>{/if}
      <button type="button" class="btn btn-secondary" disabled={!canObserve} onclick={() => controller.observe()}>Read values for review</button>
      {#if observation}<section class="space-y-3" aria-label="CRM value review">
        <h3 class="font-medium">Review exact CRM values</h3>
        {#if observation.contract_issues?.length}<div role="alert" class="text-sm text-warning space-y-2"><p>These values do not fit the reviewed contract design. Resolve the issues before applying:</p>
          {#each observation.contract_issues as issue}<p class="break-words">{issue.path}: {issue.message}</p>{/each}</div>{/if}
        {#if observation.observed_at}<p class="text-xs text-text-muted">Observed {observation.observed_at}. Apply reads the records again and refuses changed values.</p>{:else}<p class="text-sm">This review removes CRM mappings and preserves the current document values. No provider verification is claimed.</p>{/if}
        {#each observation.items as item (item.variable)}<div class="border border-border-light rounded-md p-3 space-y-2 text-sm min-w-0">
          <p class="font-medium break-words">{item.variable}</p>
          <p class="text-xs font-mono break-all">{item.source_kind} · {item.source_ref} · {item.source_path}</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3"><div><p class="text-xs text-text-muted">Current document</p><p class="whitespace-pre-wrap break-words">{item.current_value === '' ? '(empty)' : item.current_value}</p></div>
            <div><p class="text-xs text-text-muted">Observed CRM value</p>{#if item.available}<p class="whitespace-pre-wrap break-words">{item.value === '' ? '(empty)' : item.value}</p>{:else}<p class="text-warning">Unavailable: {item.unavailable_reason}. It will not become an empty value or fallback.</p>{/if}</div></div>
          {#if item.crm_observation}<details class="text-xs"><summary>Record provenance</summary><p class="break-all mt-2">Record updated {item.crm_observation.record_updated_at} · observed {item.crm_observation.observed_at}</p><p class="font-mono break-all">Record SHA-256: {item.crm_observation.body_sha256}</p><p class="font-mono break-all">Value SHA-256: {item.crm_observation.value_sha256}</p>{#if item.crm_observation.transformation}<p>Derived using {item.crm_observation.transformation}.</p>{/if}</details>{/if}
        </div>{/each}
        <label class="flex items-start gap-2 text-sm"><input type="checkbox" aria-label="Confirm reviewed CRM values" checked={crmState.confirmation === observation.review_digest}
          disabled={!observation.can_apply || !!crmState.busy || !crmState.fresh || crmState.needsReadback || !observationFresh}
          onchange={(event) => controller.confirm(observation.review_digest, event.currentTarget.checked)} /><span>I reviewed these exact records, mappings, values and removals, and confirm they belong in this document.</span></label>
        {#if !editorClean}<p class="text-sm text-warning" role="note">Save or reconcile the document editor first. Your entered wording and values are retained.</p>{/if}
        <button type="button" class="btn btn-primary" disabled={!canApply} onclick={() => controller.apply()}>{doc.has_html_source && observation.content_changed ? 'Apply CRM values and render PDF' : observation.mappings.length ? 'Apply reviewed CRM values' : 'Apply CRM mapping removal'}</button>
      </section>{/if}
    {/if}
  {/if}
</section>
