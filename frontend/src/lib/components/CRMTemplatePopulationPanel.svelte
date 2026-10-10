<script lang="ts">
  import { CRM_KINDS, validCRMSearch, type CRMKind, type CRMTemplateState, type CRMTemplatePopulationController } from '$lib/crmTemplatePopulation';
  let { controller, state: populationState, values = {}, clock = 0 }: { controller: CRMTemplatePopulationController; state: CRMTemplateState; values?: Record<string, string>; clock?: number } = $props();
  let searchKind = $state<CRMKind>('crm.deal'), query = $state(''), stopConfirmed = $state(false);
  const context = $derived(populationState.context), observation = $derived(populationState.observation);
  const canDiscover = $derived.by(() => { populationState; return controller.canDiscover(); });
  const canObserve = $derived.by(() => { populationState; return controller.canObserve(); });
  const canStop = $derived.by(() => { populationState; return controller.canStop(); });
  const fresh = $derived.by(() => { populationState; clock; return controller.observationFresh(); });
  const labels: Record<CRMKind, string> = { 'crm.deal': 'Deal', 'crm.contact': 'Contact', 'crm.company': 'Company' };
  function map(variable: string, value: string) {
    if (!value) { controller.map(variable); return; }
    const [kind, path] = value.split(':'); if (CRM_KINDS.includes(kind as CRMKind) && path) controller.map(variable, { kind: kind as CRMKind, path });
  }
  function stop() { const confirmed = stopConfirmed; stopConfirmed = false; void controller.stop(confirmed); }
  $effect(() => { populationState.pending?.request_id; stopConfirmed = false; });
</script>

<section class="space-y-4 min-w-0" aria-label="Initial template CRM information" data-template-crm-panel>
  {#if populationState.error}<p role="alert" class="text-sm text-danger">{populationState.error}</p>{/if}
  {#if populationState.notice}<p role="status" class="text-sm text-text-secondary">{populationState.notice}</p>{/if}
  {#if populationState.busy}<p role="status" class="text-sm">{populationState.busy === 'create' ? 'Creating the reviewed draft and its PDF…' : populationState.busy === 'stop' ? 'Stopping this creation request…' : 'Checking template and CRM information…'}</p>{/if}
  {#if populationState.pending}
    <div class="border border-warning rounded-md p-4 space-y-3 text-sm" aria-label="Pending document creation" data-pending-html-creation>
      <h3 class="font-medium">Inspect pending document creation</h3>
      <p>This request remains associated with the original account and organisation. Another creation is blocked until its committed result is opened or acknowledged, or a verified stopped result is explicitly acknowledged. A missing result does not establish that creation failed.</p>
      <p class="font-mono break-all">Request {populationState.pending.request_id}</p>
      <p class="text-xs text-text-muted">Only request identifiers are retained across reloads. Entered document text and CRM records are not saved in browser storage.</p>
      <button type="button" class="btn btn-secondary" disabled={!!populationState.busy} onclick={() => controller.inspect()}>Inspect creation request</button>
      {#if controller.canRetry()}<button type="button" class="btn btn-secondary" disabled={!!populationState.busy} onclick={() => controller.retry()}>Retry exact same creation request</button><p class="text-xs">This explicitly retries the same request and captured information. It does not create a new request.</p>{/if}
      {#if populationState.created && !populationState.readback}<p>The verified draft has been created.</p><button type="button" class="btn btn-primary" disabled={!!populationState.busy} onclick={() => controller.openCreated()}>Open created draft</button>{/if}
      {#if populationState.readback?.state === 'closed'}
        <p>This request was permanently stopped at {populationState.readback.closed_at}. Its identifier can never create a document.</p>
        <button type="button" class="btn btn-primary" disabled={!!populationState.busy} onclick={() => controller.acknowledgeClosed()}>Acknowledge stopped request</button>
      {:else if populationState.readback?.state === 'committed'}
        <p>Original creation: {populationState.readback.creation.created_at} · {populationState.readback.creation.page_count} pages.</p>
        {#if populationState.readback.document}<p class="break-words">Current saved document: {populationState.readback.document.name} · {populationState.readback.document.status} · updated {populationState.readback.document.updated_at}.</p>
          <p>Its current content, signing state and review may have changed since creation. Opening it leaves this form.</p>
          <button type="button" class="btn btn-primary" disabled={!!populationState.busy} onclick={() => controller.adoptReadback()}>Open inspected document</button>
        {:else}<p>The committed document has been deleted. No replacement has been created.</p><button type="button" class="btn btn-secondary" disabled={!!populationState.busy} onclick={() => controller.acknowledgeDeleted()}>Acknowledge deleted committed document</button>{/if}
      {/if}
      {#if !populationState.readback && !populationState.created}<div class="border-t border-border-light pt-3 space-y-3">
        <p>Stopping permanently retires this request if it has not committed. If it already created a document, Hash returns that saved result for inspection. Your manual entries remain in this form.</p>
        <label class="flex items-start gap-2"><input type="checkbox" aria-label="Confirm stopping this creation request" bind:checked={stopConfirmed} disabled={!canStop} /><span>I want to stop this exact creation request and inspect its durable outcome.</span></label>
        <button type="button" class="btn btn-secondary" disabled={!canStop || !stopConfirmed} onclick={stop}>Stop this request</button>
      </div>{/if}
    </div>
  {:else if populationState.requires_refresh}<p role="note" class="text-sm">The stopped request is acknowledged. Your manual entries remain. Refresh the current design and review fresh CRM values before creating a new document.</p>
  {:else if context}
    <div class="flex flex-wrap items-center justify-between gap-3"><h3 class="font-medium">Fill declared information from CRM</h3><button type="button" class="btn btn-secondary" disabled={!!populationState.busy} onclick={() => controller.load()}>Refresh template CRM information</button></div>
    <p class="text-sm text-text-secondary">Choose records, map declared fields and review exact values before creating. Your manual entries and wording remain in the form. CRM job titles, company IDs and tax details do not establish signing authority or legal sufficiency.</p>
    {#if context.connection}<details class="text-sm"><summary>CRM account and connection</summary><dl class="grid grid-cols-1 sm:grid-cols-[10rem_1fr] gap-2 mt-3">
      <dt>Address</dt><dd class="break-all">{context.connection.origin}</dd><dt>Team ID</dt><dd class="font-mono break-all">{context.connection.crm_team_id}</dd><dt>Integration user ID</dt><dd class="font-mono break-all">{context.connection.crm_user_id}</dd><dt>Connection revision</dt><dd class="font-mono break-all">{context.connection.generation} · {context.connection.status}</dd>
    </dl><p class="text-xs text-text-muted mt-2">Fresh reads check this account. Key scopes and expiry are not verified here.</p></details>{/if}
    {#if !context.available || context.connection?.status !== 'active'}<p class="text-sm" role="note">CRM reads require an enabled connection. You can create a manually populated document without CRM mappings. An owner can manage the connection in <a href="/settings/integrations/brightcrm" class="underline">CRM settings</a>.</p>{/if}
    <form onsubmit={(event) => { event.preventDefault(); if (canDiscover) void controller.search(searchKind, query); }} class="space-y-3">
      <div class="grid grid-cols-1 sm:grid-cols-[8rem_1fr_auto] gap-3">
        <label class="text-sm">Record type<select aria-label="Initial CRM record type" bind:value={searchKind} disabled={!canDiscover} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2">{#each CRM_KINDS as kind}<option value={kind}>{labels[kind]}</option>{/each}</select></label>
        <label class="text-sm">Search<input aria-label="Search initial CRM records" bind:value={query} disabled={!canDiscover} maxlength="200" placeholder="Leave empty for recent records" class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2" /></label>
        <button type="submit" class="btn btn-secondary self-end" disabled={!canDiscover || !validCRMSearch(query, 0)}>Search initial records</button>
      </div><p class="text-xs text-text-muted">Search matches complete words. Result labels help choose a record; only the observed scalar values below will be used.</p>
    </form>
    {#if populationState.search}<div class="space-y-2" aria-label="Initial CRM search results">
      {#if !populationState.search.choices.length}<p class="text-sm">No records were returned.</p>{/if}
      {#each populationState.search.choices as choice (choice.id)}<div class="flex flex-wrap items-start justify-between gap-3 border border-border-light rounded-md p-3 min-w-0"><div class="min-w-0 flex-1"><p class="text-sm break-words">{choice.label || choice.id}</p><p class="text-xs break-words text-text-muted">{choice.secondary}</p><p class="text-xs font-mono break-all text-text-muted">{choice.id}</p></div><button type="button" class="btn btn-secondary text-xs" disabled={!canDiscover} onclick={() => controller.select(choice)}>Use this {labels[choice.kind].toLowerCase()}</button></div>{/each}
      {#if populationState.search.has_more}<button type="button" class="btn btn-secondary" disabled={!canDiscover} onclick={() => populationState.search && controller.search(populationState.search.kind, populationState.search.query, populationState.search.next_offset)}>Next initial results</button>{/if}
    </div>{/if}
    {#if Object.keys(populationState.selected).length}<div aria-label="Selected initial CRM records" class="space-y-2 text-sm">{#each CRM_KINDS as kind}{@const selected = populationState.selected[kind]}{#if selected}<p class="break-words"><strong>{labels[kind]}:</strong> {selected.label} <span class="font-mono break-all">({selected.id})</span></p>{/if}{/each}<p class="text-xs text-text-muted">Selected records must have matching CRM relationships. One record per type can supply values.</p></div>{/if}
    <div aria-label="Initial CRM field mapping" class="space-y-3">{#each context.variables as variable (variable.name)}{@const mapping = populationState.mappings.find(m => m.variable === variable.name)}<label class="block text-sm break-words">{variable.name}{variable.required ? ' (required)' : ''}
      <select aria-label={`Initial CRM source for ${variable.name}`} value={mapping ? `${mapping.source_kind}:${mapping.source_path}` : ''} disabled={!canObserve} onchange={(event) => map(variable.name, event.currentTarget.value)} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2"><option value="">Keep manually entered value</option>{#each CRM_KINDS as kind}{#if populationState.selected[kind]}<optgroup label={labels[kind]}>{#each context.catalog[kind] as field (field.path)}<option value={`${kind}:${field.path}`}>{field.path} · {field.type}{field.derived ? ' (derived)' : ''}</option>{/each}</optgroup>{/if}{/each}</select>
      <span class="text-xs text-text-muted">Manual form: <span class="whitespace-pre-wrap break-words">{!Object.hasOwn(values, variable.name) ? '(not entered)' : values[variable.name] === '' ? '(empty)' : values[variable.name]}</span></span>
    </label>{/each}</div>
    {#if populationState.mappings.length}<button type="button" class="btn btn-secondary" disabled={!!populationState.busy} onclick={() => controller.unlink()}>Remove initial CRM mappings</button><p class="text-xs text-text-muted">Removing tentative mappings keeps the manual entries.</p>{/if}
    <button type="button" class="btn btn-secondary" disabled={!canObserve} onclick={() => controller.observe()}>Read initial values for review</button>
    {#if observation}<section class="space-y-3" aria-label="Initial CRM value review"><h3 class="font-medium">Review values for the new document</h3>
      <p class="text-xs text-text-muted">Observed {observation.observed_at}. Creating reads the selected records again and refuses changed values. This confirmation also covers the current document name, manual entries and wording.</p>
      {#if observation.contract_issues?.length}<div role="alert" class="text-sm text-warning">{#each observation.contract_issues as issue}<p class="break-words">{issue.path}: {issue.message}</p>{/each}</div>{/if}
      {#each observation.items as item (item.variable)}<div class="border border-border-light rounded-md p-3 space-y-2 text-sm min-w-0"><p class="font-medium break-words">{item.variable}</p><p class="font-mono text-xs break-all">{item.source_kind} · {item.source_ref} · {item.source_path}</p><div class="grid grid-cols-1 sm:grid-cols-2 gap-3"><div><p class="text-xs text-text-muted">Current manual value</p><p class="whitespace-pre-wrap break-words">{!item.current_present ? '(not entered)' : item.current_value === '' ? '(empty)' : item.current_value}</p></div><div><p class="text-xs text-text-muted">Observed CRM value</p>{#if item.available}<p class="whitespace-pre-wrap break-words">{item.value === '' ? '(empty)' : item.value}</p>{:else}<p class="text-warning">Unavailable: {item.unavailable_reason}. This will not become an empty value or fallback.</p>{/if}</div></div>
        {#if item.crm_observation}<details class="text-xs"><summary>Initial record provenance</summary><p class="break-all mt-2">Record updated {item.crm_observation.record_updated_at} · observed {item.crm_observation.observed_at}</p><p class="font-mono break-all">Record SHA-256: {item.crm_observation.body_sha256}</p><p class="font-mono break-all">Value SHA-256: {item.crm_observation.value_sha256}</p>{#if item.crm_observation.transformation}<p>Derived using {item.crm_observation.transformation}.</p>{/if}</details>{/if}
      </div>{/each}
      <label class="flex items-start gap-2 text-sm"><input type="checkbox" aria-label="Confirm initial CRM values" checked={populationState.confirmation === observation.review_digest} disabled={!observation.can_create || !!populationState.busy || !fresh} onchange={(event) => controller.confirm(observation.review_digest, event.currentTarget.checked)} /><span>I reviewed the selected account, records, mappings and exact values, and the current manual entries and wording for this new document.</span></label>
      {#if !fresh}<p role="note" class="text-sm text-warning">This review expired. Read the values again before creating.</p>{/if}
    </section>{/if}
  {:else if !populationState.busy}<p class="text-sm" role="note">CRM information is unavailable. Unmapped manual creation remains available with the original authoring account.</p>
    {#if populationState.mappings.length}<button type="button" class="btn btn-secondary" onclick={() => controller.unlink()}>Remove initial CRM mappings</button>{/if}
  {/if}
</section>
