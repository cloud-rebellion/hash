<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { getTemplate, type TemplateResponse, type DocumentResponse } from '$lib/api/client';
  import { htmlContractProfile, htmlProfileIssues, htmlProfileSectionValues, htmlSigningPageIssues, htmlTemplateGroups, htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate, type HTMLFormField, type HTMLSectionDefinition } from '$lib/htmlTemplate';
  import { crmTemplateTransport } from '$lib/api/crmTemplatePopulation';
  import { CRMTemplatePopulationController, initialCRMTemplateState, readCreationMarker, storeCreationMarker, type CRMTemplateState, type HTMLCreationMarker } from '$lib/crmTemplatePopulation';
  import CRMTemplatePopulationPanel from './CRMTemplatePopulationPanel.svelte';

  type DraftNavigation = { cancel: () => void; willUnload: boolean; from: { url: URL } | null; to: { url: URL } | null };

  let { template, onCreated, onClose, onBusyChange, onDirtyChange, onPendingChange = () => {}, pendingMarker = null }: {
    template: TemplateResponse;
    onCreated: (document: DocumentResponse) => Promise<void> | void;
    onClose: () => void;
    onBusyChange: (busy: boolean) => void;
    onDirtyChange: (dirty: boolean) => void;
    onPendingChange?: (marker: HTMLCreationMarker | null) => void;
    pendingMarker?: HTMLCreationMarker | null;
  } = $props();
  const sourceID = untrack(() => template.id);
  const sourceOrg = untrack(() => template.org_id);
  let design = $state<TemplateResponse | null>(null);
  let pendingDesign = $state<TemplateResponse | null>(null);
  let fields = $state<HTMLFormField[]>([]);
  let values = $state<Record<string, string>>({});
  let sections = $state<Record<string, string>>({});
  let sectionDefinitions = $state<HTMLSectionDefinition[]>([]);
  let name = $state(untrack(() => `${template.name} (${new Date().toLocaleDateString()})`));
  const initialName = untrack(() => name);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let needsRefresh = $state(false);
  let createdDocument = $state<DocumentResponse | null>(null);
  let navigating = $state(false);
  let creationUncertain = $state(false);
  let populationState = $state.raw<CRMTemplateState>(initialCRMTemplateState());
  let markerError = $state(false), clock = $state(0);
  let disposed = false;
  let readRevision = 0;
  const current = () => !disposed && template.id === sourceID && template.org_id === sourceOrg;
  const approved = $derived(design !== null && isApprovedHTMLTemplate(design));
  const profile = $derived(design?.html_master_json ? htmlContractProfile(design.html_master_json) : null);
  const groups = $derived(design ? htmlTemplateGroups(design) : []);
  const controller = new CRMTemplatePopulationController(null, crmTemplateTransport, candidate,
    (next) => { populationState = next; busy = next.busy === 'create' || next.busy === 'readback' || next.busy === 'stop'; createdDocument = next.created;
      creationUncertain = !!next.pending; onBusyChange(busy || navigating); },
    (marker) => { storeCreationMarker(window.sessionStorage, marker); onPendingChange(marker); },
    async (doc) => { if (!current()) throw new Error('The current form changed. Inspect this request before opening it.');
      navigating = true; createdDocument = doc; onBusyChange(true);
      try { await onCreated(doc); } finally { if (current()) { navigating = false; onBusyChange(false); } } }, untrack(() => pendingMarker));
  const effectiveValues = $derived.by(() => { populationState; clock; values; name; sections; try { return controller.effectiveValues(); } catch { return values; } });
  const profileIssues = $derived(profile ? [...htmlProfileIssues(profile, effectiveValues, sections), ...(design?.html_master_json?.schema_version === 3 ? htmlSigningPageIssues(profile, effectiveValues) : [])] : []);
  const canCreate = $derived.by(() => { populationState; clock; values; sections; name; return !markerError && controller.canCreate(); });
  const unusedValues = $derived(Object.entries(values).filter(([name]) => !fields.some((field) => field.name === name)));
  const unusedSections = $derived(Object.entries(sections).filter(([name]) => !sectionDefinitions.some((section) => section.name === name)));
  const dirty = $derived(name !== initialName || unusedValues.length > 0 || unusedSections.length > 0 || fields.some((field) => values[field.name] !== field.defaultValue)
    || sectionDefinitions.some((section) => sections[section.name] !== section.default_text));
  $effect(() => { onDirtyChange(dirty); });

  function candidate() {
    if (!design) throw new Error('Load an approved design first.');
    const submittedSections = htmlProfileSectionValues(design.html_master_json!, sections, true);
    return { name: name.trim(), values: htmlValuesForSubmission(fields, values, true), ...(submittedSections === undefined ? {} : { sections: submittedSections }) };
  }
  function inputChanged() { controller.inputChanged(); error = null; }
  function mappedRequiredFilled(field: HTMLFormField) {
    clock;
    return populationState.mappings.some(m => m.variable === field.name) && controller.observationFresh()
      && populationState.observation?.items.some(i => i.variable === field.name && i.available && !!i.value?.trim());
  }

  function adoptDesign(next: TemplateResponse) {
    const nextFields = htmlTemplateFields(next);
    const nextValues: Record<string, string> = { ...values };
    const nextSections: Record<string, string> = { ...sections }, nextDefinitions = next.html_master_json!.sections ?? [];
    for (const field of nextFields) {
      const previous = fields.find((candidate) => candidate.name === field.name);
      const untouched = previous && values[field.name] === previous.defaultValue;
      nextValues[field.name] = Object.hasOwn(values, field.name) && !untouched ? values[field.name] : field.defaultValue;
    }
    for (const section of nextDefinitions) {
      const previous = sectionDefinitions.find((candidate) => candidate.name === section.name), untouched = previous && sections[section.name] === previous.default_text;
      nextSections[section.name] = Object.hasOwn(sections, section.name) && !untouched ? sections[section.name] : section.default_text;
    }
    fields = nextFields;
    values = nextValues;
    sections = nextSections; sectionDefinitions = nextDefinitions;
    design = next;
    pendingDesign = null;
    needsRefresh = false;
    controller.setTemplate(next);
    if (isApprovedHTMLTemplate(next)) void controller.load();
  }
  async function refreshDesign() {
    if (!current() || busy || navigating || createdDocument || creationUncertain || markerError || (loading && design !== null)) return;
    controller.invalidate();
    const revision = ++readRevision;
    loading = true;
    error = null;
    try {
      const next = await getTemplate(sourceID);
      if (!current() || revision !== readRevision) return;
      if (next.id !== sourceID || next.org_id !== sourceOrg) throw new Error('The server returned a different design.');
      htmlTemplateFields(next);
      if (design && (next.version !== design.version || next.content_sha256 !== design.content_sha256)) {
        pendingDesign = next;
        needsRefresh = true;
      } else adoptDesign(next);
    } catch (e) {
      if (current() && revision === readRevision) error = (e as Error).message;
    } finally {
      if (current() && revision === readRevision) loading = false;
    }
  }
  function useUpdatedDesign() {
    if (!current() || busy || navigating || createdDocument || creationUncertain || markerError || !pendingDesign) return;
    adoptDesign(pendingDesign);
    error = null;
  }
  async function create(event: Event) {
    event.preventDefault();
    if (!current() || !design || !approved || loading || busy || navigating || createdDocument || creationUncertain || markerError || needsRefresh || pendingDesign || !controller.canCreate()) return;
    try {
      if (!name.trim()) throw new Error('Enter a document name.');
      htmlValuesForSubmission(fields, controller.effectiveValues());
      if (profileIssues.length) throw new Error(profileIssues[0]);
      htmlProfileSectionValues(design.html_master_json!, sections);
    } catch (e) { error = (e as Error).message; return; }
    error = null;
    await controller.create();
  }
  async function openCreatedDocument() {
    if (current() && !navigating) await controller.openCreated();
  }
  function close() {
    if (!current() || busy || navigating || creationUncertain || markerError || (dirty && !window.confirm('Discard these entered values and close this design?'))) return;
    onClose();
  }
  function protectNavigation(navigation: DraftNavigation) {
    const createdDestination = navigating && createdDocument && navigation.to?.url.pathname === `/documents/${createdDocument.id}`;
    if (!navigation.willUnload && navigation.to?.url.pathname !== navigation.from?.url.pathname && !createdDestination
        && (dirty || busy || navigating || creationUncertain || markerError) && !window.confirm(busy
          ? 'PDF creation is in progress and may still complete. Leave and discard these entered values?'
          : creationUncertain ? 'Leave this form? Its pending request remains blocked and can be inspected after returning. Entered text is not retained after navigation.' : 'Leave this design and discard its entered values?')) { navigation.cancel(); return; }
    if (!createdDestination && (navigation.willUnload || navigation.to?.url.href !== navigation.from?.url.href)) controller.invalidate();
  }
  beforeNavigate(protectNavigation);
  function protectDraft(event: BeforeUnloadEvent) {
    if (!(dirty || busy || navigating || creationUncertain || markerError)) return;
    event.preventDefault(); event.returnValue = '';
  }
  onMount(() => {
    try { const marker = readCreationMarker(window.sessionStorage);
      if (marker) { creationUncertain = true; loading = false; onPendingChange(marker); controller.restorePending(marker); }
      else void refreshDesign();
    } catch { loading = false; markerError = true; error = 'The pending request marker cannot be verified. Another creation is blocked; do not remove the marker to bypass recovery.'; }
    const interval = setInterval(() => { clock++; controller.expire(); }, 1000);
    const hidden = () => { if (document.visibilityState === 'hidden') controller.invalidate(); };
    document.addEventListener('visibilitychange', hidden);
    window.addEventListener('beforeunload', protectDraft);
    return () => { clearInterval(interval); document.removeEventListener('visibilitychange', hidden); window.removeEventListener('beforeunload', protectDraft); controller.dispose(); };
  });
  onDestroy(() => { disposed = true; readRevision++; });
</script>

<section class="card p-6 mb-6 space-y-4" aria-label="Populate approved design">
  <div>
    <h2 class="font-display text-lg">New document from {template.name}</h2>
    <p class="text-sm text-text-secondary mt-1">Fill the declared information and review any wording changes. Hash keeps the design, then creates a fresh PDF for your review.</p>
  </div>
  {#if loading}<p class="text-sm" role="status">Loading current design…</p>{/if}
  {#if error}<p role="alert" class="text-sm text-danger">{error}</p>{/if}
  {#if design}
    <p class="text-sm text-text-secondary">Version {design.version} · {approved ? 'Approved design' : 'Awaiting owner approval'}</p>
    {#if profile}<div class="border border-border-light rounded-md p-4 space-y-2 text-sm" aria-label="Declared contract checks">
      <p class="font-medium">{profile.kind === 'proposal' ? 'Proposal' : 'Ordinary B2B services'} · reviewed profile {profile.id.replaceAll('_', ' ')} version {profile.version}</p>
      <p>Both representatives will sign. Hash creates the provider and customer recipients from the names and email addresses printed below. These declarations do not independently verify identity or authority, or establish legal sufficiency.</p>
      {#if populationState.mappings.length}<p>This party summary uses the proposed observed CRM values when available. Your manual entries remain in the form below.</p>{/if}
      {#if design.html_master_json?.schema_version === 3}<p>The approved design appends a signing page with saved branding and fixed signature locations for both representatives. Party details must fit its bounded layout and bundled Latin font. Review the complete generated PDF, including that final page, before sending.</p>{/if}
      {#each profile.parties as party (party.slot)}<p class="break-words"><strong>{party.slot === 'provider' ? 'Our company' : 'Customer'}:</strong> {effectiveValues[party.company_name]?.trim() || 'Company not entered'} · {effectiveValues[party.representative_name]?.trim() || 'Representative not entered'} · {effectiveValues[party.representative_email]?.trim() || 'Email not entered'}</p>{/each}
      {#if profileIssues.length}<p class="text-warning" role="status">Complete the declared party and commercial information before creating the PDF.</p><ul class="list-disc pl-5 space-y-1">{#each profileIssues as issue, index (index)}<li>{issue}</li>{/each}</ul>{/if}
    </div>{/if}
    {#if !approved}<p class="text-sm" role="note">This revision needs owner approval before it can create documents.</p>{/if}
    {#if pendingDesign}
      <div class="border-l-2 border-warning pl-4 space-y-2">
        <p class="text-sm">The design changed to version {pendingDesign.version}. Your entered values are retained. Review the new revision before using it.</p>
        <button type="button" class="btn btn-secondary" onclick={useUpdatedDesign}>Use updated design</button>
      </div>
    {/if}
    <CRMTemplatePopulationPanel {controller} state={populationState} {values} {clock} />
    <form onsubmit={create} class="space-y-4">
      <fieldset disabled={loading || populationState.busy === 'load' || busy || navigating || creationUncertain || markerError || !!createdDocument} class="space-y-4">
        <label class="block text-sm">Document name
          <input bind:value={name} oninput={inputChanged} required maxlength="200" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" />
        </label>
        {#each groups as group (group.id)}
          <section class="space-y-3" aria-label={group.label}><h3 class="font-medium">{group.label}</h3>
            {#each group.fields as field (field.name)}<div class="space-y-1">
              <label class="block text-sm capitalize" for={`html-value-${field.name}`}>{field.label}{field.required ? ' (required)' : ''}</label>
              <textarea id={`html-value-${field.name}`} bind:value={values[field.name]} oninput={inputChanged} required={field.required && !mappedRequiredFilled(field)} maxlength={field.max_chars * 2} rows={field.max_chars > 200 ? 3 : 1}
                class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"></textarea>
            </div>{/each}
            {#each group.sections as section (section.name)}<div class="text-sm space-y-2">
              <label class="block capitalize" for={`html-section-${section.name}`}>{section.label} wording (required)</label>
              <textarea id={`html-section-${section.name}`} bind:value={sections[section.name]} oninput={inputChanged} required maxlength={section.max_chars * 2} rows="5"
                class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"></textarea>
              <details><summary class="cursor-pointer text-text-secondary">Approved design wording</summary><p class="whitespace-pre-wrap break-words mt-1">{section.default_text || 'No saved wording; enter the reviewed document terms.'}</p></details>
              {#if sections[section.name] !== section.default_text}<p class="text-xs text-warning" role="note">This wording differs from the approved default. Review the exact PDF before sending.</p>{/if}
            </div>{/each}
          </section>
        {/each}
      </fieldset>
      {#if unusedValues.length > 0}
        <details class="text-sm">
          <summary class="cursor-pointer text-text-secondary">Retained values no longer declared in this revision</summary>
          <p class="mt-2">These values are kept here for copying and will not be printed in the new document.</p>
          {#each unusedValues as [name, value] (name)}<p class="mt-2 whitespace-pre-wrap"><strong>{name.replaceAll('_', ' ')}</strong>: {value}</p>{/each}
        </details>
      {/if}
      {#if unusedSections.length > 0}<details class="text-sm"><summary class="cursor-pointer text-text-secondary">Retained wording no longer declared in this revision</summary><p class="mt-2">This text is kept for copying and will not be printed.</p>{#each unusedSections as [name, text] (name)}<p class="mt-2 whitespace-pre-wrap"><strong>{name.replaceAll('_', ' ')}</strong>: {text}</p>{/each}</details>{/if}
      {#if design.html_master_json?.sections?.length}
        <details class="text-sm">
          <summary class="cursor-pointer text-text-secondary">Approved wording retained in this document</summary>
          {#each design.html_master_json.sections as section (section.name)}
            <div class="mt-3"><p class="font-medium capitalize">{section.name.replaceAll('_', ' ')}</p><p class="whitespace-pre-wrap mt-1">{section.default_text}</p></div>
          {/each}
        </details>
      {/if}
      <div class="flex flex-wrap gap-2">
        {#if !createdDocument}
          <button type="submit" class="btn btn-primary" disabled={loading || busy || navigating || creationUncertain || !canCreate || !approved || needsRefresh || !!pendingDesign || profileIssues.length > 0}>{busy ? 'Creating PDF…' : 'Create PDF for review'}</button>
          <button type="button" class="btn btn-secondary" disabled={loading || busy || navigating || creationUncertain || markerError} onclick={refreshDesign}>Refresh design</button>
        {/if}
        <button type="button" class="btn btn-secondary" disabled={busy || navigating || creationUncertain || markerError} onclick={close}>Cancel</button>
      </div>
      {#if createdDocument}<p class="text-sm" role="status">The draft has been created. Open it to review the exact PDF.</p>{/if}
      {#if needsRefresh && !pendingDesign}<p class="text-sm" role="note">Refresh this design before trying again. Your values remain in this form.</p>{/if}
    </form>
  {:else if !loading}
    {#if creationUncertain}<CRMTemplatePopulationPanel {controller} state={populationState} {values} {clock} />{:else}<div class="flex gap-2"><button type="button" class="btn btn-secondary" disabled={markerError} onclick={refreshDesign}>Retry design load</button><button type="button" class="btn btn-secondary" disabled={markerError} onclick={close}>Cancel</button></div>{/if}
  {/if}
</section>
