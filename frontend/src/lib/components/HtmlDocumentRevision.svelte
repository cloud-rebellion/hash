<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { APIError, getMe, getDocument, getHTMLDocumentSource, reviseHTMLDocument, type DocumentResponse, type HTMLDocumentSource } from '$lib/api/client';
  import { advanceCleanHTMLObservation, currentHTMLSource, htmlRevisionGroups, htmlRevisionInput, htmlUUID, revisionDraft, verifiedHTMLRevision } from '$lib/htmlRevision';

  type Identity = Awaited<ReturnType<typeof getMe>>;
  type Navigation = { cancel: () => void; willUnload: boolean; from: { url: URL } | null; to: { url: URL } | null };
  let { document, onRevised, onStateChange, onSourceChange, onEditorStateChange, externalBusy = false, mutationBlocked = false, reconciliationBusy = false }: { document: DocumentResponse; onRevised: (updated: DocumentResponse) => boolean | void;
    onStateChange?: (blocked: boolean) => void; onSourceChange?: (source: HTMLDocumentSource | null) => void;
    onEditorStateChange?: (clean: boolean) => void; externalBusy?: boolean; mutationBlocked?: boolean; reconciliationBusy?: boolean } = $props();
  const sourceID = untrack(() => document.id), sourceOrg = untrack(() => document.org_id);
  let retained = $state<HTMLDocumentSource | null>(null);
  let values = $state<Record<string, string>>({}), sections = $state<Record<string, string>>({}), summary = $state('');
  let baseline = $state('');
  let me = $state<Identity | null>(null);
  let loading = $state(true), busy = $state(false), error = $state<string | null>(null);
  let needsRefresh = $state(false), uncertain = $state(false);
  let acknowledgedDocument = $state<DocumentResponse | null>(null);
  let latestDocument = $state<DocumentResponse | null>(null), latestSource = $state<HTMLDocumentSource | null>(null);
  let disposed = false, operation = 0;
  const current = () => !disposed && document.id === sourceID && document.org_id === sourceOrg;
  const fingerprint = () => JSON.stringify({ values, sections, summary });
  const dirty = $derived(retained !== null && fingerprint() !== baseline);
  const authority = $derived(!!me && me.org_id === sourceOrg && (me.role === 'owner' || (me.role === 'sender' && me.user_id === document.sender_id)));
  const observationCurrent = $derived(!!retained && current() && document.has_html_source === true && document.source_kind === 'pdf'
    && retained.document_id === document.id && retained.org_id === document.org_id && retained.template_id === document.template_id
    && retained.updated_at === document.updated_at && retained.html_source_commitment === document.html_source_commitment
    && retained.pdf_sha256 === document.pdf_sha256 && retained.materialization_revision === document.html_materialization_revision);
  const writeBusy = $derived(externalBusy || mutationBlocked || reconciliationBusy);
  const canSave = $derived(current() && document.status === 'draft' && authority && retained?.can_edit && observationCurrent && !needsRefresh && !uncertain && !busy && !loading && !writeBusy);
  const valueGroups = $derived(retained ? htmlRevisionGroups(retained) : []);
  $effect(() => { reconcileObservation(); });
  $effect(() => { reportRevisionState(); });

  function reconcileObservation() {
    if (!retained || observationCurrent) return;
    const next = current() ? advanceCleanHTMLObservation(retained, document, dirty || busy || loading || uncertain || needsRefresh || !me) : null;
    if (next) retained = next;
    else needsRefresh = true;
  }
  function reportRevisionState() {
    const clean = !dirty && !busy && !loading && !needsRefresh && !uncertain && !!retained && observationCurrent && !!me;
    const blocked = !clean || externalBusy;
    const verified = !blocked ? retained : null;
    untrack(() => { onStateChange?.(blocked); onSourceChange?.(verified); onEditorStateChange?.(clean); });
  }

  function identity(next: Identity): Identity {
    if (!next || !htmlUUID(next.user_id) || !htmlUUID(next.org_id) || !['owner', 'sender', 'viewer'].includes(next.role) || next.org_id !== sourceOrg) {
      me = null;
      throw new Error('The current session or organisation could not be verified. Your entered values and wording are retained.');
    }
    return next;
  }
  function recordError(e: unknown) {
    error = (e as Error).message;
    if (e instanceof APIError && (e.status === 401 || e.status === 403)) me = null;
    if (e instanceof APIError && (e.status === 409 || e.status === 412 || e.status === 428)) needsRefresh = true;
  }
  function adopt(source: HTMLDocumentSource) {
    const next = revisionDraft(source);
    retained = source; values = next.values; sections = next.sections; summary = '';
    baseline = fingerprint(); needsRefresh = false; uncertain = false; error = null;
    latestDocument = null; latestSource = null; acknowledgedDocument = null;
  }
  async function loadInitial() {
    if (!current() || busy || externalBusy || reconciliationBusy) return;
    if (retained || uncertain || dirty) { await inspectLatest(); return; }
    const selected = ++operation, observed = document;
    loading = true; error = null;
    try {
      const session = await getMe();
      if (!current() || selected !== operation) return;
      me = identity(session);
      const source = await getHTMLDocumentSource(sourceID);
      if (!current() || selected !== operation || document.updated_at !== observed.updated_at || document.html_source_commitment !== observed.html_source_commitment) return;
      adopt(currentHTMLSource(source, observed));
    } catch (e) { if (current() && selected === operation) recordError(e); }
    finally { if (current() && selected === operation) loading = false; }
  }
  async function save(event: Event) {
    event.preventDefault();
    if (!current() || !canSave || busy || writeBusy || uncertain || needsRefresh || !retained || !dirty) return;
    let input;
    try { input = htmlRevisionInput(retained, values, sections, summary); } catch (e) { recordError(e); return; }
    const source = retained, before = document, submitted = fingerprint(), selected = ++operation;
    let writeAccepted = false;
    busy = true; error = null;
    try {
      const result = await reviseHTMLDocument(sourceID, input);
      if (!current() || selected !== operation || fingerprint() !== submitted) return;
      const saved = verifiedHTMLRevision(result, before, source);
      writeAccepted = true; acknowledgedDocument = saved;
      const fresh = await getHTMLDocumentSource(sourceID);
      if (!current() || selected !== operation || fingerprint() !== submitted) return;
      currentHTMLSource(fresh, saved);
      if (onRevised(saved) === false) throw new Error('The displayed document changed before the saved revision could be adopted.');
      adopt(fresh);
    } catch (e) {
      if (current() && selected === operation) {
        recordError(e);
        if (writeAccepted || !(e instanceof APIError) || e.status >= 500) {
          uncertain = true;
          error = writeAccepted
            ? 'The PDF revision was saved, but its source could not be read back. Inspect the saved document before another write. Your entered values and wording are retained.'
            : 'We could not confirm the revision. Inspect the current saved document before another write. Your entered values and wording are retained.';
        }
      }
    } finally { if (current() && selected === operation) busy = false; }
  }
  async function inspectLatest() {
    if (!current() || busy || externalBusy || reconciliationBusy) return;
    const selected = ++operation;
    busy = true; error = null;
    try {
      const session = await getMe();
      if (!current() || selected !== operation) return;
      me = identity(session);
      const freshDocument = await getDocument(sourceID);
      if (!current() || selected !== operation) return;
      if (freshDocument.id !== sourceID || freshDocument.org_id !== sourceOrg || !freshDocument.has_html_source) throw new Error('The saved document identity could not be verified.');
      const source = await getHTMLDocumentSource(sourceID);
      if (!current() || selected !== operation) return;
      latestSource = currentHTMLSource(source, freshDocument); latestDocument = freshDocument;
    } catch (e) { if (current() && selected === operation) recordError(e); }
    finally { if (current() && selected === operation) busy = false; }
  }
  function adoptLatest() {
    if (!current() || busy || externalBusy || reconciliationBusy || !latestSource || !latestDocument) return;
    if ((dirty || uncertain) && !window.confirm('Discard local document values, wording and summary, and load this saved revision? An uncertain request may still complete.')) return;
    const source = latestSource, doc = latestDocument;
    if (onRevised(doc) === false) { error = 'The displayed document changed. Inspect the saved revision again; your local inputs are retained.'; return; }
    adopt(source);
  }
  function protectNavigation(navigation: Navigation) {
    if (!navigation.willUnload && navigation.to?.url.pathname !== navigation.from?.url.pathname && (dirty || busy || uncertain)
        && !window.confirm(busy ? 'The PDF revision request may still complete. Leave and discard local document inputs?' : 'Leave and discard unsaved document values and wording?')) navigation.cancel();
  }
  function protectUnload(event: BeforeUnloadEvent) { if (dirty || busy || uncertain) { event.preventDefault(); event.returnValue = ''; } }
  beforeNavigate(protectNavigation);
  onMount(() => { void loadInitial(); window.addEventListener('beforeunload', protectUnload); return () => window.removeEventListener('beforeunload', protectUnload); });
  onDestroy(() => { disposed = true; operation++; onStateChange?.(true); onSourceChange?.(null); onEditorStateChange?.(false); });
</script>

<section class="card p-6 mb-6 space-y-4" aria-label="Revise HTML document">
  <h2 class="font-display text-lg">Document values and wording</h2>
  <p class="text-sm text-text-secondary">The approved layout, CSS, assets and template defaults stay fixed. Change only this document’s declared information or text sections. Saving renders a new immutable PDF revision; its content needs fresh human review{retained?.source_schema_version === 3 ? ', and both signature locations are regenerated for the new PDF' : ' and field placement'} before sending.</p>
  {#if loading}<p role="status" class="text-sm">Loading retained document source…</p>{/if}
  {#if error}<p role="alert" class="text-sm text-danger">{error}</p>{/if}
  {#if needsRefresh || uncertain}<div class="text-sm space-y-2"><p>Your local inputs are retained. Inspect the saved revision before another write.</p>
    {#if acknowledgedDocument}<p>Revision {acknowledgedDocument.html_materialization_revision} was acknowledged as saved.</p>{/if}
    <button type="button" class="btn btn-secondary" disabled={busy || externalBusy || reconciliationBusy} onclick={inspectLatest}>Inspect current HTML revision</button></div>
  {:else if !me || (!retained && !loading)}<button type="button" class="btn btn-secondary" disabled={busy || externalBusy || reconciliationBusy} onclick={loadInitial}>Reload session and source</button>{/if}
  {#if latestSource && latestDocument}<div class="text-sm space-y-2"><p>Saved PDF revision {latestSource.materialization_revision} · {latestDocument.status}. Loading it replaces local document inputs.</p>
    <button type="button" class="btn btn-secondary" disabled={busy || externalBusy || reconciliationBusy} onclick={adoptLatest}>Load saved HTML revision</button></div>{/if}
  {#if retained}
    <p class="text-xs text-text-secondary">Retained template version {retained.template_version} · PDF revision {retained.materialization_revision}</p>
    {#if retained.contract_profile}<div class="border border-border-light rounded-md p-4 text-sm space-y-2">
      <p class="font-medium">Reviewed {retained.contract_profile.kind === 'proposal' ? 'proposal' : 'ordinary B2B services'} profile · version {retained.contract_profile.version}</p>
      <p>Both parties sign. Representative names and email addresses come from these printed values. Changing them updates the intended signer, renders a fresh PDF and {retained.source_schema_version === 3 ? 'regenerates the signature locations for fresh review' : 'clears review and signature placement'}. Declared identity and authority are assertions; Hash does not independently verify them or determine legal sufficiency.</p>
    </div>{/if}
    {#if retained.source_schema_version === 3}<p class="text-sm" role="note">The appended signing page and its branding stay fixed to the approved design. Both signature locations are generated automatically and cannot be moved or reassigned. Party details must fit its bounded layout and bundled Latin font.</p>{/if}
    {#if !retained.can_edit || document.status !== 'draft'}<p role="note" class="text-sm">This document cannot currently be revised here. If a recipient has entered a field value, signed or accepted, preserve that evidence and create a superseding document instead.</p>
    {:else if !authority}<p role="note" class="text-sm">The original sender or an owner must revise this document.</p>{/if}
    <form onsubmit={save} class="space-y-4">
      <fieldset disabled={!canSave} class="space-y-4 min-w-0">
        {#each valueGroups as group (group.id)}<section class="space-y-3" aria-label={group.label}><h3 class="font-medium">{group.label}</h3>
          {#each group.values as field (field.name)}<label class="block text-sm break-words">{field.label}{field.required ? ' (required)' : ''}
            <textarea bind:value={values[field.name]} rows="2" maxlength={field.max_chars * 2} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2"></textarea>
            <span class="text-xs text-text-secondary">Up to {field.max_chars} characters.</span></label>{/each}
        </section>{/each}
        {#each retained.sections as section (section.name)}<div class="space-y-2"><label class="block text-sm break-words">Document wording: {section.name.replaceAll('_', ' ')}
          <textarea bind:value={sections[section.name]} rows="5" maxlength={section.max_chars * 2} class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2"></textarea></label>
          <details class="text-xs text-text-secondary"><summary>Approved template wording</summary><p class="whitespace-pre-wrap break-words mt-2">{section.default_text}</p></details>
          {#if sections[section.name] !== section.default_text}<p role="note" class="text-xs text-warning">This wording differs from the approved template. Human review of the exact rendered PDF is required; Hash does not determine legal completeness.</p>{/if}</div>{/each}
        <label class="block text-sm">Revision summary<textarea bind:value={summary} rows="2" maxlength="1000" class="mt-1 block w-full border border-border-light rounded-md bg-bg-elevated px-3 py-2"></textarea><span class="text-xs text-text-secondary">Optional, up to 500 characters. This appears in document history.</span></label>
      </fieldset>
      <button type="submit" class="btn btn-primary" disabled={!canSave || !dirty}>{busy ? 'Saving and rendering revision…' : 'Save revision and render PDF'}</button>
    </form>
  {/if}
</section>
