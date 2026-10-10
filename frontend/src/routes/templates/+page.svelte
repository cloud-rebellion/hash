<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    listTemplates,
    uploadPDFTemplate,
    createDocumentFromTemplate,
    createStarterTemplate,
    createBlocksTemplate,
    type TemplateResponse,
    type PDFPartyBinding,
  } from '$lib/api/client';
  import { pdfTemplateParties, type PDFTemplateParty } from '$lib/pdfTemplate';
  import { LOCALES } from '$lib/i18n';
  import HtmlTemplatePopulate from '$lib/components/HtmlTemplatePopulate.svelte';
  import CRMTemplatePopulationPanel from '$lib/components/CRMTemplatePopulationPanel.svelte';
  import { CRMTemplatePopulationController, initialCRMTemplateState, readCreationMarker, storeCreationMarker, type HTMLCreationMarker, type CRMTemplateState } from '$lib/crmTemplatePopulation';
  import { crmTemplateTransport } from '$lib/api/crmTemplatePopulation';
  import { Upload, FileText, FilePlus, Sparkles, FileSignature } from 'lucide-svelte';

  let templates = $state<TemplateResponse[]>([]);
  let loading = $state(true);
  let uploading = $state(false);
  let error = $state<string | null>(null);
  let creatingId = $state<string | null>(null);
  let seeding = $state<string | null>(null);
  let selectedTemplate = $state<TemplateResponse | null>(null);
  let selectedHTMLTemplate = $state<TemplateResponse | null>(null);
  let htmlFormDirty = $state(false);
  let selectedParties = $state<PDFTemplateParty[]>([]);
  let bindings = $state<PDFPartyBinding[]>([]);
  let documentName = $state('');
  let pendingMarker = $state<HTMLCreationMarker | null>(null), pendingMarkerInvalid = $state(false);
  let pendingChecked = $state(false);
  let recoveryState = $state.raw<CRMTemplateState>(initialCRMTemplateState());
  let recoveryController = $state.raw<CRMTemplatePopulationController | null>(null);
  const pendingCreation = $derived(!pendingChecked || !!pendingMarker || pendingMarkerInvalid);
  let disposed = false;
  onDestroy(() => { disposed = true; recoveryController?.dispose(); });
  function persistPending(marker: HTMLCreationMarker | null) { storeCreationMarker(window.sessionStorage, marker); pendingMarker = marker; }
  function recoverPending(marker: HTMLCreationMarker) {
    recoveryController?.dispose();
    recoveryController = new CRMTemplatePopulationController(null, crmTemplateTransport,
      () => { throw new Error('A restored request can only be inspected.'); }, (next) => { if (!disposed) recoveryState = next; },
      persistPending, async (doc) => { if (disposed) throw new Error('Return to the template library to inspect this request.'); await goto(`/documents/${doc.id}`); }, marker);
    recoveryState = recoveryController.state;
  }

  async function seedStarter() {
    if (pendingCreation) return;
    seeding = 'starter';
    error = null;
    try {
      await createStarterTemplate('services-agreement-sv');
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      seeding = null;
    }
  }

  async function newBlankTemplate() {
    if (pendingCreation) return;
    seeding = 'blank';
    error = null;
    try {
      await createBlocksTemplate(`Ny mall (${new Date().toLocaleDateString()})`);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      seeding = null;
    }
  }

  async function useTemplate(t: TemplateResponse) {
    if (creatingId !== null || pendingCreation) return;
    if (selectedHTMLTemplate && htmlFormDirty && !window.confirm('Discard the entered values and select another template?')) return;
    if (selectedTemplate && bindings.some((binding) => binding.name.trim() || binding.email.trim())
        && !window.confirm('Discard the entered signing parties and select another template?')) return;
    selectedHTMLTemplate = null;
    htmlFormDirty = false;
    selectedTemplate = null;
    error = null;
    if (t.source_kind === 'html') {
      selectedHTMLTemplate = t;
      return;
    }
    if (t.source_kind === 'pdf') {
      try {
        const parties = pdfTemplateParties(t.fields_json);
        if (parties.length) {
          selectedTemplate = t;
          selectedParties = parties;
          bindings = parties.map((party) => ({ role: party.role, name: '', email: '', locale: 'en' }));
          documentName = `${t.name} (${new Date().toLocaleDateString()})`;
          return;
        }
      } catch (e) { error = (e as Error).message; return; }
    }
    creatingId = t.id;
    error = null;
    try {
      const doc = await createDocumentFromTemplate(
        `${t.name} (${new Date().toLocaleDateString()})`,
        t.id,
        t.source_kind,
      );
      if (!disposed) await goto(`/documents/${doc.id}`);
    } catch (e) {
      error = (e as Error).message;
      creatingId = null;
    }
  }

  async function createBoundDocument(event: Event) {
    event.preventDefault();
    if (!selectedTemplate || creatingId !== null || pendingCreation) return;
    const template = selectedTemplate;
    const parties = bindings.map((party) => ({ ...party, name: party.name.trim(), email: party.email.trim() }));
    creatingId = template.id;
    error = null;
    try {
      const doc = await createDocumentFromTemplate(documentName.trim(), template.id, 'pdf', {
        expected_template_version: template.version, parties,
      });
      if (!disposed && selectedTemplate?.id === template.id && selectedTemplate.version === template.version) {
        await goto(`/documents/${doc.id}`);
      }
    } catch (e) { if (!disposed) error = (e as Error).message; }
    finally { if (!disposed) creatingId = null; }
  }

  let fileInput: HTMLInputElement;
  let nameInput = $state('');

  async function refresh() {
    loading = true;
    try {
      const res = await listTemplates();
      templates = res.templates;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    try { pendingMarker = readCreationMarker(window.sessionStorage); if (pendingMarker) recoverPending(pendingMarker); }
    catch { pendingMarkerInvalid = true; error = 'The pending creation marker cannot be verified. Another creation remains blocked; return with the original account for recovery.'; }
    finally { pendingChecked = true; }
    void refresh();
  });

  async function onUpload(e: Event) {
    e.preventDefault();
    const file = fileInput.files?.[0];
    if (!file || !nameInput || pendingCreation) return;
    uploading = true;
    error = null;
    try {
      await uploadPDFTemplate(nameInput, file);
      nameInput = '';
      fileInput.value = '';
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      uploading = false;
    }
  }
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Library</p>
    <h1 class="page-title">Templates</h1>
    <a href="/templates/html/new" class="btn btn-secondary" aria-disabled={pendingCreation} onclick={(event) => { if (pendingCreation) event.preventDefault(); }}>Create HTML design</a>
  </div>

  {#if error}<p role="alert" class="card p-4 mb-6 text-danger">{error}</p>{/if}
  {#if !selectedHTMLTemplate && recoveryController && pendingMarker}<div class="card p-6 mb-6"><CRMTemplatePopulationPanel controller={recoveryController} state={recoveryState} /></div>{/if}

  {#if selectedHTMLTemplate}
    {#key selectedHTMLTemplate.id}
      {@const selectedID = selectedHTMLTemplate.id}
      <HtmlTemplatePopulate template={selectedHTMLTemplate}
        {pendingMarker} onPendingChange={(marker) => { pendingMarker = marker; }}
        onDirtyChange={(dirty) => { if (selectedHTMLTemplate?.id === selectedID) htmlFormDirty = dirty; }}
        onBusyChange={(busy) => { if (!disposed && selectedHTMLTemplate?.id === selectedID) creatingId = busy ? selectedID : null; }}
        onClose={() => { if (selectedHTMLTemplate?.id === selectedID) { selectedHTMLTemplate = null; htmlFormDirty = false; } }}
        onCreated={async (doc) => { if (disposed || selectedHTMLTemplate?.id !== selectedID) throw new Error('Return to the original creation form before opening this document.'); htmlFormDirty = false; await goto(`/documents/${doc.id}`); }} />
    {/key}
  {/if}

  {#if selectedTemplate}
    <form onsubmit={createBoundDocument} class="card p-6 mb-6 space-y-4" aria-label="Create document from PDF signing template">
      <h2 class="font-display text-lg">New contract from {selectedTemplate.name}</h2>
      <p class="text-sm text-text-secondary">Version {selectedTemplate.version} reuses the PDF text and signature positions. Add the people who will sign this contract.</p>
      <label class="block text-sm">Document name
        <input bind:value={documentName} required maxlength="200" disabled={creatingId !== null} class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" />
      </label>
      {#each bindings as binding, index (binding.role)}
        <fieldset class="border border-border-light rounded-md p-4 space-y-3" disabled={creatingId !== null}>
          <legend class="text-sm px-1">{selectedParties[index].label}</legend>
          <label class="block text-sm">Full name <input bind:value={binding.name} required maxlength="200" autocomplete="name" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
          <label class="block text-sm">Email address <input type="email" bind:value={binding.email} required maxlength="254" autocomplete="email" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
          <label class="block text-sm">Email language
            <select bind:value={binding.locale} class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated">
              {#each LOCALES as locale}<option value={locale.code}>{locale.name}</option>{/each}
            </select>
          </label>
        </fieldset>
      {/each}
      <div class="flex gap-2">
        <button type="submit" class="btn btn-primary" disabled={creatingId !== null}>{creatingId ? 'Creating…' : 'Create contract draft'}</button>
        <button type="button" class="btn btn-secondary" disabled={creatingId !== null} onclick={() => { selectedTemplate = null; bindings = []; selectedParties = []; }}>Cancel</button>
      </div>
    </form>
  {/if}

  <div class="card p-6 mb-6">
    <h2 class="font-display font-extralight text-lg mb-1">Development-only legal draft</h2>
    <p class="text-sm text-text-secondary mb-4 leading-relaxed">
      This Swedish starter is not counsel-approved and is unavailable in production.
      In development you can seed it for layout testing; do not treat it as legal advice
      or send it for signature without approval of the exact revision.
    </p>
    <div class="flex flex-wrap gap-3">
      <button class="btn btn-primary" disabled={seeding !== null || pendingCreation} onclick={seedStarter}>
        <FileSignature class="size-4" />
        {seeding === 'starter' ? 'Creating…' : 'UTKAST — Tjänsteavtal (svenska)'}
      </button>
      <button class="btn btn-secondary" disabled={seeding !== null || pendingCreation} onclick={newBlankTemplate}>
        <Sparkles class="size-4" />
        {seeding === 'blank' ? 'Creating…' : 'Blank block template'}
      </button>
    </div>
  </div>

  <form onsubmit={onUpload} class="card p-6 mb-8 space-y-4">
    <div>
      <label class="block text-sm font-medium mb-1" for="tpl-name">Template name</label>
      <input
        id="tpl-name"
        type="text"
        bind:value={nameInput}
        disabled={pendingCreation}
        required
        placeholder="Consulting Agreement v1"
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      />
    </div>
    <div>
      <label class="block text-sm font-medium mb-1" for="tpl-file">PDF file</label>
      <input
        id="tpl-file"
        type="file"
        accept="application/pdf"
        bind:this={fileInput}
        disabled={pendingCreation}
        required
        class="w-full text-sm"
      />
    </div>
    <button type="submit" class="btn btn-primary" disabled={uploading || pendingCreation}>
      <Upload class="size-4" />
      {uploading ? 'Uploading…' : 'Upload PDF as template'}
    </button>
  </form>

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if templates.length === 0}
    <div class="card p-12 text-center">
      <FileText class="size-8 mx-auto text-text-muted mb-3" />
      <p class="font-display text-xl font-extralight">No templates yet</p>
      <p class="text-text-secondary text-sm mt-2">Create an HTML design or upload your first PDF above.</p>
    </div>
  {:else}
    <div class="card overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Name</th>
            <th class="hidden sm:table-cell text-left px-4 py-3 font-medium">Type</th>
            <th class="text-left px-4 py-3 font-medium">Version</th>
            <th class="hidden sm:table-cell text-left px-4 py-3 font-medium">Updated</th>
            <th class="text-right px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each templates as t (t.id)}
            <tr class="border-b border-border-light last:border-0">
              <td class="px-4 py-3">{t.name}<span class="block sm:hidden text-xs text-text-muted capitalize">{t.source_kind}</span></td>
              <td class="hidden sm:table-cell px-4 py-3 capitalize">{t.source_kind}</td>
              <td class="px-4 py-3 text-text-muted">v{t.version}</td>
              <td class="hidden sm:table-cell px-4 py-3 text-text-muted">{new Date(t.updated_at).toLocaleString()}</td>
              <td class="px-4 py-3 text-right">
                {#if t.source_kind === 'html'}<a href={`/templates/${t.id}/html`} class="btn btn-secondary text-xs mr-2" aria-disabled={pendingCreation} onclick={(event) => { if (pendingCreation) event.preventDefault(); }}>Open design</a>{/if}
                <button
                  class="btn btn-secondary text-xs"
                  disabled={creatingId !== null || pendingCreation}
                  onclick={() => useTemplate(t)}
                >
                  <FilePlus class="size-3" />
                  {creatingId === t.id ? 'Creating…' : t.source_kind === 'html' ? 'Use design' : 'New document'}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
