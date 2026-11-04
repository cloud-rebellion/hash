<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import { goto, beforeNavigate } from '$app/navigation';
  import {
    listTemplates,
    getMe,
    uploadPDFTemplate,
    createDocumentFromTemplate,
    createStarterTemplate,
    createBlocksTemplate,
    type TemplateResponse,
    type PDFPartyBinding,
  } from '$lib/api/client';
  import { pdfTemplateParties, type PDFTemplateParty } from '$lib/pdfTemplate';
  import { LOCALES } from '$lib/i18n';
  import DocumentPurposeSelect from '$lib/components/DocumentPurposeSelect.svelte';
  import { requireDocumentPurpose, blockTemplateNeedsSigning, type DocumentPurpose } from '$lib/documentPurpose';
  import { ui, staffLocale } from '$lib/staffPreferences';
  import HtmlTemplatePopulate from '$lib/components/HtmlTemplatePopulate.svelte';
  import DocumentThumbnail from '$lib/components/DocumentThumbnail.svelte';
  import TemplateReadPreview from '$lib/components/TemplateReadPreview.svelte';
  import LibraryRemovalAction from '$lib/components/LibraryRemovalAction.svelte';
  import CRMTemplatePopulationPanel from '$lib/components/CRMTemplatePopulationPanel.svelte';
  import { CRMTemplatePopulationController, initialCRMTemplateState, readCreationMarker, storeCreationMarker, type HTMLCreationMarker, type CRMTemplateState } from '$lib/crmTemplatePopulation';
  import { crmTemplateTransport } from '$lib/api/crmTemplatePopulation';
  import { Upload, FileText, FilePlus, Sparkles, FileSignature, Search, RefreshCw, ArrowUpRight } from 'lucide-svelte';

  let templates = $state<TemplateResponse[]>([]);
  let search = $state('');
  let canManageTemplates = $state(false), removalBusy = $state(false);
  let listError = $state<string | null>(null);
  const visibleTemplates = $derived(templates.filter(template => template.name.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())));
  let loading = $state(true);
  let starterTemplatesAvailable = $state(false);
  let uploading = $state(false);
  let showUpload = $state(false);
  let error = $state<string | null>(null);
  let creatingId = $state<string | null>(null);
  let seeding = $state<string | null>(null);
  let selectedTemplate = $state<TemplateResponse | null>(null);
  let selectedHTMLTemplate = $state<TemplateResponse | null>(null);
  let htmlFormDirty = $state(false);
  let selectedParties = $state<PDFTemplateParty[]>([]);
  let bindings = $state<PDFPartyBinding[]>([]);
  let documentName = $state('');
  let documentPurpose = $state<DocumentPurpose | ''>('');
  let templateCreationUnconfirmed = $state(false);
  let pendingMarker = $state<HTMLCreationMarker | null>(null), pendingMarkerInvalid = $state(false);
  let pendingChecked = $state(false);
  let recoveryState = $state.raw<CRMTemplateState>(initialCRMTemplateState());
  let recoveryController = $state.raw<CRMTemplatePopulationController | null>(null);
  const pendingCreation = $derived(!pendingChecked || !!pendingMarker || pendingMarkerInvalid || templateCreationUnconfirmed);
  const selectedBlockSigning = $derived(selectedTemplate?.source_kind === 'blocks' ? blockTemplateNeedsSigning(selectedTemplate.blocks_json) : false);
  let previewTemplate = $state<TemplateResponse | null>(null);
  let previewOwner = $state.raw<{ retire(): Promise<void>; canLeave(): boolean } | undefined>(undefined);
  let previewPanel = $state.raw<HTMLDivElement | undefined>(undefined);
  let creationPanel = $state.raw<HTMLDivElement | undefined>(undefined);
  let previewRevision = 0;
  let disposed = false;
  onDestroy(() => { disposed = true; recoveryController?.dispose(); });
  beforeNavigate(({ cancel }) => { if (previewOwner && previewOwner.canLeave?.() !== true) cancel(); });
  function persistPending(marker: HTMLCreationMarker | null) { storeCreationMarker(window.sessionStorage, marker); pendingMarker = marker; }
  function recoverPending(marker: HTMLCreationMarker) {
    recoveryController?.dispose();
    recoveryController = new CRMTemplatePopulationController(null, crmTemplateTransport,
      () => { throw new Error($ui('A restored request can only be inspected.')); }, (next) => { if (!disposed) recoveryState = next; },
      persistPending, async (doc) => { if (disposed) throw new Error($ui('Return to the template library to inspect this request.')); await goto(`/documents/${doc.id}`); }, marker);
    recoveryState = recoveryController.state;
  }

  async function seedStarter() {
    if (pendingCreation || removalBusy || !starterTemplatesAvailable) return;
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
    if (pendingCreation || removalBusy) return;
    seeding = 'blank';
    error = null;
    try {
      await createBlocksTemplate(`${$ui('New template')} (${new Date().toLocaleDateString($staffLocale)})`);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      seeding = null;
    }
  }

  async function useTemplate(t: TemplateResponse) {
    if (creatingId !== null || pendingCreation || removalBusy || templateCreationUnconfirmed) return;
    if (selectedHTMLTemplate && htmlFormDirty && !window.confirm($ui('Discard the entered values and select another template?'))) return;
    if (selectedTemplate && bindings.some((binding) => binding.name.trim() || binding.email.trim())
        && !window.confirm($ui('Discard the entered signing parties and select another template?'))) return;
    selectedHTMLTemplate = null;
    htmlFormDirty = false;
    selectedTemplate = null;
    error = null;
    if (t.source_kind === 'html') {
      selectedHTMLTemplate = t;
      return;
    }
    try {
      const parties = t.source_kind === 'pdf' ? pdfTemplateParties(t.fields_json) : [];
      selectedTemplate = t; selectedParties = parties;
      bindings = parties.map((party) => ({ role: party.role, name: '', email: '', locale: 'en' }));
      documentName = `${t.name} (${new Date().toLocaleDateString($staffLocale)})`;
      documentPurpose = '';
    } catch (e) { error = (e as Error).message; }
  }

  async function closePreview(): Promise<boolean> {
    if (previewOwner && previewOwner.canLeave?.() !== true) return false;
    const revision = ++previewRevision;
    try { await previewOwner?.retire(); }
    catch { if (!disposed) error = $ui('The preview could not be closed. Refresh this page before opening another template.'); return false; }
    if (disposed || revision !== previewRevision) return false;
    previewTemplate = null;
    // Retire and unmount the old keyed view before a same-card reopen.
    await tick();
    if (disposed || revision !== previewRevision) return false;
    return true;
  }

  async function openTemplate(t: TemplateResponse) {
    if (disposed || creatingId !== null || pendingCreation || removalBusy) return;
    if (selectedHTMLTemplate && htmlFormDirty && !window.confirm($ui('Discard the entered values and select another template?'))) return;
    if (selectedTemplate && bindings.some((binding) => binding.name.trim() || binding.email.trim())
        && !window.confirm($ui('Discard the entered signing parties and select another template?'))) return;
    if (!await closePreview()) return;
    selectedHTMLTemplate = null; htmlFormDirty = false; selectedTemplate = null; bindings = []; selectedParties = []; error = null;
    if (t.source_kind === 'html') { try { await goto(`/templates/${t.id}/html`); } catch { if (!disposed) error = $ui('The design could not be opened. Try again.'); } return; }
    previewTemplate = t;
    await tick();
    if (!disposed && previewTemplate?.id === t.id) { previewPanel?.focus(); previewPanel?.scrollIntoView({ block: 'start' }); }
  }

  async function useFromLibrary(t: TemplateResponse) {
    if (disposed || creatingId !== null || pendingCreation || removalBusy) return;
    if (previewTemplate && !await closePreview()) return;
    await useTemplate(t);
    await tick();
    if (!disposed && (selectedTemplate || selectedHTMLTemplate)) { creationPanel?.focus(); creationPanel?.scrollIntoView({ block: 'start' }); }
  }

  async function usePreview() {
    const t = previewTemplate;
    if (t) await useFromLibrary(t);
  }

  async function createBoundDocument(event: Event) {
    event.preventDefault();
    if (!selectedTemplate || creatingId !== null || pendingCreation || removalBusy || templateCreationUnconfirmed) return;
    const template = selectedTemplate;
    let purpose: DocumentPurpose;
    try {
      purpose = requireDocumentPurpose(documentPurpose);
      if (!documentName.trim()) throw new Error('Enter a document name.');
      const needsSigning = template.source_kind === 'blocks' ? blockTemplateNeedsSigning(template.blocks_json) : false;
      if (needsSigning === null) throw new Error('The template content could not be checked. Open the template or refresh the library before creating a document.');
      if (needsSigning && purpose !== 'signing') throw new Error('This template contains recipient-fillable fields and requires Signing. Choose a design without those fields for a document or presentation.');
    }
    catch (e) { error = (e as Error).message; return; }
    const parties = bindings.map((party) => ({ ...party, name: party.name.trim(), email: party.email.trim() }));
    creatingId = template.id; error = null;
    try {
      const doc = await createDocumentFromTemplate(documentName.trim(), template.id, template.source_kind as 'pdf' | 'blocks',
        template.source_kind === 'pdf' ? { expected_template_version: template.version, ...(purpose === 'signing' && parties.length ? { parties } : {}) } : undefined, purpose);
      if (doc.purpose !== purpose || doc.org_id !== template.org_id || doc.template_id !== template.id) throw new Error('The saved document purpose could not be confirmed. Reload the document library before creating another document.');
      if (!disposed && selectedTemplate?.id === template.id && selectedTemplate.version === template.version) await goto(`/documents/${doc.id}`);
    } catch (e) { if (!disposed) { error = (e as Error).message; templateCreationUnconfirmed = true; } }
    finally { if (!disposed) creatingId = null; }
  }

  async function prepareTemplateRemoval(id: string): Promise<boolean> {
    if (disposed || pendingCreation || creatingId !== null || uploading || seeding !== null || selectedTemplate?.id === id || selectedHTMLTemplate?.id === id) return false;
    return previewTemplate?.id === id ? await closePreview() : true;
  }

  let fileInput: HTMLInputElement;
  let nameInput = $state('');

  async function refresh() {
    if (disposed) return;
    loading = true;
    listError = null;
    starterTemplatesAvailable = false;
    try {
      const res = await listTemplates();
      if (disposed) return;
      templates = res.templates;
      starterTemplatesAvailable = res.starter_templates_available === true;
    } catch (e) {
      if (!disposed) listError = (e as Error).message;
    } finally {
      if (!disposed) loading = false;
    }
  }

  onMount(() => {
    void getMe().then(me => { if (!disposed) canManageTemplates = me.role === 'owner' || me.role === 'sender'; }).catch(() => { if (!disposed) canManageTemplates = false; });
    try { pendingMarker = readCreationMarker(window.sessionStorage); if (pendingMarker) recoverPending(pendingMarker); }
    catch { pendingMarkerInvalid = true; error = $ui('The pending creation marker cannot be verified. Another creation remains blocked; return with the original account for recovery.'); }
    finally { pendingChecked = true; }
    void refresh();
  });

  function toggleUpload() {
    if (uploading || pendingCreation || removalBusy) return;
    showUpload = !showUpload;
  }

  async function onUpload(e: Event) {
    e.preventDefault();
    const file = fileInput.files?.[0];
    if (!file || !nameInput || pendingCreation || removalBusy) return;
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

<div class="template-workspace">
  <header class="library-header">
    <div class="library-introduction">
      <p class="page-eyebrow">{$ui('Library')}</p>
      <h1 class="library-title">{$ui('Templates')}</h1>
      <p class="library-description">{$ui('Save a reusable design, then create a fresh document for each customer.')}</p>
    </div>

  </header>
  <div class="library-command-bar">
    <div class="creation-actions">
      <a href="/templates/html/new" class="btn btn-primary" aria-disabled={pendingCreation || removalBusy} onclick={(event) => { if (pendingCreation || removalBusy) event.preventDefault(); }}>
        <FilePlus class="size-4" /> {$ui('Create HTML design')}
      </a>

      <button type="button" class="btn btn-secondary" disabled={uploading || pendingCreation || removalBusy} aria-expanded={showUpload} aria-controls="template-pdf-upload-panel" onclick={toggleUpload}>
        <Upload class="size-4" /> {$ui('Upload a PDF template')}
      </button>
    </div>
      <label class="library-search">
        <Search class="size-4 text-text-secondary" />
        <input type="search" bind:value={search} aria-label={$ui('Search templates')} placeholder={$ui('Search templates')} class="min-w-0 bg-transparent text-sm text-text-primary outline-none" />
      </label>
  </div>

  {#if error}<p role="alert" class="card p-4 mb-6 text-danger">{error}</p>{/if}
  {#if !selectedHTMLTemplate && recoveryController && pendingMarker}<div class="card p-6 mb-6"><CRMTemplatePopulationPanel controller={recoveryController} state={recoveryState} /></div>{/if}

  {#if previewTemplate}<div bind:this={previewPanel} tabindex="-1" class="preview-panel-focus">{#key previewTemplate.id}<TemplateReadPreview bind:this={previewOwner} template={previewTemplate} canManageReminders={canManageTemplates} onClose={() => { void closePreview(); }} onUse={() => { void usePreview(); }} disabled={creatingId !== null || pendingCreation || removalBusy} />{/key}</div>{/if}

  <div bind:this={creationPanel} tabindex="-1" class="preview-panel-focus">
  {#if selectedHTMLTemplate}
    {#key selectedHTMLTemplate.id}
      {@const selectedID = selectedHTMLTemplate.id}
      <HtmlTemplatePopulate template={selectedHTMLTemplate}
        {pendingMarker} onPendingChange={(marker) => { pendingMarker = marker; }}
        onDirtyChange={(dirty) => { if (selectedHTMLTemplate?.id === selectedID) htmlFormDirty = dirty; }}
        onBusyChange={(busy) => { if (!disposed && selectedHTMLTemplate?.id === selectedID) creatingId = busy ? selectedID : null; }}
        onClose={() => { if (selectedHTMLTemplate?.id === selectedID) { selectedHTMLTemplate = null; htmlFormDirty = false; } }}
        onCreated={async (doc) => { if (disposed || selectedHTMLTemplate?.id !== selectedID) throw new Error($ui('Return to the original creation form before opening this document.')); htmlFormDirty = false; await goto(`/documents/${doc.id}`); }} />
    {/key}
  {/if}

  {#if selectedTemplate}
    <form onsubmit={createBoundDocument} class="card p-6 mb-6 space-y-4" aria-label={$ui('Create document from template')}>
      <h2 class="font-display text-lg">{$ui('New document from {name}', { name: selectedTemplate.name })}</h2>
      <p class="text-sm text-text-secondary">{$ui('Version {version} preserves the saved design. Choose how the new document will be used.', { version: selectedTemplate.version })}</p>
      <label class="block text-sm">{$ui('Document name')}
        <input bind:value={documentName} required maxlength="200" disabled={creatingId !== null || removalBusy || templateCreationUnconfirmed} class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" />
      </label>
      <DocumentPurposeSelect value={documentPurpose} signingOnly={selectedBlockSigning === true} signingReason="This template contains recipient-fillable fields and requires Signing. Choose a design without those fields for a document or presentation." onChange={value => { documentPurpose = value; }} disabled={creatingId !== null || removalBusy || templateCreationUnconfirmed || selectedBlockSigning === null} />
      {#if selectedBlockSigning === null}<p role="alert" class="text-sm text-danger">{$ui('The template content could not be checked. Open the template or refresh the library before creating a document.')}</p>{/if}
      {#if documentPurpose === 'signing'}
      {#each bindings as binding, index (binding.role)}
        <fieldset class="border border-border-light rounded-md p-4 space-y-3" disabled={creatingId !== null || removalBusy || templateCreationUnconfirmed}>
          <legend class="text-sm px-1">{selectedParties[index].label}</legend>
          <label class="block text-sm">{$ui('Full name')} <input bind:value={binding.name} required maxlength="200" autocomplete="name" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
          <label class="block text-sm">{$ui('Email address')} <input type="email" bind:value={binding.email} required maxlength="254" autocomplete="email" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
          <label class="block text-sm">{$ui('Email language')}
            <select bind:value={binding.locale} class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated">
              {#each LOCALES as locale}<option value={locale.code}>{locale.name}</option>{/each}
            </select>
          </label>
        </fieldset>
      {/each}
      {/if}
      {#if templateCreationUnconfirmed}<p role="alert" class="text-sm text-danger">{$ui('Creation is unconfirmed. Reload the document library and inspect the existing draft before creating another.')}</p>{/if}
      <div class="flex gap-2">
        <button type="submit" class="btn btn-primary" disabled={creatingId !== null || removalBusy || templateCreationUnconfirmed || selectedBlockSigning === null}>{creatingId ? $ui('Creating…') : $ui('Create document')}</button>
        <button type="button" class="btn btn-secondary" disabled={creatingId !== null || removalBusy || templateCreationUnconfirmed} onclick={() => { selectedTemplate = null; bindings = []; selectedParties = []; }}>{$ui('Cancel')}</button>
      </div>
    </form>
  {/if}

  </div>

  {#if !loading && starterTemplatesAvailable}
    <div class="card p-5 mb-6">
      <h2 class="font-display text-lg mb-1">{$ui('Development-only legal draft')}</h2>
      <p id="starter-template-availability" class="text-sm text-text-secondary mb-4 leading-relaxed">
        {$ui('This Swedish starter is not counsel-approved. Seed it for layout testing; do not treat it as legal advice or send it for signature without approval of the exact revision.')}
      </p>
      <button type="button" class="btn btn-secondary" disabled={loading || !starterTemplatesAvailable || seeding !== null || pendingCreation} aria-describedby="starter-template-availability" onclick={seedStarter}>
        <FileSignature class="size-4" />
        {seeding === 'starter' ? $ui('Creating…') : $ui('DRAFT — Services agreement (Swedish)')}
      </button>
    </div>
  {/if}

  <form id="template-pdf-upload-panel" hidden={!showUpload} onsubmit={onUpload} class="card p-6 mb-8 space-y-4" aria-label={$ui('Upload a PDF template')}>
    <div class="space-y-1">
      <h2 class="font-display text-lg">{$ui('Upload a PDF template')}</h2>
      <p class="text-sm text-text-secondary">{$ui('Keep an existing PDF layout as a reusable template.')}</p>
    </div>
    <div>
      <label class="block text-sm font-medium mb-1" for="tpl-name">{$ui('Template name')}</label>
      <input
        id="tpl-name"
        type="text"
        bind:value={nameInput}
        disabled={uploading || pendingCreation || removalBusy}
        required
        placeholder={$ui('Consulting Agreement v1')}
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      />
    </div>
    <div>
      <label class="block text-sm font-medium mb-1" for="tpl-file">{$ui('PDF file')}</label>
      <input
        id="tpl-file"
        type="file"
        accept="application/pdf"
        bind:this={fileInput}
        disabled={uploading || pendingCreation || removalBusy}
        required
        class="w-full text-sm"
      />
    </div>
    <button type="submit" class="btn btn-primary" disabled={uploading || pendingCreation || removalBusy}>
      <Upload class="size-4" />
      {uploading ? $ui('Uploading…') : $ui('Upload PDF as template')}
    </button>
  </form>

  <section aria-labelledby="saved-templates-heading" class="template-library">
    <div class="library-toolbar">
      <div class="library-section-title"><h2 id="saved-templates-heading">{$ui('Saved templates')}</h2>{#if !loading && !listError}<span class="library-count">{templates.length}</span>{/if}</div>

    </div>
    {#if loading}
      <div class="card p-10 text-center text-text-secondary" role="status">{$ui('Loading templates…')}</div>
    {:else if listError}
      <div class="card p-6 space-y-3" role="alert">
        <p class="text-sm text-danger">{listError}</p>
        <button type="button" class="btn btn-secondary" onclick={refresh}><RefreshCw class="size-4" /> {$ui('Try again')}</button>
      </div>
    {:else if templates.length === 0}
      <div class="empty-library">
        <div class="empty-pages" aria-hidden="true"><span></span><span></span><span><FileText class="size-8" /></span></div>
        <div class="empty-copy"><p class="font-display text-2xl text-text-primary">{$ui('Your reusable designs start here')}</p>
        <p class="mt-3 max-w-sm text-sm leading-relaxed text-text-secondary">{$ui('Create an HTML design, start with a blank template or upload your first PDF above.')}</p></div>
      </div>
    {:else if visibleTemplates.length === 0}
      <div class="card p-10 text-center text-sm text-text-secondary">{$ui('No templates match your search.')}</div>
    {:else}
      <div class="template-grid">
        {#each visibleTemplates as t (t.id)}
          <article class="template-card">
            <div class="template-preview">
              {#key `${t.id}:${t.version}:${t.content_sha256 ?? ''}:${t.pdf_sha256 ?? ''}`}<DocumentThumbnail item={t} kind="template" />{/key}
              <div class="preview-caption" aria-hidden="true"><span>{$ui(t.source_kind === 'html' ? 'HTML design' : t.source_kind === 'pdf' ? 'PDF template' : 'Block template')}</span><span>{$ui('Version {version}', { version: t.version })}</span></div>
            </div>
            <div class="template-information">
              <div class="template-details">
                <h3>{t.name}</h3>
                <p class="template-updated">{$ui('Updated')} <time datetime={t.updated_at}>{new Date(t.updated_at).toLocaleDateString($staffLocale === 'sv' ? 'sv-SE' : 'en-GB')}</time></p>
              </div>
              <div class="template-card-actions">
                <button type="button" class="btn btn-secondary template-open" disabled={creatingId !== null || pendingCreation || removalBusy} onclick={() => { void openTemplate(t); }}>{$ui('Open template')}</button>
                <button type="button" class="btn btn-primary template-use" disabled={creatingId !== null || pendingCreation || removalBusy} onclick={() => { void useFromLibrary(t); }}>
                  <span>{creatingId === t.id ? $ui('Creating…') : $ui('Use template')}</span><ArrowUpRight class="size-4" />
                </button>
              </div>
              <LibraryRemovalAction kind="template" item={t} canWrite={canManageTemplates}
                disabled={removalBusy || templateCreationUnconfirmed || pendingCreation || creatingId !== null || uploading || seeding !== null || selectedTemplate?.id === t.id || selectedHTMLTemplate?.id === t.id}
                beforeRemove={() => prepareTemplateRemoval(t.id)} onbusy={value => { removalBusy = value; }} onremoved={refresh} />
            </div>
          </article>
        {/each}
      </div>
    {/if}
    <p class="library-note">{$ui('Block templates are created from a saved document.')} <a href="/documents">{$ui('Go to documents')} <ArrowUpRight class="size-3" /></a></p>
  </section>
</div>
<style>
  .template-workspace{max-width:1280px;margin:0 auto;padding:44px 36px 64px;}
  .library-header{padding:0 0 26px;margin-bottom:24px;}
  .library-introduction{min-width:0;max-width:640px;}
  .library-title{font-family:var(--font-display);font-size:44px;font-weight:500;line-height:1.12;letter-spacing:-1.8px;margin:12px 0;}
  .library-description{max-width:600px;font-size:14px;line-height:1.65;color:var(--t-text-secondary);}
  .library-command-bar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:30px;padding-bottom:26px;border-bottom:1px solid var(--t-border);}.creation-actions{display:flex;flex-wrap:wrap;gap:8px;}
  .creation-actions :global(.btn){height:38px;padding:0 12px;border-radius:8px;font-size:12px;white-space:nowrap;}
  .template-library{padding-top:2px;}
  .library-toolbar{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:24px;}
  .library-section-title{display:flex;align-items:center;gap:10px;}
  .library-section-title h2{font-family:var(--font-display);font-size:17px;letter-spacing:-.35px;font-weight:500;}
  .library-count{display:inline-flex;align-items:center;justify-content:center;min-width:25px;height:25px;padding:0 7px;border:1px solid var(--t-border);border-radius:7px;color:var(--t-text-secondary);font-family:var(--font-mono);font-size:11px;}
  .library-search{display:flex;align-items:center;gap:10px;width:260px;min-height:38px;padding:8px 12px;border:1px solid var(--t-border);border-radius:9px;background:var(--t-bg-surface);}
  .library-search:focus-within{outline:2px solid var(--t-accent);outline-offset:3px;}
  .library-search input{width:100%;font-size:12px;}
  .template-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;}
  .template-card{display:flex;flex-direction:column;min-width:0;overflow:hidden;border:1px solid var(--t-border);border-radius:16px;background:var(--t-bg-surface);box-shadow:0 2px 3px #00000003;transition:box-shadow .18s ease,border-color .18s ease;}
  .template-card:hover{border-color:color-mix(in srgb,var(--t-text-secondary) 45%,var(--t-border));box-shadow:0 12px 26px -18px #00000066;}
  .template-preview{position:relative;isolation:isolate;overflow:hidden;}
  .template-preview > :global(div:not(.preview-caption)){height:282px;padding-top:52px;border-bottom:1px solid var(--t-border-light);background:linear-gradient(145deg,var(--t-bg-elevated),var(--t-bg-hover));}
  .template-preview :global(img),.template-preview :global([aria-label="Content preview"]),.template-preview :global([aria-label="Innehållsförhandsvisning"]){box-shadow:0 14px 22px -14px #00000088,0 0 0 1px #00000006;transform:rotate(-1deg);}
  .template-card:nth-child(2n) .template-preview :global(img){transform:rotate(1deg);}
  .preview-caption{position:absolute;left:16px;right:16px;top:15px;display:flex;align-items:center;justify-content:space-between;gap:8px;pointer-events:none;}
  .preview-caption span:first-child{padding:5px 8px;border:1px solid var(--t-border);border-radius:5px;background:var(--t-bg-surface);color:var(--t-text-secondary);font-size:10px;font-weight:500;letter-spacing:.02em;}
  .preview-caption span:last-child{font-size:10px;font-family:var(--font-mono);color:var(--t-text-secondary);}
  .template-information{display:flex;flex:1;flex-direction:column;gap:20px;padding:18px;}.template-details{flex:1;min-height:82px;}
  .template-details h3{font-size:14px;font-weight:500;line-height:1.5;min-height:42px;letter-spacing:-.3px;overflow-wrap:anywhere;}
  .template-updated{display:flex;gap:5px;margin-top:8px;font-size:11px;color:var(--t-text-secondary);}
  .template-card-actions{display:grid;grid-template-columns:1fr 1fr;gap:7px;align-items:stretch;margin-top:auto;}
  .template-card-actions :global(.btn){min-height:37px;height:auto;padding:8px 9px;font-size:10px;border-radius:7px;}
  .template-use{justify-content:space-between;min-width:0;}.template-open{min-width:0;}.library-note{display:flex;flex-wrap:wrap;gap:6px;margin-top:26px;font-size:11px;line-height:1.7;color:var(--t-text-secondary);}.library-note a{display:inline-flex;align-items:center;gap:3px;color:var(--t-text-primary);text-decoration:underline;text-underline-offset:3px;}.preview-panel-focus{outline:none;scroll-margin-top:24px;}
  .empty-library{display:flex;align-items:center;justify-content:center;gap:66px;min-height:320px;padding:44px;border:1px dashed var(--t-border);border-radius:16px;background:var(--t-bg-surface);}
  .empty-pages{position:relative;flex:none;width:140px;height:170px;}
  .empty-pages span{position:absolute;inset:8px 12px;border:1px solid var(--t-border);border-radius:8px;background:var(--t-bg-elevated);}
  .empty-pages span:first-child{transform:rotate(-13deg) translateX(-16px);}
  .empty-pages span:nth-child(2){transform:rotate(9deg) translateX(14px);}
  .empty-pages span:last-child{display:flex;align-items:center;justify-content:center;background:var(--t-bg-surface);color:var(--t-text-muted);box-shadow:0 14px 28px -24px #00000066;}
  @media(max-width:1100px){.template-grid{grid-template-columns:repeat(3,minmax(0,1fr));}}
  @media(max-width:900px){.template-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;}.template-workspace{padding:32px 24px 48px;}}
  @media(max-width:580px){.template-workspace{padding:26px 20px 40px;}.library-title{font-size:36px;letter-spacing:-1.25px;}.library-header{padding-bottom:24px;margin-bottom:24px;}.library-command-bar{align-items:stretch;flex-direction:column;gap:16px;}.creation-actions{gap:8px;}.creation-actions :global(.btn){font-size:11px;}.library-toolbar{align-items:flex-start;flex-direction:column;gap:16px;}.library-search{width:100%;}.template-grid{grid-template-columns:1fr;}.template-preview > :global(div:not(.preview-caption)){height:276px;}.empty-library{flex-direction:column;gap:30px;padding:38px 24px;text-align:center;}.empty-pages{width:110px;height:138px;}}
  @media(prefers-reduced-motion:reduce){.template-card{transition:none;}}
</style>
