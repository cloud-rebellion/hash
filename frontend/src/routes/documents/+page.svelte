<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { goto } from '$app/navigation';
  import { createBlocksDocument, importProposalPDF, importProposalHTML, listDocuments, type DocumentResponse } from '$lib/api/client';
  import { ui, staffLocale } from '$lib/staffPreferences';
  import DocumentThumbnail from '$lib/components/DocumentThumbnail.svelte';
  import DocumentFolders from '$lib/components/DocumentFolders.svelte';
  import { FileText, Plus, Upload, PenLine, Search, ArrowUpRight, RefreshCw, X, FolderInput, ChevronLeft, ChevronRight } from 'lucide-svelte';

  let docs = $state<DocumentResponse[]>([]);
  let loading = $state(true);
  let listError = $state<string | null>(null);
  let error = $state<string | null>(null);
  let creating = $state(false);
  let newName = $state('');
  let importKind = $state<'pdf' | 'html'>('pdf');
  let importName = $state('');
  let pdfFile = $state<File | null>(null);
  let htmlFile = $state<File | null>(null);
  let landscape = $state(false);
  let importing = $state(false);
  let composer = $state<'blank' | 'import' | null>(null);
  let blankTrigger: HTMLButtonElement;
  let importTrigger: HTMLButtonElement;
  let blankNameInput: HTMLInputElement;
  let importNameInput: HTMLInputElement;
  let search = $state('');
  let status = $state('all');
  let folder = $state('all');
  let total = $state(0);
  let offset = $state(0);
  const limit = 24;
  let foldersAvailable = $state(false);
  let canManageFolders = $state(false);
  let folderBusy = $state(false);
  let movingDocument = $state<DocumentResponse | null>(null);
  let moveTrigger = $state.raw<HTMLButtonElement>();
  let disposed = false;
  let listRevision = 0;
  let listController: AbortController | null = null;
  const busy = $derived(creating || importing || folderBusy);
  const visibleDocs = $derived(docs.filter(doc => doc.name.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())));

  async function toggleComposer(kind: 'blank' | 'import') {
    if (busy) return;
    composer = composer === kind ? null : kind;
    await tick();
    if (composer === kind) (kind === 'blank' ? blankNameInput : importNameInput)?.focus();
    else if (composer === null) (kind === 'blank' ? blankTrigger : importTrigger)?.focus();
  }

  async function refresh() {
    if (disposed) return;
    const ticket = ++listRevision;
    listController?.abort(); const controller = new AbortController(); listController = controller;
    loading = true; listError = null;
    try {
      const page = await listDocuments({ folder, status, limit, offset }, controller.signal);
      if (disposed || ticket !== listRevision) return;
      if (!Array.isArray(page.documents) || !Number.isSafeInteger(page.total) || page.total < 0) throw new Error('Unable to load documents.');
      if (offset > 0 && page.documents.length === 0 && page.total <= offset) {
        offset = Math.max(0, Math.floor(Math.max(0, page.total - 1) / limit) * limit);
        await refresh(); return;
      }
      docs = page.documents; total = page.total;
    } catch (e) { if (!disposed && ticket === listRevision) listError = (e as Error).message; }
    finally { if (!disposed && ticket === listRevision) loading = false; }
  }
  function selectFolder(next: string) {
    folder = next; offset = 0; search = ''; movingDocument = null;
    void refresh();
  }
  function changeStatus() { offset = 0; search = ''; void refresh(); }
  function changePage(next: number) {
    if (busy || loading || next < 0 || next >= total) return;
    offset = next; search = ''; movingDocument = null; void refresh();
  }
  function openMove(doc: DocumentResponse, trigger: HTMLButtonElement) {
    if (busy || !foldersAvailable || !canManageFolders) return;
    moveTrigger = trigger; movingDocument = doc;
  }
  function closeMove() { movingDocument = null; moveTrigger?.focus(); }
  onMount(() => { void refresh(); return () => { disposed = true; listRevision++; listController?.abort(); }; });

  async function createBlank(e: Event) {
    e.preventDefault();
    if (busy) return;
    const name = newName.trim();
    if (!name) { error = $ui('Enter a document name.'); return; }
    error = null; creating = true;
    try { const doc = await createBlocksDocument(name); await goto(`/documents/${doc.id}`); }
    catch (e) { error = (e as Error).message; }
    finally { creating = false; }
  }

  function changeImportKind(kind: 'pdf' | 'html') {
    if (busy || importKind === kind) return;
    importKind = kind; pdfFile = null; htmlFile = null; error = null;
  }

  async function importProposal(e: Event) {
    e.preventDefault();
    if (busy) return;
    const name = importName.trim();
    if (!name) { error = $ui('Enter a document name.'); return; }
    const file = importKind === 'pdf' ? pdfFile : htmlFile;
    if (!file) { error = $ui(importKind === 'pdf' ? 'Choose a PDF file to upload.' : 'Choose an HTML file to render.'); return; }
    error = null; importing = true;
    try {
      const out = importKind === 'pdf'
        ? await importProposalPDF(name, file)
        : await importProposalHTML(name, await file.text(), landscape);
      await goto(`/documents/${out.document.id}`);
    } catch (e) { error = (e as Error).message; }
    finally { importing = false; }
  }

  function statusLabel(value: string): string {
    return $ui(({ draft: 'Draft', sent: 'Sent', in_progress: 'In progress', completed: 'Completed', voided: 'Voided', expired: 'Expired' } as Record<string, string>)[value] ?? value);
  }
  function statusTone(value: string): string {
    if (value === 'completed') return 'bg-success/10 text-success';
    if (value === 'sent' || value === 'in_progress') return 'bg-info/10 text-info';
    if (value === 'voided' || value === 'expired') return 'bg-danger/10 text-danger';
    return 'bg-bg-hover text-text-secondary';
  }
</script>

<div class="max-w-6xl mx-auto px-5 sm:px-6 py-8 sm:py-10 space-y-7">
  <header class="flex flex-col sm:flex-row sm:items-end justify-between gap-5 pb-7 border-b border-border-light">
    <div class="max-w-2xl">
      <p class="page-eyebrow mb-3">{$ui('Your workspace')}</p>
      <h1 class="page-title !font-normal !tracking-tight">{$ui('Documents')}</h1>
      <p class="text-sm text-text-secondary mt-3 leading-relaxed">{$ui('From first draft to final signature. Create a document here or bring a finished design.')}</p>
    </div>
    <div class="flex flex-wrap items-center gap-2 shrink-0">
      <button type="button" bind:this={importTrigger} class="btn btn-secondary !py-2.5" disabled={busy} aria-expanded={composer === 'import'} aria-controls="import-document-composer" onclick={() => toggleComposer('import')}><Upload class="size-4" />{$ui('Import a document')}</button>
      <button type="button" bind:this={blankTrigger} class="btn btn-primary !py-2.5" disabled={busy} aria-expanded={composer === 'blank'} aria-controls="blank-document-composer" onclick={() => toggleComposer('blank')}><Plus class="size-4" />{$ui('New document')}</button>
    </div>
  </header>

  {#if error}<div role="alert" class="rounded-xl border border-danger/25 bg-danger/5 px-5 py-4 text-sm text-danger">{$ui(error)}</div>{/if}

  <div class:hidden={composer === null}>
    <form id="blank-document-composer" hidden={composer !== 'blank'} onsubmit={createBlank} class="card p-5 sm:p-6 flex-col gap-5 {composer === 'blank' ? 'flex' : '!hidden'}" aria-label={$ui('Create a blank document')} aria-busy={creating}>
      <div class="flex items-start gap-3">
        <div class="rounded-xl bg-bg-hover p-3"><PenLine class="size-5 text-accent" /></div>
        <div class="flex-1"><h2 class="font-medium">{$ui('Start with a blank document')}</h2><p class="text-sm text-text-secondary mt-1">{$ui('Write your content in Hash, then add the people who will sign.')}</p></div><button type="button" class="btn btn-secondary !p-2" disabled={busy} aria-label={$ui('Close')} onclick={() => toggleComposer('blank')}><X class="size-4" /></button>
      </div>
      <div>
        <label class="block text-sm font-medium mb-2" for="doc-name">{$ui('New document name')}</label>
        <input id="doc-name" bind:this={blankNameInput} type="text" bind:value={newName} required maxlength="200" disabled={busy} placeholder={$ui('e.g. Service agreement — Acme')} class="w-full px-3 py-2.5 rounded-lg border border-border bg-bg-elevated text-sm" />
      </div>
      <button type="submit" class="btn btn-primary sm:self-start" disabled={busy}><Plus class="size-4" />{$ui(creating ? 'Creating…' : 'Create blank')}</button>
    </form>

    <form id="import-document-composer" hidden={composer !== 'import'} onsubmit={importProposal} class="card p-5 sm:p-6 space-y-5 {composer === 'import' ? '' : '!hidden'}" aria-label={$ui('Import a document')} aria-busy={importing}>
      <div class="flex items-start gap-3">
        <div class="rounded-xl bg-accent/8 p-3"><Upload class="size-5 text-accent" /></div>
        <div class="flex-1"><h2 class="font-medium">{$ui('Use a finished design')}</h2><p class="text-sm text-text-secondary mt-1">{$ui('Import a PDF or HTML page, place signature fields, and send.')}</p></div><button type="button" class="btn btn-secondary !p-2" disabled={busy} aria-label={$ui('Close')} onclick={() => toggleComposer('import')}><X class="size-4" /></button>
      </div>
      <div class="inline-flex rounded-lg bg-bg-hover p-1 gap-1" aria-label={$ui('Import format')}>
        <button type="button" aria-pressed={importKind === 'pdf'} disabled={busy} class="px-3 py-2 rounded-md text-sm flex items-center gap-2 {importKind === 'pdf' ? 'bg-bg-surface shadow-sm font-medium' : 'text-text-secondary'}" onclick={() => changeImportKind('pdf')}><FileText class="size-4" />{$ui('PDF file')}</button>
        <button type="button" aria-pressed={importKind === 'html'} disabled={busy} class="px-3 py-2 rounded-md text-sm flex items-center gap-2 {importKind === 'html' ? 'bg-bg-surface shadow-sm font-medium' : 'text-text-secondary'}" onclick={() => changeImportKind('html')}><PenLine class="size-4" />{$ui('Designed page (HTML)')}</button>
      </div>
      <div class="grid sm:grid-cols-2 gap-4">
        <div><label class="block text-sm font-medium mb-2" for="import-name">{$ui('Document name')}</label><input id="import-name" bind:this={importNameInput} bind:value={importName} required maxlength="200" disabled={busy} placeholder={$ui('e.g. Partnership proposal')} class="w-full px-3 py-2.5 rounded-lg border border-border bg-bg-elevated text-sm" /></div>
        <div>
          {#if importKind === 'pdf'}
            <label class="block text-sm font-medium mb-2" for="import-pdf">{$ui('PDF file')}</label><input id="import-pdf" type="file" required disabled={busy} accept="application/pdf,.pdf" onchange={e => pdfFile = e.currentTarget.files?.[0] ?? null} class="block w-full text-sm text-text-secondary file:mr-3 file:rounded-md file:border-0 file:bg-bg-hover file:px-3 file:py-2.5 file:text-text-primary" />
          {:else}
            <label class="block text-sm font-medium mb-2" for="import-html">{$ui('HTML file')}</label><input id="import-html" type="file" required disabled={busy} accept="text/html,.html,.htm" onchange={e => htmlFile = e.currentTarget.files?.[0] ?? null} class="block w-full text-sm text-text-secondary file:mr-3 file:rounded-md file:border-0 file:bg-bg-hover file:px-3 file:py-2.5 file:text-text-primary" />
          {/if}
        </div>
      </div>
      {#if importKind === 'html'}<label class="flex gap-2 items-center text-sm"><input type="checkbox" bind:checked={landscape} disabled={busy} />{$ui('Landscape')}</label>{/if}
      <button type="submit" class="btn btn-secondary" disabled={busy}><Upload class="size-4" />{$ui(importing ? 'Preparing…' : 'Import & place fields')}</button>
    </form>
  </div>

  <div class="grid lg:grid-cols-[13rem_minmax(0,1fr)] gap-7 lg:gap-9">
    <DocumentFolders selected={folder} disabled={busy} {movingDocument} onselect={selectFolder} onchange={refresh} oncloseMove={closeMove} onbusy={value => { folderBusy = value; }} oncapability={(available, canWrite) => { foldersAvailable = available; canManageFolders = canWrite; }} />
  <section aria-label={$ui('Document library')} class="space-y-5 min-w-0">
    <div class="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
      <h2 class="font-medium text-lg">{$ui(folder === 'all' ? 'Your documents' : folder === 'unfiled' ? 'Unfiled documents' : 'Folder documents')}{#if !loading && !listError}<span class="ml-2 text-sm font-normal text-text-muted">{total}</span>{/if}</h2>
      <div class="flex flex-wrap gap-2">
        <label class="relative flex-1 sm:flex-none"><span class="sr-only">{$ui('Search this page')}</span><Search class="absolute left-3 top-2.5 size-4 text-text-muted" /><input bind:value={search} type="search" placeholder={$ui('Search this page')} class="w-full sm:w-56 pl-9 pr-3 py-2 rounded-lg border border-border bg-bg-surface text-sm" /></label>
        <select aria-label={$ui('Filter by status')} bind:value={status} disabled={busy} onchange={changeStatus} class="rounded-lg border border-border bg-bg-surface px-3 py-2 text-sm"><option value="all">{$ui('All statuses')}</option>{#each ['draft', 'sent', 'in_progress', 'completed', 'voided', 'expired'] as value}<option value={value}>{statusLabel(value)}</option>{/each}</select>
      </div>
    </div>
    {#if loading}<div class="card p-10 text-center text-text-secondary" role="status">{$ui('Loading documents…')}</div>
    {:else if listError}<div class="card p-6 space-y-3" role="alert"><p class="text-danger text-sm">{$ui(listError)}</p><button type="button" class="btn btn-secondary" onclick={refresh}><RefreshCw class="size-4" />{$ui('Try again')}</button></div>
    {:else if docs.length === 0 && folder === 'all' && status === 'all'}<div class="card py-14 px-6 text-center"><div class="w-14 h-14 rounded-2xl bg-bg-hover flex items-center justify-center mx-auto mb-4"><FileText class="size-6 text-text-secondary" /></div><h3 class="font-medium text-lg">{$ui('Your first document starts here')}</h3><p class="text-text-secondary text-sm mt-2">{$ui('Create a draft above or import a document you already designed.')}</p></div>
    {:else if visibleDocs.length === 0}<div class="card p-10 text-center text-text-secondary text-sm">{$ui(search.trim() ? 'No documents on this page match your search.' : 'No documents in this selection.')}</div>
    {:else}<div class="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5 sm:gap-6">
      {#each visibleDocs as doc (doc.id)}
        <article class="card overflow-hidden group transition-[box-shadow,border-color,transform] duration-200 hover:-translate-y-0.5 hover:border-text-muted/35 hover:shadow-lg hover:shadow-black/5 focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-4">
          <a href={`/documents/${doc.id}`} aria-label={$ui('Open {name}', { name: doc.name })}>
          {#key `${doc.id}:${doc.updated_at}:${doc.pdf_sha256 ?? ''}`}<DocumentThumbnail item={doc} kind="document" />{/key}
          <div class="p-4 sm:p-5 space-y-4"><div class="flex gap-2 justify-between items-start min-h-10"><h3 class="font-medium text-sm leading-5 line-clamp-2 [overflow-wrap:anywhere]">{doc.name}</h3><ArrowUpRight class="size-4 text-text-muted shrink-0 group-hover:text-text-primary" /></div><div class="flex gap-2 items-center justify-between"><span class={`rounded-full px-2.5 py-1 text-xs font-medium ${statusTone(doc.status)}`}>{statusLabel(doc.status)}</span><span class="text-xs text-text-secondary">{new Date(doc.updated_at).toLocaleDateString($staffLocale === 'sv' ? 'sv-SE' : 'en-GB')}</span></div></div>
          </a>
          {#if foldersAvailable && canManageFolders}<div class="px-4 sm:px-5 pb-4"><button type="button" class="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-40" disabled={busy} aria-label={$ui('Move {name} to a folder', { name: doc.name })} onclick={event => openMove(doc, event.currentTarget)}><FolderInput class="size-3.5" />{$ui('Move to folder')}</button></div>{/if}
        </article>
      {/each}
    </div>{/if}
    {#if !loading && !listError && total > 0}<div class="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs text-text-secondary"><p>{$ui('{start}–{end} of {total} documents', { start: offset + 1, end: Math.min(offset + docs.length, total), total })}{#if search.trim()} · {$ui('{count} matches on this page', { count: visibleDocs.length })}{/if}</p><div class="flex gap-2"><button type="button" class="btn btn-secondary !text-xs !px-3 !py-2" disabled={busy || offset === 0} onclick={() => changePage(Math.max(0, offset - limit))}><ChevronLeft class="size-4" />{$ui('Previous')}</button><button type="button" class="btn btn-secondary !text-xs !px-3 !py-2" disabled={busy || offset + docs.length >= total} onclick={() => changePage(offset + limit)}>{$ui('Next')}<ChevronRight class="size-4" /></button></div></div>{/if}
  </section>
  </div>
</div>
