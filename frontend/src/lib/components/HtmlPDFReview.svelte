<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { fetchVerifiedDocumentPDF, reviewHTMLDocument, type DocumentResponse } from '$lib/api/client';
  import type { PdfDoc } from '$lib/pdf';

  let { document, canReview, onReviewed, onRefresh }: {
    document: DocumentResponse;
    canReview: boolean;
    onReviewed: (updated: DocumentResponse) => void;
    onRefresh: () => Promise<void> | void;
  } = $props();
  const sourceID = untrack(() => document.id);
  const sourceStamp = untrack(() => document.updated_at);
  const sourceSHA = untrack(() => document.pdf_sha256 ?? '');
  let loading = $state(true);
  let rendering = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let pageNumber = $state(1);
  let pageCount = $state(0);
  let acknowledged = $state(false);
  let seenPages = $state<number[]>([]);
  let canvas: HTMLCanvasElement;
  let activePDF = $state.raw<PdfDoc | null>(null);
  let disposed = false;
  let revision = 0;
  const abort = new AbortController();
  const current = () => !disposed && document.id === sourceID && document.updated_at === sourceStamp && document.pdf_sha256 === sourceSHA;
  const allPagesSeen = $derived(pageCount > 0 && seenPages.length === pageCount);

  async function renderPage(number: number) {
    if (!current() || !activePDF || busy || rendering) return;
    rendering = true;
    error = null;
    const observed = ++revision;
    try {
      const pdf = await import('$lib/pdf');
      const width = await pdf.unscaledWidth(activePDF, number);
      if (!current() || observed !== revision) return;
      await pdf.renderPage(activePDF, number, canvas, Math.min(760 / width, 2));
      if (!current() || observed !== revision) return;
      pageNumber = number;
      if (!seenPages.includes(number)) seenPages = [...seenPages, number];
    } catch (e) {
      if (current() && observed === revision) error = (e as Error).message;
    } finally {
      if (current() && observed === revision) rendering = false;
    }
  }
  async function loadPreview() {
    if (!current() || busy || activePDF) return;
    loading = true;
    error = null;
    try {
      const bytes = await fetchVerifiedDocumentPDF(sourceID, sourceSHA, abort.signal);
      if (!current()) return;
      const pdf = await import('$lib/pdf');
      if (!current()) return;
      const loaded = await pdf.loadPdfData(bytes);
      if (!current()) { void loaded.loadingTask.destroy().catch(() => {}); return; }
      if (loaded.numPages < 1 || loaded.numPages > 500) {
        void loaded.loadingTask.destroy().catch(() => {});
        throw new Error('This PDF cannot be reviewed here. Ask its owner to inspect it.');
      }
      activePDF = loaded;
      pageCount = loaded.numPages;
      await renderPage(1);
    } catch (e) {
      if (current()) error = (e as Error).message;
    } finally {
      if (current()) loading = false;
    }
  }
  async function approve() {
    if (!current() || !canReview || !document.has_html_source || !document.html_review_required
        || loading || rendering || busy || error || !activePDF || !allPagesSeen || !acknowledged) return;
    busy = true;
    error = null;
    try {
      const updated = await reviewHTMLDocument(sourceID, sourceStamp, sourceSHA);
      if (!current()) return;
      if (updated.id !== sourceID || updated.org_id !== document.org_id || updated.source_kind !== 'pdf'
          || updated.status !== 'draft' || !updated.has_html_source || updated.html_review_required || updated.pdf_sha256 !== sourceSHA) {
        throw new Error('The review response does not match this PDF. Refresh the document before continuing.');
      }
      onReviewed(updated);
    } catch (e) {
      if (current()) { error = (e as Error).message; acknowledged = false; }
    } finally {
      if (current()) busy = false;
    }
  }
  onMount(() => { void loadPreview(); });
  onDestroy(() => {
    disposed = true; revision++; abort.abort();
    if (activePDF) void activePDF.loadingTask.destroy().catch(() => {});
  });
</script>

<section class="card p-6 mb-6 space-y-4" aria-label="Review generated PDF">
  <div>
    <h2 class="font-display text-lg">Review the generated PDF</h2>
    <p class="text-sm text-text-secondary mt-1">Check the printed information, wording, page breaks and layout before sending. This review applies to this exact PDF.</p>
  </div>
  {#if loading}<p role="status" class="text-sm">Loading and verifying the PDF…</p>{/if}
  {#if error}
    <p role="alert" class="text-sm text-danger">{error}</p>
    {#if !activePDF}<button type="button" class="btn btn-secondary" disabled={loading} onclick={loadPreview}>Retry PDF preview</button>{/if}
    {#if activePDF}<button type="button" class="btn btn-secondary" disabled={rendering || busy} onclick={() => renderPage(pageNumber)}>Retry this page</button>{/if}
    <button type="button" class="btn btn-secondary" disabled={busy} onclick={onRefresh}>Refresh document</button>
  {/if}
  <div class="overflow-auto border border-border-light rounded-md bg-bg-elevated p-2">
    <canvas bind:this={canvas} aria-label={`Generated PDF, page ${pageNumber}`} class="max-w-full h-auto mx-auto"></canvas>
  </div>
  {#if pageCount > 0}
    <div class="flex flex-wrap items-center justify-between gap-3 text-sm">
      <button type="button" class="btn btn-secondary" disabled={loading || rendering || busy || pageNumber <= 1} onclick={() => renderPage(pageNumber - 1)}>Previous page</button>
      <p role="status">Page {pageNumber} of {pageCount}{rendering ? ' · Rendering…' : ''}</p>
      <button type="button" class="btn btn-secondary" disabled={loading || rendering || busy || pageNumber >= pageCount} onclick={() => renderPage(pageNumber + 1)}>Next page</button>
    </div>
  {/if}
  {#if document.html_review_required}
    {#if canReview}
      <label class="flex gap-3 items-start text-sm">
        <input type="checkbox" bind:checked={acknowledged} disabled={loading || rendering || busy || !allPagesSeen || !!error} class="mt-1" />
        <span>I have reviewed every page of this PDF and approve its printed content and layout.</span>
      </label>
      {#if !allPagesSeen && pageCount > 0}<p class="text-sm text-text-secondary">Open every page before approving this PDF.</p>{/if}
      <button type="button" class="btn btn-primary" disabled={loading || rendering || busy || !allPagesSeen || !acknowledged || !!error} onclick={approve}>{busy ? 'Recording review…' : 'Approve this PDF for sending'}</button>
    {:else}
      <p class="text-sm" role="note">The document's sender or an owner must review this PDF before it can be sent.</p>
    {/if}
  {:else}
    <p class="text-sm text-success" role="status">This exact PDF has been reviewed. Add recipients and any required signature fields below before sending.</p>
  {/if}
</section>
