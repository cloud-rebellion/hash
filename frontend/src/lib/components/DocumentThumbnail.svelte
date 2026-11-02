<script lang="ts">
  import { onMount, onDestroy, untrack } from 'svelte';
  import { FileText } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { getDocument, getTemplate, fetchVerifiedDocumentPDF, fetchVerifiedTemplatePDF } from '$lib/api/client';
  import { previewLines, thumbnailTurn, type ThumbnailItem } from '$lib/documentThumbnail';
  import type { PdfDoc } from '$lib/pdf';
  import type { PdfLoad } from '$lib/pdfLoad';
  import { captureFlarePDFViewError } from '$lib/flare-client';

  let { item, kind }: { item: ThumbnailItem; kind: 'document' | 'template' } = $props();
  const source = untrack(() => ({ ...item }));
  const sourceKind = untrack(() => kind);
  let container: HTMLDivElement;
  let canvas: HTMLCanvasElement;
  let imageURL = $state('');
  let lines = $state<string[]>([]);
  let previewState = $state<'waiting' | 'loading' | 'ready' | 'empty' | 'unavailable'>('waiting');
  let closed = false, started = false;
  const controller = new AbortController();
  let load: PdfLoad<PdfDoc> | null = null;
  let observer: IntersectionObserver | null = null;
  let work: Promise<void> | null = null;

  async function retire(): Promise<void> {
    try { await load?.destroy(); }
    catch { captureFlarePDFViewError(); }
  }
  async function renderPreview() {
    if (started || closed) return;
    started = true; previewState = 'loading'; observer?.disconnect();
    let release: (() => void) | null = null;
    let pdfOperation = false;
    try {
      release = await thumbnailTurn(controller.signal);
      if (closed) return;
      if (source.source_kind === 'pdf' && source.pdf_sha256) {
        const bytes = sourceKind === 'document'
          ? await fetchVerifiedDocumentPDF(source.id, source.pdf_sha256, controller.signal)
          : await fetchVerifiedTemplatePDF(source.id, source.version ?? 0, source.pdf_sha256, controller.signal);
        const pdf = await import('$lib/pdf');
        if (closed) return;
        pdfOperation = true;
        load = pdf.startPdfData(bytes);
        const doc = await load.promise;
        if (closed) return;
        const page = await doc.getPage(1);
        const natural = page.getViewport({ scale: 1 });
        if (![natural.width, natural.height].every(value => Number.isFinite(value) && value > 0)) throw new Error('Invalid preview dimensions');
        if (closed) return;
        await pdf.renderPage(doc, 1, canvas, Math.min(280 / natural.width, 360 / natural.height, 1));
        if (closed) return;
        const blob = await new Promise<Blob | null>(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.82));
        if (!blob) throw new Error('Preview image unavailable');
        if (closed) return;
        imageURL = URL.createObjectURL(blob); previewState = 'ready'; pdfOperation = false;
      } else {
        let detail = source;
        if (!source.blocks_json && !source.html_master_json) detail = sourceKind === 'document'
          ? await getDocument(source.id, controller.signal) : await getTemplate(source.id, controller.signal);
        if (closed) return;
        if (detail.id !== source.id || detail.source_kind !== source.source_kind
          || (sourceKind === 'template' && (detail.version !== source.version || detail.content_sha256 !== source.content_sha256))
          || (sourceKind === 'document' && source.updated_at && detail.updated_at !== source.updated_at)) throw new Error('Preview source changed');
        lines = previewLines(detail.source_kind === 'html' ? detail.html_master_json : detail.blocks_json, detail.source_kind === 'html');
        previewState = lines.length ? 'ready' : 'empty';
      }
    } catch (error) {
      if (!closed && !(error instanceof Error && (error.name === 'AbortError' || error.name === 'RenderingCancelledException'))) {
        previewState = 'unavailable';
        if (pdfOperation) captureFlarePDFViewError();
      }
    } finally { await retire(); release?.(); }
  }
  onMount(() => {
    if (typeof IntersectionObserver === 'undefined') { work = renderPreview(); return; }
    observer = new IntersectionObserver(entries => { if (entries.some(entry => entry.isIntersecting)) work = renderPreview(); }, { rootMargin: '120px' });
    observer.observe(container);
  });
  onDestroy(() => {
    closed = true; observer?.disconnect(); controller.abort();
    if (imageURL) URL.revokeObjectURL(imageURL);
    void retire();
    // Observe the original job even when navigation removes its card.
    void work?.catch(() => {});
  });
</script>

<div bind:this={container} class="relative h-56 overflow-hidden border-b border-border-light bg-bg-hover p-5 flex items-start justify-center" aria-label={$ui('Preview of {name}', { name: source.name })}>
  {#if imageURL}
    <img src={imageURL} alt={$ui('First page of {name}', { name: source.name })} class="w-40 h-auto shadow-md rounded-sm" />
  {:else if lines.length}
    <div class="w-40 min-h-56 bg-white text-zinc-800 shadow-md p-4 rounded-sm overflow-hidden" aria-label={$ui('Content preview')}>
      {#each lines as line, index}<p class={index === 0 ? 'text-[9px] leading-3 font-semibold mb-3' : 'text-[6px] leading-[10px] mb-2'}>{line}</p>{/each}
    </div>
    <span class="absolute bottom-2 right-3 rounded bg-bg-surface/95 px-2 py-1 text-[10px] text-text-secondary">{$ui('Content preview')}</span>
  {:else}
    <div class="w-40 h-52 rounded-sm border border-border bg-bg-surface flex flex-col items-center justify-center gap-3 text-text-muted px-3 text-center">
      <FileText class="size-7" /><span class="text-xs">{$ui(previewState === 'waiting' || previewState === 'loading' ? 'Loading preview…' : previewState === 'unavailable' ? 'Preview unavailable' : 'Blank document')}</span>
    </div>
  {/if}
  <canvas bind:this={canvas} width="0" height="0" class="hidden" aria-hidden="true"></canvas>
</div>
