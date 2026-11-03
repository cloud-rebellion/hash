<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import type { PdfDoc } from '$lib/pdf';
  import { PDFThumbnailWindow, pdfThumbnailPages, type ThumbnailPaint, type ThumbnailState } from '$lib/pdfPageStrip';
  import { captureFlarePDFViewError } from '$lib/flare-client';

  let { doc, activePage, paint, onSelect, disabled = false, busy = false, translate = (text: string) => text }: {
    doc: PdfDoc; activePage: number; paint: ThumbnailPaint<PdfDoc>; onSelect: (page: number) => void;
    disabled?: boolean; busy?: boolean; translate?: (text: string) => string;
  } = $props();
  const source = untrack(() => doc);
  const slots = Array.from({ length: Math.min(source.numPages, 5) }, (_, index) => index);
  const numbers = $derived(pdfThumbnailPages(activePage, source.numPages));
  let states = $state<Record<number, { page: number; state: ThumbnailState }>>({});
  let error = $state(false), disposed = false, reported = false;
  const canvases: Record<number, HTMLCanvasElement> = {};
  let thumbnails: PDFThumbnailWindow<PdfDoc> | null = null;
  function failure(reason: unknown) {
    if (disposed || source !== doc) return;
    if (!(reason instanceof Error && (reason.name === 'AbortError' || reason.name === 'RenderingCancelledException')) && !reported) { reported = true; captureFlarePDFViewError(); }
    error = true;
  }
  function select(page: number) { if (!disposed && source === doc && !disabled && Number.isInteger(page) && page >= 1 && page <= source.numPages) onSelect(page); }
  $effect(() => { const selected = activePage; untrack(() => thumbnails?.select(selected)); });
  onMount(async () => {
    try {
      const pdf = await import('$lib/pdf');
      if (disposed || source !== doc) return;
      thumbnails = new PDFThumbnailWindow(source, {
        current: () => { if (disposed || source !== doc) throw new DOMException('The document view was closed.', 'AbortError'); },
        geometry: pdf.pageGeometry, canvas: slot => canvases[slot], paint,
        recycle: pdf.recyclePage, resident: pdf.pageIsResident,
        state: (slot, page, state) => { if (!disposed && source === doc) states = { ...states, [slot]: { page, state } }; }, failed: failure,
      });
      thumbnails.select(untrack(() => activePage));
    } catch (reason) { failure(reason); }
  });
  onDestroy(() => { disposed = true; const closing = thumbnails?.stop(); if (closing) void closing.catch(failure); });
</script>

<nav class="mt-4 space-y-2" aria-label={translate('Document pages')}>
  <div class="flex items-center justify-between gap-3 text-xs text-text-secondary">
    <button type="button" class="btn btn-secondary text-xs" disabled={disabled || activePage <= 1} onclick={() => select(activePage - 1)}>{translate('Previous page')}</button>
    <p role="status">{translate('Page')} {activePage} {translate('of')} {source.numPages}{busy ? ' · ' + translate('Rendering…') : ''}</p>
    <button type="button" class="btn btn-secondary text-xs" disabled={disabled || activePage >= source.numPages} onclick={() => select(activePage + 1)}>{translate('Next page')}</button>
  </div>
  <div class="flex justify-center gap-2 overflow-x-auto py-2">
    {#each slots as slot (slot)}
      {@const number = numbers[slot]}
      {@const state = states[slot]?.page === number ? states[slot].state : 'loading'}
      <button type="button" class="thumbnail shrink-0 rounded-lg border border-border bg-bg-elevated p-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent" class:selected={activePage === number}
        disabled={disabled} aria-label={`${translate('Show page')} ${number}`} aria-current={activePage === number ? 'page' : undefined} onclick={() => select(number)}>
        <span class="relative flex h-40 w-28 items-center justify-center overflow-hidden rounded-sm bg-bg-surface">
          <canvas width="0" height="0" bind:this={canvases[slot]} aria-hidden="true" class="max-h-full max-w-full" style:visibility={state === 'ready' && !error ? 'visible' : 'hidden'}></canvas>
          {#if state !== 'ready' || error}<span class="absolute inset-2 flex items-center justify-center text-center text-[10px] leading-relaxed text-text-muted">{translate(error || state === 'released' ? 'Select to view this page' : 'Rendering thumbnail…')}</span>{/if}
        </span>
        <span class="mt-2 block text-xs font-medium text-text-primary">{translate('Page')} {number}</span>
      </button>
    {/each}
  </div>
  {#if error}<p class="text-xs text-text-secondary" role="status">{translate('Thumbnails are unavailable. Page controls still open the full PDF page.')}</p>{/if}
</nav>

<style>
  .thumbnail.selected { border-color: var(--color-accent); box-shadow: 0 0 0 1px var(--color-accent); }
  .thumbnail:disabled { opacity: 0.65; }
</style>
