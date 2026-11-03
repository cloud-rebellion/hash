<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import type { PdfDoc } from '$lib/pdf';
  import type { PdfLoad } from '$lib/pdfLoad';
  import { captureFlarePDFViewError } from '$lib/flare-client';
  import { PDFPaintLane, PDF_FIT_PAGE_HEIGHT, type ThumbnailPaint } from '$lib/pdfPageStrip';
  import PDFPageStrip from './PDFPageStrip.svelte';

  type Proof = { key: string; allPagesSeen: boolean };
  let { bytes, proofKey, expectedPages, onProof, ariaLabel = "Saved design preview", onRetirement, onOwner, translate = (text: string) => text }: {
    bytes: Uint8Array; proofKey: string; expectedPages: number; onProof: (proof: Proof) => void; ariaLabel?: string; onRetirement?: (retirement: Promise<void>) => void; onOwner?: (owner: { retire(): Promise<void> }) => void; translate?: (text: string) => string;
  } = $props();
  const sourceKey = untrack(() => proofKey);
  let loadedPDF = $state.raw<PdfDoc | null>(null);
  let canvas: HTMLCanvasElement;
  let fitPage = $state(true);
  let loading = $state(true);
  let rendering = $state(false);
  let page = $state(1);
  let seen = $state<number[]>([]);
  let error = $state<string | null>(null);
  let disposed = false;
  let pdfLoad: PdfLoad<PdfDoc> | null = null;
  let renderRevision = 0;
  const current = () => !disposed && sourceKey === proofKey;
  const paintLane = new PDFPaintLane(() => { if (!current()) throw new DOMException('The document view was closed.', 'AbortError'); });
  let pdfRenderer: typeof import('$lib/pdf') | null = null;
  const paintThumbnail: ThumbnailPaint<PdfDoc> = (doc, number, canvas, scale, options) => paintLane.paint('thumbnail', () => { if (!pdfRenderer) throw new Error('The PDF is not loaded.'); return pdfRenderer.renderPage(doc, number, canvas, scale, options); }, options.signal);
  // Observe each original retirement promise once, including after unmount.
  // Rejected native cleanup remains a real ownership failure; callers still
  // receive the same promise and rejection, without waiting for telemetry.
  const observedPDFRetirements = new WeakSet<Promise<void>>();
  function retirePDF(): Promise<void> {
    paintLane.close();
    const retirement = pdfLoad?.destroy() ?? Promise.resolve();
    if (pdfLoad && !observedPDFRetirements.has(retirement)) {
      observedPDFRetirements.add(retirement);
      void retirement.catch(() => { captureFlarePDFViewError(); });
    }
    return retirement;
  }
  function setPageFit(fit: boolean) {
    if (typeof fit !== 'boolean' || !current() || loading || rendering || error) return;
    fitPage = fit;
  }
  async function render(number: number) {
    if (!current() || !loadedPDF || rendering || number < 1 || number > expectedPages) return;
    rendering = true; error = null;
    onProof({ key: sourceKey, allPagesSeen: false });
    const revision = ++renderRevision;
    try {
      const pdf = await import('$lib/pdf');
      const width = await pdf.unscaledWidth(loadedPDF, number);
      if (!current() || revision !== renderRevision) return;
      await paintLane.paint('page', () => pdf.renderPage(loadedPDF!, number, canvas, Math.min(760 / width, 2)));
      if (!current() || revision !== renderRevision) return;
      page = number; if (!seen.includes(number)) seen = [...seen, number];
      onProof({ key: sourceKey, allPagesSeen: seen.length === expectedPages });
    } catch (e) {
      if (current() && revision === renderRevision) {
        if (!(e instanceof Error && (e.name === 'AbortError' || e.name === 'RenderingCancelledException'))) captureFlarePDFViewError();
        error = (e as Error).message; onProof({ key: sourceKey, allPagesSeen: false });
      }
    } finally { if (current() && revision === renderRevision) rendering = false; }
  }
  onMount(async () => {
    let pdfOperation = true;
    try {
      const pdf = await import('$lib/pdf');
      if (!current()) return;
      pdfRenderer = pdf;
      pdfLoad = pdf.startPdfData(bytes.slice());
      const loaded = await pdfLoad.promise;
      pdfOperation = false;
      if (!current()) { await retirePDF(); return; }
      if (!Number.isInteger(expectedPages) || expectedPages < 1 || expectedPages > 500 || loaded.numPages !== expectedPages) {
        throw new Error('The PDF page count does not match the preview. Generate a new preview.');
      }
      loadedPDF = loaded;
      await render(1);
    } catch (e) {
      const unexpectedPDF = pdfOperation && !(e instanceof Error && (e.name === 'AbortError' || e.name === 'RenderingCancelledException'));
      let retirementFailed = false;
      try { await retirePDF(); } catch { retirementFailed = true; }
      if (current()) {
        if (unexpectedPDF) captureFlarePDFViewError();
        error = retirementFailed ? 'The PDF preview could not be closed. Refresh this page before trying again.' : (e as Error).message;
        onProof({ key: sourceKey, allPagesSeen: false });
      }
    }
    finally { if (current()) loading = false; }
  });
  let retirement: Promise<void> | null = null;
  export function retire(): Promise<void> {
    if (retirement) return retirement;
    disposed = true; paintLane.close(); renderRevision++; onProof({ key: sourceKey, allPagesSeen: false });
    retirement = retirePDF();
    onRetirement?.(retirement);
    // Exact-generation stores are released by PdfLoad's shared canvas ledger.
    void retirement.then(() => { loadedPDF = null; }, () => {});
    void retirement.catch(() => {}); return retirement;
  }
  untrack(() => onOwner?.({ retire }));
  onDestroy(() => { void retire(); });
</script>

{#if loading}<p class="text-sm" role="status">{translate('Loading verified PDF pages…')}</p>{/if}
{#if error}<div role="alert" class="text-danger text-sm space-y-2"><p>{translate(error)}</p>{#if loadedPDF}<button type="button" class="btn btn-secondary" disabled={rendering} onclick={() => render(page)}>{translate('Retry this page')}</button>{/if}</div>{/if}
<div class="max-w-full overflow-auto border border-border-light rounded-md bg-bg-elevated p-2">
  <div class="flex justify-end gap-1 mb-3" role="group" aria-label={translate('Page size')}>
    <button type="button" class="btn text-xs {fitPage ? 'btn-primary' : 'btn-secondary'}" aria-pressed={fitPage} disabled={loading || rendering || !!error} onclick={() => setPageFit(true)}>{translate('Fit page')}</button>
    <button type="button" class="btn text-xs {!fitPage ? 'btn-primary' : 'btn-secondary'}" aria-pressed={!fitPage} disabled={loading || rendering || !!error} onclick={() => setPageFit(false)}>{translate('Larger page')}</button>
  </div>
  <canvas width="0" height="0" bind:this={canvas} aria-label={`${ariaLabel}, ${translate('page')} ${page}`} class="max-w-full h-auto mx-auto" style:max-height={fitPage ? PDF_FIT_PAGE_HEIGHT : undefined}></canvas>
</div>
{#if loadedPDF}
  <PDFPageStrip doc={loadedPDF} activePage={page} paint={paintThumbnail} onSelect={render} busy={rendering} disabled={loading || rendering} {translate} />
{/if}
