<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import type { PdfDoc } from '$lib/pdf';
  import type { PdfLoad } from '$lib/pdfLoad';
  import { captureFlarePDFViewError } from '$lib/flare-client';

  type Proof = { key: string; allPagesSeen: boolean };
  let { bytes, proofKey, expectedPages, onProof, ariaLabel = "Saved design preview", onRetirement, onOwner }: {
    bytes: Uint8Array; proofKey: string; expectedPages: number; onProof: (proof: Proof) => void; ariaLabel?: string; onRetirement?: (retirement: Promise<void>) => void; onOwner?: (owner: { retire(): Promise<void> }) => void;
  } = $props();
  const sourceKey = untrack(() => proofKey);
  let loadedPDF = $state.raw<PdfDoc | null>(null);
  let canvas: HTMLCanvasElement;
  let loading = $state(true);
  let rendering = $state(false);
  let page = $state(1);
  let seen = $state<number[]>([]);
  let error = $state<string | null>(null);
  let disposed = false;
  let pdfLoad: PdfLoad<PdfDoc> | null = null;
  let renderRevision = 0;
  const current = () => !disposed && sourceKey === proofKey;
  // Observe each original retirement promise once, including after unmount.
  // Rejected native cleanup remains a real ownership failure; callers still
  // receive the same promise and rejection, without waiting for telemetry.
  const observedPDFRetirements = new WeakSet<Promise<void>>();
  function retirePDF(): Promise<void> {
    const retirement = pdfLoad?.destroy() ?? Promise.resolve();
    if (pdfLoad && !observedPDFRetirements.has(retirement)) {
      observedPDFRetirements.add(retirement);
      void retirement.catch(() => { captureFlarePDFViewError(); });
    }
    return retirement;
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
      await pdf.renderPage(loadedPDF, number, canvas, Math.min(760 / width, 2));
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
    disposed = true; renderRevision++; onProof({ key: sourceKey, allPagesSeen: false });
    retirement = retirePDF();
    onRetirement?.(retirement);
    // Exact-generation stores are released by PdfLoad's shared canvas ledger.
    void retirement.then(() => { loadedPDF = null; }, () => {});
    void retirement.catch(() => {}); return retirement;
  }
  untrack(() => onOwner?.({ retire }));
  onDestroy(() => { void retire(); });
</script>

{#if loading}<p class="text-sm" role="status">Loading verified PDF pages…</p>{/if}
{#if error}<div role="alert" class="text-danger text-sm space-y-2"><p>{error}</p>{#if loadedPDF}<button type="button" class="btn btn-secondary" disabled={rendering} onclick={() => render(page)}>Retry this page</button>{/if}</div>{/if}
<div class="max-w-full overflow-auto border border-border-light rounded-md bg-bg-elevated p-2">
  <canvas width="0" height="0" bind:this={canvas} aria-label={`${ariaLabel}, page ${page}`} class="max-w-full h-auto mx-auto"></canvas>
</div>
{#if loadedPDF}
  <div class="flex flex-wrap items-center justify-between gap-3 text-sm">
    <button type="button" class="btn btn-secondary" disabled={loading || rendering || page <= 1} onclick={() => render(page - 1)}>Previous page</button>
    <p role="status">Page {page} of {expectedPages}{rendering ? ' · Rendering…' : ''}</p>
    <button type="button" class="btn btn-secondary" disabled={loading || rendering || page >= expectedPages} onclick={() => render(page + 1)}>Next page</button>
  </div>
{/if}
