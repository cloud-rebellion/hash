<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import type { PdfDoc } from '$lib/pdf';

  type Proof = { key: string; allPagesSeen: boolean };
  let { bytes, proofKey, expectedPages, onProof }: {
    bytes: Uint8Array; proofKey: string; expectedPages: number; onProof: (proof: Proof) => void;
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
  let renderRevision = 0;
  const current = () => !disposed && sourceKey === proofKey;
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
      if (current() && revision === renderRevision) { error = (e as Error).message; onProof({ key: sourceKey, allPagesSeen: false }); }
    } finally { if (current() && revision === renderRevision) rendering = false; }
  }
  onMount(async () => {
    try {
      const pdf = await import('$lib/pdf');
      if (!current()) return;
      const loaded = await pdf.loadPdfData(bytes.slice());
      if (!current()) { void loaded.loadingTask.destroy().catch(() => {}); return; }
      if (!Number.isInteger(expectedPages) || expectedPages < 1 || expectedPages > 500 || loaded.numPages !== expectedPages) {
        void loaded.loadingTask.destroy().catch(() => {});
        throw new Error('The PDF page count does not match the preview. Generate a new preview.');
      }
      loadedPDF = loaded;
      await render(1);
    } catch (e) { if (current()) { error = (e as Error).message; onProof({ key: sourceKey, allPagesSeen: false }); } }
    finally { if (current()) loading = false; }
  });
  onDestroy(() => { disposed = true; renderRevision++; if (loadedPDF) void loadedPDF.loadingTask.destroy().catch(() => {}); });
</script>

{#if loading}<p class="text-sm" role="status">Loading verified PDF pages…</p>{/if}
{#if error}<div role="alert" class="text-danger text-sm space-y-2"><p>{error}</p>{#if loadedPDF}<button type="button" class="btn btn-secondary" disabled={rendering} onclick={() => render(page)}>Retry this page</button>{/if}</div>{/if}
<div class="max-w-full overflow-auto border border-border-light rounded-md bg-bg-elevated p-2">
  <canvas bind:this={canvas} aria-label={`Saved design preview, page ${page}`} class="max-w-full h-auto mx-auto"></canvas>
</div>
{#if loadedPDF}
  <div class="flex flex-wrap items-center justify-between gap-3 text-sm">
    <button type="button" class="btn btn-secondary" disabled={loading || rendering || page <= 1} onclick={() => render(page - 1)}>Previous page</button>
    <p role="status">Page {page} of {expectedPages}{rendering ? ' · Rendering…' : ''}</p>
    <button type="button" class="btn btn-secondary" disabled={loading || rendering || page >= expectedPages} onclick={() => render(page + 1)}>Next page</button>
  </div>
{/if}
