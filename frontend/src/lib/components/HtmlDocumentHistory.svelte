<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { fetchVerifiedHTMLRevisionPDF, getHTMLDocumentHistory, getHTMLRevisionSource, type DocumentResponse, type HTMLDocumentSource, type HTMLHistoryEntry } from '$lib/api/client';
  import { validateHTMLHistory, validateHTMLSource } from '$lib/htmlRevision';
  import VerifiedPDFPages from './VerifiedPDFPages.svelte';

  let { document }: { document: DocumentResponse } = $props();
  const sourceID = untrack(() => document.id), sourceOrg = untrack(() => document.org_id);
  let rows = $state<HTMLHistoryEntry[]>([]);
  let loading = $state(true), opening = $state(false), error = $state<string | null>(null);
  let selected = $state<HTMLDocumentSource | null>(null);
  let bytes = $state.raw<Uint8Array | null>(null);
  let disposed = false, listOperation = 0, selectionOperation = 0;
  let abort: AbortController | null = null;
  const current = () => !disposed && document.id === sourceID && document.org_id === sourceOrg;
  const proofKey = $derived(selected ? `${sourceID}:${selected.materialization_revision}:${selected.html_source_commitment}:${selected.pdf_sha256}` : '');
  // The retained rows are historical observations. Never label one current
  // based on a server flag whose document observation may have since changed.
  const isCurrentRevision = (row: HTMLHistoryEntry) => row.sequence === document.html_materialization_revision
    && row.source_commitment === document.html_source_commitment && row.pdf_sha256 === document.pdf_sha256;

  async function refresh() {
    if (!current() || loading && rows.length > 0) return;
    const operation = ++listOperation;
    loading = true; error = null;
    try {
      const result = await getHTMLDocumentHistory(sourceID);
      if (!current() || operation !== listOperation) return;
      rows = validateHTMLHistory(result.revisions).slice().sort((a, b) => b.sequence - a.sequence);
    } catch (e) { if (current() && operation === listOperation) error = (e as Error).message; }
    finally { if (current() && operation === listOperation) loading = false; }
  }
  async function openRevision(row: HTMLHistoryEntry) {
    if (!current() || !rows.includes(row)) return;
    const operation = ++selectionOperation;
    abort?.abort(); abort = new AbortController();
    const signal = abort.signal;
    selected = null; bytes = null; opening = true; error = null;
    try {
      const source = await getHTMLRevisionSource(sourceID, row.sequence);
      if (!current() || operation !== selectionOperation) return;
      validateHTMLSource(source, sourceID, sourceOrg);
      if (source.materialization_revision !== row.sequence || source.html_source_commitment !== row.source_commitment
          || source.pdf_sha256 !== row.pdf_sha256 || source.page_count !== row.page_count || source.can_edit !== false) {
        throw new Error('This source does not match the immutable history entry. Refresh history before opening it.');
      }
      const verified = await fetchVerifiedHTMLRevisionPDF(sourceID, source, signal);
      if (!current() || operation !== selectionOperation) return;
      selected = source; bytes = verified;
    } catch (e) { if (current() && operation === selectionOperation) error = (e as Error).message; }
    finally { if (current() && operation === selectionOperation) opening = false; }
  }
  function closeRevision() { selectionOperation++; abort?.abort(); selected = null; bytes = null; opening = false; }
  onMount(() => { void refresh(); });
  onDestroy(() => { disposed = true; listOperation++; selectionOperation++; abort?.abort(); });
</script>

<section class="card p-6 mb-6 space-y-4 min-w-0" aria-label="HTML PDF revision history">
  <div class="flex flex-wrap justify-between items-center gap-3"><h2 class="font-display text-lg">PDF revision history</h2>
    <button type="button" class="btn btn-secondary" disabled={loading} onclick={refresh}>Refresh PDF history</button></div>
  <p class="text-sm text-text-secondary">Each revision retains its exact PDF, declared information and wording. Opening an earlier revision is read-only and does not restore, approve or send it.</p>
  {#if loading}<p role="status" class="text-sm">Loading immutable PDF history…</p>{/if}
  {#if error}<p role="alert" class="text-sm text-danger">{error}</p>{/if}
  {#if rows.length}<ol class="space-y-3">
    {#each rows as row (row.sequence)}<li class="border border-border-light rounded-md p-3 space-y-2">
      <p class="text-sm">PDF revision {row.sequence}{isCurrentRevision(row) ? ' · Current PDF' : ''} · {row.page_count} {row.page_count === 1 ? 'page' : 'pages'}</p>
      <p class="text-xs text-text-secondary">{new Date(row.created_at).toLocaleString()}</p>
      {#if row.summary}<p class="text-sm whitespace-pre-wrap break-words">{row.summary}</p>{/if}
      <button type="button" class="btn btn-secondary" onclick={() => openRevision(row)}>Open PDF revision {row.sequence}</button>
    </li>{/each}
  </ol>{:else if !loading}<p class="text-sm">No immutable PDF revisions were returned. Refresh history before proceeding.</p>{/if}
  {#if opening}<p role="status" class="text-sm">Verifying the selected revision’s source and PDF…</p>{/if}
  {#if selected && bytes}<div class="space-y-4 border-t border-border-light pt-4">
    <div class="flex flex-wrap items-center justify-between gap-3"><h3 class="font-display">Read-only PDF revision {selected.materialization_revision}</h3>
      <button type="button" class="btn btn-secondary" onclick={closeRevision}>Close revision</button></div>
    {#key proofKey}<VerifiedPDFPages {bytes} {proofKey} expectedPages={selected.page_count} onProof={() => {}} />{/key}
    <details class="text-sm space-y-3"><summary>Information and wording retained in this revision</summary>
      <dl class="space-y-3 mt-3">{#each selected.values as value (value.name)}<div><dt class="font-medium">{value.name.replaceAll('_', ' ')}</dt><dd class="whitespace-pre-wrap break-words">{value.text || '(blank)'}</dd></div>{/each}
        {#each selected.sections as section (section.name)}<div><dt class="font-medium">{section.name.replaceAll('_', ' ')}</dt><dd class="whitespace-pre-wrap break-words">{section.text || '(blank)'}</dd>
          {#if section.text !== section.default_text}<p class="text-xs text-warning">This wording differs from the approved template.</p>{/if}</div>{/each}</dl>
    </details>
  </div>{/if}
</section>
