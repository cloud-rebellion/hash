<script lang="ts">
  import { onDestroy } from 'svelte';
  import { ui } from '$lib/staffPreferences';
  import { listDocuments, type DocumentResponse } from '$lib/api/client';
  import AgentTokensPanel from './AgentTokensPanel.svelte';
  import { ChevronLeft, ChevronRight, KeyRound } from 'lucide-svelte';

  let open = $state(false), loading = $state(false);
  let documents = $state<DocumentResponse[]>([]), total = $state(0), offset = $state(0);
  let selected = $state(''), error = $state<string | null>(null);
  const limit = 25;
  let disposed = false, revision = 0, controller: AbortController | null = null;

  async function load(next = offset) {
    if (disposed || next < 0) return;
    const ticket = ++revision;
    controller?.abort(); const request = new AbortController(); controller = request;
    loading = true; error = null; selected = ''; documents = [];
    const timer = setTimeout(() => request.abort(), 15_000);
    try {
      const result = await listDocuments({ limit, offset: next }, request.signal);
      if (disposed || ticket !== revision || request.signal.aborted) return;
      if (!Array.isArray(result.documents) || !Number.isSafeInteger(result.total) || result.total < 0) throw new Error('Unable to load documents.');
      documents = result.documents; total = result.total; offset = next;
    } catch (cause) {
      if (!disposed && ticket === revision) error = request.signal.aborted ? 'Loading documents timed out. Try again.' : 'Unable to load documents.';
    } finally {
      clearTimeout(timer);
      if (!disposed && ticket === revision) { loading = false; controller = null; }
    }
  }
  function toggle() { open = !open; if (open) void load(); else { revision++; controller?.abort(); controller = null; loading = false; selected = ''; documents = []; } }
  onDestroy(() => { disposed = true; revision++; controller?.abort(); });
</script>

<section class="card mt-8 overflow-hidden" aria-labelledby="document-ai-access-title">
  <button type="button" class="flex w-full items-start gap-3 p-5 text-left hover:bg-bg-hover" aria-expanded={open} aria-controls="document-ai-access-settings" onclick={toggle}>
    <KeyRound class="mt-1 size-4 shrink-0" />
    <span class="min-w-0 flex-1"><span id="document-ai-access-title" class="block font-medium">{$ui('Restrict AI access to one document')}</span><span class="mt-1 block text-sm text-text-secondary">{$ui('Optional: create an agent token that can access only the document you choose.')}</span></span>
    <span class="text-sm text-text-secondary">{$ui(open ? 'Close' : 'Manage')}</span>
  </button>
  {#if open}
    <div id="document-ai-access-settings" class="space-y-4 border-t border-border p-5">
      <p class="text-sm text-text-secondary">{$ui('Your workspace API key already connects MCP. A document token is only needed when an agent should have access to one document.')}</p>
      {#if error}<p class="text-sm text-danger" role="alert">{$ui(error)}</p><button type="button" class="btn btn-secondary" onclick={() => load()}>{$ui('Retry')}</button>
      {:else if loading}<p class="text-sm text-text-secondary" role="status">{$ui('Loading documents…')}</p>
      {:else if documents.length === 0}<p class="text-sm text-text-secondary">{$ui('No documents on this page.')}</p>
      {:else}
        <label for="document-ai-access-picker" class="block text-sm font-medium">{$ui('Document')}</label>
        <select id="document-ai-access-picker" bind:value={selected} class="block w-full rounded-lg border border-border bg-bg-elevated px-3 py-2 text-sm">
          <option value="">{$ui('Choose a document')}</option>
          {#each documents as document (document.id)}<option value={document.id}>{document.name}</option>{/each}
        </select>
      {/if}
      <div class="flex items-center justify-between gap-3">
        <p class="text-xs text-text-secondary">{$ui('Documents {from}–{to} of {total}', { from: total ? offset + 1 : 0, to: Math.min(offset + documents.length, total), total })}</p>
        <div class="flex gap-2"><button type="button" class="btn btn-secondary" aria-label={$ui('Previous page')} disabled={loading || offset === 0} onclick={() => load(Math.max(0, offset - limit))}><ChevronLeft class="size-4" /></button><button type="button" class="btn btn-secondary" aria-label={$ui('Next page')} disabled={loading || offset + limit >= total} onclick={() => load(offset + limit)}><ChevronRight class="size-4" /></button></div>
      </div>
      {#if selected && documents.some(document => document.id === selected)}
        {#key selected}<AgentTokensPanel documentID={selected} />{/key}
      {/if}
    </div>
  {/if}
</section>
