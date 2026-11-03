<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Download } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { fetchDocumentDownload, documentDownloadName, type DownloadDocument, type DocumentDownloadKind } from '$lib/documentDownload';
  let { document, blocked = false }: { document: DownloadDocument; blocked?: boolean } = $props();
  let busy = $state(false), error = $state<string | null>(null);
  let disposed = false, revision = 0, controller: AbortController | null = null;
  const urls = new Set<string>();
  function identity() { return JSON.stringify([document.id, document.updated_at, document.status, document.pdf_sha256]); }
  async function download(kind: DocumentDownloadKind = 'pdf') {
    if (disposed || blocked || busy) return;
    const ticket = ++revision, original = identity(), snapshot = { ...document };
    const request = new AbortController(); controller = request; busy = true; error = null;
    const timer = setTimeout(() => request.abort(), 60_000);
    try {
      const blob = await fetchDocumentDownload(snapshot, request.signal, fetch, kind);
      if (disposed || ticket !== revision || request.signal.aborted || original !== identity() || blocked) return;
      const url = URL.createObjectURL(blob); urls.add(url);
      const link = window.document.createElement('a'); link.href = url; link.download = documentDownloadName(snapshot, kind);
      window.document.body.append(link); link.click(); link.remove();
      setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 1_000);
    } catch (cause) {
      if (!disposed && ticket === revision && original === identity()) error = request.signal.aborted ? 'Downloading timed out. Try again.' : (cause as Error).message;
    } finally {
      clearTimeout(timer); if (!disposed && ticket === revision) { busy = false; controller = null; }
    }
  }
  onDestroy(() => { disposed = true; revision++; controller?.abort(); for (const url of urls) URL.revokeObjectURL(url); urls.clear(); });
</script>

<div class="space-y-1">
  <button type="button" class="btn btn-primary" onclick={() => download()} disabled={blocked || busy} aria-busy={busy} aria-describedby={blocked ? 'document-download-help' : undefined}><Download class="size-4" /> {$ui(busy ? 'Preparing PDF…' : document.status === 'completed' && document.requires_signature === true ? 'Download signed PDF' : 'Download PDF')}</button>
  {#if document.status === 'completed'}
    <p class="max-w-xs text-xs text-text-secondary">{$ui(document.requires_signature === true ? 'Signed PDF. Signing details are available in the evidence report.' : 'Completed PDF. Completion details are available in the evidence report.')}</p>
    <button type="button" class="text-sm text-text-secondary underline underline-offset-4 hover:text-text-primary disabled:opacity-50" onclick={() => download('evidence')} disabled={blocked || busy}>{$ui('Download evidence report')}</button>
  {/if}
  {#if blocked}<p id="document-download-help" class="max-w-xs text-xs text-text-secondary">{$ui('Save your changes before downloading.')}</p>{/if}
  {#if error}<p role="alert" class="max-w-xs text-sm text-danger">{$ui(error)}</p>{/if}
</div>
