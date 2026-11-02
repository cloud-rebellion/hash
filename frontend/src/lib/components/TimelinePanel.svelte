<script lang="ts">
  import { ui, staffLocale } from '$lib/staffPreferences';
  import { onMount } from 'svelte';
  import { getTimeline, timelineCsvURL, type TimelineEntry } from '$lib/api/client';
  import { History, Download, RefreshCw } from 'lucide-svelte';

  type Props = {
    documentID: string;
  };

  let { documentID }: Props = $props();

  let entries = $state<TimelineEntry[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  async function refresh() {
    loading = true;
    try {
      const res = await getTimeline(documentID);
      entries = res.entries ?? [];
      error = null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  // "document.sent" -> "Document sent", "recipient.viewed" -> "Recipient viewed".
  function humanize(kind: string): string {
    const cleaned = kind.replace(/[._]/g, ' ').trim();
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  }

  function actor(e: TimelineEntry): string {
    return e.actor_email || (e.actor_user_id ? 'A team member' : 'System');
  }

  function ts(value: string): string {
    return value ? new Date(value).toLocaleString() : '';
  }
</script>

<section class="card p-5 mb-6">
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <History class="size-4" /> {$ui("Audit timeline")}
    </h2>
    <div class="flex gap-2">
      <button class="btn btn-secondary text-xs" onclick={refresh} disabled={loading}>
        <RefreshCw class="size-3" /> {$ui("Refresh")}
      </button>
      <a class="btn btn-secondary text-xs" href={timelineCsvURL(documentID)} download>
        <Download class="size-3" /> {$ui("CSV")}
      </a>
    </div>
  </div>

  <p class="text-sm text-text-secondary mb-4 leading-relaxed">
    {$ui("Every lifecycle event is hash-chained and tamper-evident. For a successfully completed ceremony, the document-scoped event set is committed into the signed audit certificate.")}
  </p>

  {#if error}
    <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">
      {$ui(error)}
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted text-sm">{$ui("Loading...")}</p>
  {:else if entries.length === 0}
    <p class="text-text-muted text-sm">{$ui("No events recorded yet.")}</p>
  {:else}
    <ol class="relative border-l border-border-light ml-2">
      {#each entries as e (e.id)}
        <li class="ml-4 pb-4">
          <span
            class="absolute -left-[5px] mt-1.5 size-2.5 rounded-full bg-accent border border-bg-surface"
          ></span>
          <div class="flex items-baseline justify-between gap-3 flex-wrap">
            <span class="text-sm font-medium">
              {$ui(humanize(e.kind))}
              {#if e.occurrences > 1}
                <span class="text-xs text-text-muted">{$ui("x")}{e.occurrences}</span>
              {/if}
            </span>
            <span class="text-xs text-text-muted font-mono">{e.created_at ? new Date(e.created_at).toLocaleString($staffLocale) : ''}</span>
          </div>
          <div class="text-xs text-text-muted">
            {$ui(actor(e))}{#if e.ip}{' · '}{e.ip}{/if}
          </div>
        </li>
      {/each}
    </ol>
  {/if}
</section>
