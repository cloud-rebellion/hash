<script lang="ts">
  import { ui, staffLocale } from '$lib/staffPreferences';
  import { onMount } from 'svelte';
  import {
    listEnvelopeChildren,
    getEnvelopeManifest,
    detachFromEnvelope,
    promoteToEnvelope,
    type EnvelopeChild,
    type EnvelopeManifest,
  } from '$lib/api/client';
  import { Layers, Trash2, Sparkles, ShieldCheck } from 'lucide-svelte';

  type Props = {
    documentID: string;
    isEnvelope: boolean;
  };

  let { documentID, isEnvelope }: Props = $props();

  let children = $state<EnvelopeChild[]>([]);
  let manifest = $state<EnvelopeManifest | null>(null);
  let loading = $state(false);
  let error = $state<string | null>(null);
  let promoting = $state(false);

  async function refresh() {
    if (!isEnvelope) return;
    loading = true;
    try {
      const [c, m] = await Promise.all([
        listEnvelopeChildren(documentID),
        getEnvelopeManifest(documentID).catch(() => null),
      ]);
      children = c.children ?? [];
      manifest = m;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(refresh);

  async function promote() {
    if (!confirm('Promote this document to an envelope? You can attach other documents as children afterwards.')) return;
    promoting = true;
    try {
      await promoteToEnvelope(documentID);
      window.location.reload();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      promoting = false;
    }
  }

  async function detach(childID: string) {
    if (!confirm('Detach this child from the envelope?')) return;
    try {
      await detachFromEnvelope(documentID, childID);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }
</script>

<section class="card p-5 mb-6">
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <Layers class="size-4" /> {$ui("Multi-document signing")}
    </h2>
    {#if !isEnvelope}
      <button class="btn btn-secondary text-xs" onclick={promote} disabled={promoting}>
        <Sparkles class="size-3" /> {$ui(promoting ? 'Creating package…' : 'Create signing package')}
      </button>
    {/if}
  </div>

  {#if !isEnvelope}
    <p class="text-sm text-text-secondary leading-relaxed">
      {$ui("Group separate Hash documents so recipients sign them together. To include supporting PDFs such as an NDA or DPA alongside the main document, use Attachments.")}
    </p>
  {:else}
    {#if error}
      <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">{$ui(error)}</div>
    {/if}
    {#if loading}
      <p class="text-text-muted text-sm">{$ui("Loading...")}</p>
    {:else if children.length === 0}
      <p class="text-text-muted text-sm">{$ui("No children attached yet. Use the MCP tool")} <code class="font-mono">attach_to_envelope</code> {$ui("or the REST attach endpoint with a child document id.")}</p>
    {:else}
      <ul class="divide-y divide-border-light mb-4">
        {#each children as c (c.id)}
          <li class="py-2 flex items-center gap-3">
            <span class="text-xs font-mono w-8 text-text-muted">#{c.envelope_position}</span>
            <a class="flex-1 text-sm hover:underline" href="/documents/{c.id}">{c.name || c.id}</a>
            <span class="text-xs font-mono uppercase tracking-widest text-text-muted">{c.status}</span>
            <button class="btn btn-secondary text-xs" onclick={() => detach(c.id)}>
              <Trash2 class="size-3" />
            </button>
          </li>
        {/each}
      </ul>
    {/if}

    {#if manifest}
      <div class="p-3 rounded-md border border-border-light bg-bg-elevated text-xs">
        <div class="flex items-center gap-2 mb-1">
          <ShieldCheck class="size-3" />
          <span class="font-mono uppercase tracking-widest">{$ui("Manifest hash")}</span>
        </div>
        <code class="font-mono text-[11px] break-all">{manifest.manifest_sha256}</code>
        <p class="text-text-muted mt-1">
          {$ui("This identifies the saved set of documents and their content. Changing that set changes its identifier. The evidence report records the selected versions.")}
        </p>
      </div>
    {/if}
  {/if}
</section>
