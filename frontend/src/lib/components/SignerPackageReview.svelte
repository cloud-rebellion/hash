<script lang="ts">
  import { onMount, onDestroy, tick, untrack } from 'svelte';
  import VerifiedPDFPages from './VerifiedPDFPages.svelte';
  import { fetchSignerPackage, fetchSignerPackagePDF, initialSignerPackagePreview, signerPackageResponse,
    SignerPackagePreviewController, type SignerPackage, type SignerPackagePreview, type SignerPackageResponse, type SignerPackageScope } from '$lib/signerPackage';

  let { scope, mainReady, disabled = false, onChange }: {
    scope: SignerPackageScope; mainReady: boolean; disabled?: boolean;
    onChange: (state: { key: string; ready: boolean; settled: boolean; response?: SignerPackageResponse }) => void;
  } = $props();
  const original = untrack(() => scope);
  let value = $state.raw<SignerPackage | null>(null);
  let loaded = $state(false), busy = $state(true), consent = $state(false), error = $state<string | null>(null);
  let reviewed = $state<Record<number, boolean>>({});
  let preview = $state.raw<SignerPackagePreview>(initialSignerPackagePreview());
  let owner: { retire(): Promise<void> } | null = null;
  let abort: AbortController | null = null, revision = 0, disposed = false;
  const current = () => !disposed && scope.key === original.key && scope.token === original.token;
  const controller = new SignerPackagePreviewController(fetchSignerPackagePDF, async () => {
    await tick(); const previous = owner; await previous?.retire(); if (owner === previous) owner = null;
  }, next => { preview = next; });
  const allAttachmentsReviewed = $derived(!!value && value.annexes.every((_, i) => reviewed[i + 1]));
  const canConsent = $derived(loaded && !busy && !error && !!value && mainReady && allAttachmentsReviewed && !preview.opening && !preview.closing && !preview.blocked && !preview.error);
  $effect(() => {
    if ((!mainReady || preview.error || preview.blocked) && consent) consent = false;
  });
  $effect(() => {
    const ready = current() && loaded && !busy && !error && !preview.blocked && !preview.opening && !preview.closing
      && (value === null || canConsent && consent);
    const response = ready && value ? signerPackageResponse(value) : undefined;
    const settled = current() && !busy;
    untrack(() => onChange({ key: original.key, ready, settled, ...(response ? { response } : {}) }));
  });

  async function refresh() {
    if (!current() || disabled) return;
    const mine = ++revision;
    abort?.abort(); consent = false; reviewed = {}; loaded = false; busy = true; error = null;
    await controller.close();
    if (!current() || mine !== revision) return;
    if (preview.blocked) { busy = false; error = 'Reload this page to close the previous attachment view before continuing.'; return; }
    const request = new AbortController(); abort = request;
    try {
      const next = await fetchSignerPackage(original, request.signal);
      if (!current() || mine !== revision || request.signal.aborted) return;
      value = next; loaded = true;
    } catch {
      if (current() && mine === revision && !request.signal.aborted) error = 'The contract package could not be verified. Reload the package before signing or accepting.';
    } finally { if (current() && mine === revision) busy = false; }
  }
  async function open(position: number) {
    if (!current() || !value || disabled || busy || preview.blocked) return;
    consent = false;
    await controller.open(original, value, position);
  }
  function proof(next: { key: string; allPagesSeen: boolean }) {
    const selected = preview.selection;
    if (!current() || !selected || next.key !== selected.key || preview.opening || preview.closing || preview.blocked) return;
    reviewed = { ...reviewed, [selected.position]: next.allPagesSeen };
    if (!next.allPagesSeen) consent = false;
  }
  onMount(() => { void refresh(); });
  onDestroy(() => {
    disposed = true; revision++; abort?.abort();
    if (owner) controller.observeRetirement(owner.retire());
    void controller.dispose().catch(() => {});
    onChange({ key: original.key, ready: false, settled: false });
  });
</script>

{#if busy || error || value}
<section aria-label="Contract package" class="mt-6 border-t border-border-light pt-6 space-y-4" data-signer-package>
  <div class="flex flex-wrap items-center justify-between gap-3">
    <h2 class="font-display text-lg">Your contract package</h2>
    <button type="button" class="btn btn-secondary" disabled={busy || disabled || preview.blocked} onclick={refresh}>Reload package</button>
  </div>
  {#if busy}<p role="status" class="text-sm">Checking the agreement and its attachments…</p>{/if}
  {#if error}<p role="alert" class="text-sm text-danger">{error}</p>{/if}
  {#if value && loaded}
    <p class="text-sm text-text-secondary">Review the main document and each attachment. Your response will apply to these saved versions together.</p>
    <ol class="space-y-3" aria-label="Documents in this agreement">
      <li class="border border-border-light rounded-md p-4 space-y-1">
        <p class="text-sm font-medium">Main document · {value.main.title}</p>
        <p class="text-xs text-text-secondary">{value.main.pages} page{value.main.pages === 1 ? '' : 's'} · Shown above</p>
        <p class="text-xs" role="status">{mainReady ? 'Document ready for your review' : 'Waiting for the document view'}</p>
      </li>
      {#each value.annexes as member, i (i)}
        <li class="border border-border-light rounded-md p-4 space-y-2" data-package-position={i + 1}>
          <p class="text-sm font-medium">Attachment {i + 1} · {member.title}</p>
          <p class="text-xs text-text-secondary">{member.category ? member.category + ' · ' : ''}{member.pages} page{member.pages === 1 ? '' : 's'}</p>
          <div class="flex flex-wrap items-center gap-3">
            <button type="button" class="btn btn-secondary" disabled={disabled || busy || preview.blocked || preview.closing} onclick={() => open(i + 1)}>Review attachment</button>
            <span class="text-xs" role="status">{reviewed[i + 1] ? 'All pages reviewed' : 'Review every page before continuing'}</span>
          </div>
        </li>
      {/each}
    </ol>
    {#if preview.error}<p role="alert" class="text-sm text-danger">{preview.error}</p>{/if}
    {#if preview.opening || preview.closing}<p role="status" class="text-sm">{preview.closing ? 'Closing attachment…' : 'Verifying the attachment PDF…'}</p>{/if}
    {#if preview.selection}
      <div class="space-y-3" hidden={preview.opening || preview.closing}>
        <div class="flex flex-wrap items-center justify-between gap-3">
          <h3 class="font-medium">{preview.selection.title}</h3>
          <button type="button" class="btn btn-secondary" disabled={disabled} onclick={() => controller.close()}>Close attachment</button>
        </div>
        {#key preview.selection.key}
          <VerifiedPDFPages bytes={preview.selection.bytes} proofKey={preview.selection.key} expectedPages={preview.selection.pages}
            ariaLabel="Contract attachment" onProof={proof} onOwner={next => { owner = next; }} onRetirement={p => controller.observeRetirement(p)} />
        {/key}
      </div>
    {/if}
    <details class="text-xs text-text-secondary space-y-2">
      <summary class="cursor-pointer">Verify this version · {value.revision}</summary>
      <p class="pt-2">Package fingerprint</p><code class="block break-all">{value.manifest_sha256}</code>
      <p>Agreement fingerprint</p><code class="block break-all">{value.legal_commitment_sha256}</code>
    </details>
    <label class="flex items-start gap-3 text-sm border border-border-light rounded-md p-4">
      <input type="checkbox" class="mt-1" bind:checked={consent} disabled={disabled || !canConsent} />
      <span>{value.incorporation.text}</span>
    </label>
    {#if !allAttachmentsReviewed && value.annexes.length}<p class="text-xs text-text-secondary">Open each attachment and view every page to enable the package agreement.</p>{/if}
  {/if}
</section>
{/if}
