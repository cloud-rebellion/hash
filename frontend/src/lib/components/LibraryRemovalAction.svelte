<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import { Archive, Trash2, RefreshCw } from 'lucide-svelte';
  import { LibraryRemovalError, removeLibraryItem, type LibraryItemKind } from '$lib/api/libraryRemoval';
  import { ui } from '$lib/staffPreferences';

  let { kind, item, canWrite, disabled = false, beforeRemove, onremoved, onbusy = () => {} } = $props<{
    kind: LibraryItemKind;
    item: { id: string; org_id: string; name: string; status?: string; updated_at: string; version?: number };
    canWrite: boolean; disabled?: boolean;
    beforeRemove?: () => boolean | Promise<boolean>;
    onremoved: () => void | Promise<void>;
    onbusy?: (busy: boolean) => void;
  }>();
  let confirming = $state(false), busy = $state(false), uncertain = $state(false), done = $state(false);
  let error = $state<string | null>(null);
  let trigger = $state.raw<HTMLButtonElement>(), cancelButton = $state.raw<HTMLButtonElement>(), dialog = $state.raw<HTMLDialogElement>();
  let disposed = false, revision = 0;
  let controller: AbortController | null = null;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  let rejectPending: ((reason: Error) => void) | undefined;
  const eligible = $derived(canWrite && (kind === 'template' || item.status === 'draft'));
  function currentKey(): string { return JSON.stringify([kind, item.org_id, item.id, item.status, item.updated_at, item.version]); }
  function resetDeadline() { if (deadline !== undefined) clearTimeout(deadline); deadline = undefined; rejectPending = undefined; }
  onDestroy(() => { disposed = true; revision++; controller?.abort(); rejectPending?.(new Error('retired')); resetDeadline(); });

  async function openConfirmation() {
    if (disposed || disabled || !eligible || busy || uncertain || done) return;
    confirming = true; error = null;
    await tick(); if (!disposed && confirming) { if (dialog && !dialog.open) dialog.showModal(); cancelButton?.focus(); }
  }
  async function cancelConfirmation() {
    if (disposed || busy || uncertain || done) return;
    confirming = false; error = null; dialog?.close();
    await tick(); if (!disposed) trigger?.focus();
  }
  // The browser may close a modal on a third Escape (non-cancelable). While a delete is pending or unconfirmed, or a message is
  // showing (a refusal that landed during the close), the dialog must stay.
  async function dialogClosed() {
    if (disposed || !confirming) return;
    if (busy || uncertain || error) { if (dialog && !dialog.open) dialog.showModal(); return; }
    confirming = false; error = null;
    await tick(); if (!disposed) trigger?.focus();
  }
  async function remove() {
    if (disposed || disabled || !eligible || !confirming || busy || uncertain || done) return;
    const ticket = ++revision, key = currentKey(), id = item.id, selectedKind = kind;
    busy = true; error = null; onbusy(true);
    let dispatched = false;
    try {
      // One deadline covers beforeRemove too, so a hung preview retirement cannot leave the modal busy forever.
      const abort = new AbortController(); controller = abort;
      const timedOut = new Promise<never>((_, reject) => {
        rejectPending = reject;
        deadline = setTimeout(() => {
          abort.abort();
          reject(new LibraryRemovalError('unknown', dispatched ? 'The result could not be confirmed. Reload the library before trying again.' : 'Close the preview or creation form before removing this item.'));
        }, 25000);
      });
      if (beforeRemove && !await Promise.race([beforeRemove(), timedOut])) {
        if (!disposed && ticket === revision) error = 'Close the preview or creation form before removing this item.';
        return;
      }
      if (disposed || ticket !== revision || key !== currentKey()) return;
      dispatched = true;
      await Promise.race([removeLibraryItem(selectedKind, id, abort.signal), timedOut]);
      if (disposed || ticket !== revision || key !== currentKey()) return;
      done = true; confirming = false;
      await onremoved();
    } catch (failure) {
      if (disposed || ticket !== revision || key !== currentKey()) return;
      if (done) error = 'The item was removed. Reload the library to update this view.';
      else {
        uncertain = dispatched && !(failure instanceof LibraryRemovalError && failure.outcome === 'refused');
        error = failure instanceof LibraryRemovalError ? failure.message : uncertain
          ? 'The result could not be confirmed. Reload the library before trying again.'
          : 'Close the preview or creation form before removing this item.';
      }
    } finally {
      resetDeadline(); controller = null;
      if (!disposed && ticket === revision) busy = false;
      onbusy(false);
    }
  }
</script>

{#if eligible}
  <div class="library-removal" aria-busy={busy}>
    {#if done}<p role="status" class="text-xs text-success">{$ui(kind === 'document' ? 'Draft deleted.' : 'Template archived.')}</p>
    {:else}
      <button bind:this={trigger} type="button" class="removal-trigger" disabled={disabled || busy} aria-label={$ui(kind === 'document' ? 'Delete draft {name}' : 'Archive template {name}', { name: item.name })} aria-haspopup="dialog" aria-expanded={confirming} onclick={openConfirmation}>
        {#if kind === 'document'}<Trash2 class="size-3.5" />{:else}<Archive class="size-3.5" />{/if}{$ui(kind === 'document' ? 'Delete draft' : 'Archive template')}
      </button>
    {/if}
    {#if confirming}
      <dialog bind:this={dialog} class="removal-confirmation" aria-label={$ui(kind === 'document' ? 'Confirm draft deletion' : 'Confirm template archive')} oncancel={(event) => { event.preventDefault(); void cancelConfirmation(); }} onclose={dialogClosed}>
        <p class="text-sm font-medium [overflow-wrap:anywhere]">{$ui(kind === 'document' ? 'Delete “{name}”?' : 'Archive “{name}”?', { name: item.name })}</p>
        <p class="text-xs leading-relaxed text-text-secondary mt-2">{$ui(kind === 'document' ? 'This removes the draft from your library. Source files are retained during the cleanup grace period. Sent and signed documents cannot be deleted here.' : 'This removes the template from the library. Documents already created from it and their saved evidence are kept.')}</p>
        {#if error}<p role="alert" class="text-xs text-danger mt-3">{$ui(error)}</p>{/if}
        {#if uncertain}<button type="button" class="btn btn-secondary !text-xs mt-3" onclick={() => window.location.reload()}><RefreshCw class="size-3.5" />{$ui('Reload library')}</button>
        {:else}<div class="flex flex-wrap gap-2 mt-3">
          <button bind:this={cancelButton} type="button" class="btn btn-secondary !text-xs !py-2" disabled={busy} onclick={cancelConfirmation}>{$ui('Cancel')}</button>
          <button type="button" class="btn btn-secondary removal-submit !text-xs !py-2" disabled={disabled || busy} onclick={remove}>{$ui(busy ? 'Removing…' : kind === 'document' ? 'Delete draft' : 'Archive template')}</button>
        </div>{/if}
      </dialog>
    {/if}
    {#if done && error}<p role="alert" class="text-xs text-danger mt-2">{$ui(error)}</p>{/if}
  </div>
{/if}

<style>
  .library-removal{min-width:0;}
  .removal-trigger{display:inline-flex;align-items:center;gap:6px;padding:7px 0;border-radius:4px;font-size:12px;color:var(--t-text-secondary);text-align:left;}
  .removal-trigger:hover{color:var(--t-danger);}
  .removal-trigger:focus-visible{outline:2px solid var(--t-accent);outline-offset:4px;}
  .removal-trigger:disabled{opacity:.4;cursor:default;}
  .removal-confirmation{width:min(24rem,calc(100vw - 2rem));margin:auto;padding:20px;border:1px solid color-mix(in srgb,var(--t-danger) 25%,var(--t-border));border-radius:12px;background:var(--t-bg-elevated);color:var(--t-text-primary);box-shadow:0 20px 50px rgb(0 0 0/.25);}
  .removal-confirmation::backdrop{background:rgb(15 23 42/.55);}
  .removal-submit{color:var(--t-danger);}
</style>
