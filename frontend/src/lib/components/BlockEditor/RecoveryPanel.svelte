<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    APIError, getMe, getCollaborationRecovery, recoverCollaboration,
    collaborationArchiveURL, deleteCollaborationArchive,
    type CollaborationRecoveryState
  } from '$lib/api/client';

  let { documentID, orgID, archiveReviewOnly = false, editRevision = 0, downloadDraft = () => false,
    onRecovered = () => {}, reloadDocument = () => {} }: {
    documentID: string;
    orgID: string;
    archiveReviewOnly?: boolean;
    editRevision?: number;
    downloadDraft?: () => boolean;
    onRecovered?: (documentID: string) => void;
    reloadDocument?: (documentID: string, revision: number) => void;
  } = $props();

  let loading = $state(false);
  let busy = $state(false);
  let owner = $state<boolean | null>(null);
  let error = $state<string | null>(null);
  let review = $state<CollaborationRecoveryState | null>(null);
  let reviewedRevision = $state<number | null>(null);
  let capturedRevision = $state<number | null>(null);
  let acknowledged = $state(false);
  let successRevision = $state<number | null>(null);
  let successGeneration = $state<string | null>(null);
  let disposed = false;
  let readVersion = 0;

  const canReset = $derived(readyToReset());
  const canReload = $derived(readyToReload());

  onMount(() => { void loadReview(); });
  onDestroy(() => { disposed = true; readVersion++; });

  function current(id: string, version: number) {
    return !disposed && documentID === id && readVersion === version;
  }

  function readyToReset() {
    return !archiveReviewOnly && owner === true && review !== null && review.document_deleted === false
      && review.document.source_kind === 'blocks' && review.document.status === 'draft' && !loading && !busy && acknowledged
      && successGeneration === null && reviewedRevision === editRevision && capturedRevision === editRevision;
  }

  function readyToReload() {
    return !archiveReviewOnly && review?.document_deleted === false
      && review.document.source_kind === 'blocks' && review.document.status === 'draft'
      && successRevision !== null && successRevision === editRevision
      && capturedRevision === editRevision && !busy;
  }

  function validState(state: CollaborationRecoveryState, id: string) {
    return state?.document?.id === id && state.document.org_id === orgID
      && typeof state.document_deleted === 'boolean'
      && /^\d{4}-\d{2}-\d{2}T/.test(state.document.updated_at)
      && typeof state.generation === 'string' && /^[1-9][0-9]{0,18}$/.test(state.generation)
      && BigInt(state.generation) <= 9223372036854775807n
      && Array.isArray(state.archives) && state.archives.length <= 16
      && state.archives.every((archive) => archive !== null && typeof archive === 'object' && typeof archive.id === 'string'
        && (archive.origin === 'persisted' || archive.origin === 'active_room')
        && typeof archive.created_at === 'string' && typeof archive.expires_at === 'string'
        && Number.isInteger(archive.size_bytes) && archive.size_bytes >= 0 && archive.size_bytes <= 8 * 1024 * 1024);
  }

  async function loadReview() {
    if (disposed || loading || busy) return;
    const id = documentID;
    const version = ++readVersion;
    const revision = editRevision;
    loading = true;
    error = null;
    review = null;
    reviewedRevision = null;
    acknowledged = false;
    capturedRevision = null;
    try {
      const user = await getMe();
      if (!current(id, version)) return;
      owner = user.org_id === orgID && user.role === 'owner';
      if (!owner) return;
      const state = await getCollaborationRecovery(id);
      if (!current(id, version)) return;
      if (!validState(state, id)) throw new Error('The recovery review is unavailable. Your local draft is preserved.');
      review = state;
      reviewedRevision = revision;
    } catch (e) {
      if (current(id, version)) {
        error = (e as Error).message;
        if (e instanceof APIError && (e.status === 401 || e.status === 403)) owner = false;
      }
    } finally {
      if (current(id, version)) loading = false;
    }
  }

  function captureLocalDraft() {
    if (disposed || busy) return;
    const revision = editRevision;
    if (downloadDraft() && revision === editRevision) capturedRevision = revision;
  }

  async function resetSharedEditing() {
    if (!readyToReset() || !review || disposed) return;
    const id = documentID;
    const version = readVersion;
    const revision = editRevision;
    const observation = review;
    busy = true;
    error = null;
    try {
      const result = await recoverCollaboration(id, {
        generation: observation.generation,
        expected_updated_at: observation.document.updated_at,
        acknowledged: true
      });
      if (!current(id, version)) return;
      if (result.document?.id !== id || result.document.org_id !== orgID
          || result.generation !== (BigInt(observation.generation) + 1n).toString()) {
        throw new Error('The recovery receipt could not be verified. Keep your local draft and review the saved document again.');
      }
      successRevision = revision;
      successGeneration = result.generation;
      acknowledged = false;
      // Stop the old editor connection, keeping its local content and dirty flag.
      onRecovered(id);
      review = { ...observation, document: result.document, generation: result.generation };
      try {
        const refreshed = await getCollaborationRecovery(id);
        if (current(id, version) && validState(refreshed, id)) review = refreshed;
      } catch {
        if (current(id, version)) error = 'Shared editing was reset, but the archive list could not be refreshed. Retry the review to see the retained archives.';
      }
    } catch (e) {
      if (current(id, version)) {
        error = (e as Error).message;
        if (e instanceof APIError && e.status === 412) {
          review = null;
          reviewedRevision = null;
          capturedRevision = null;
          acknowledged = false;
        }
        if (e instanceof APIError && (e.status === 401 || e.status === 403)) owner = false;
      }
    } finally {
      if (current(id, version)) busy = false;
    }
  }

  async function removeArchive(archiveID: string) {
    if (disposed || busy || owner !== true || !review?.archives.some((archive) => archive.id === archiveID)) return;
    if (!window.confirm('Permanently delete this recovery archive? Download it first if you need to preserve the older shared edits.')) return;
    const id = documentID;
    const version = readVersion;
    busy = true;
    error = null;
    try {
      await deleteCollaborationArchive(id, archiveID);
      if (current(id, version) && review) {
        review = { ...review, archives: review.archives.filter((archive) => archive.id !== archiveID) };
      }
    } catch (e) {
      if (current(id, version)) {
        error = (e as Error).message;
        if (e instanceof APIError && (e.status === 401 || e.status === 403)) owner = false;
      }
    } finally {
      if (current(id, version)) busy = false;
    }
  }

  function reloadSavedDocument() {
    if (disposed || !readyToReload() || successRevision === null) return;
    reloadDocument(documentID, successRevision);
  }

  function downloadReviewedDocument() {
    if (disposed || busy || !review) return;
    const blob = new Blob([JSON.stringify(review.document.blocks_json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `hash-saved-document-${documentID}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function preview(state: CollaborationRecoveryState): string {
    const blocks = [...(state.document.blocks_json?.blocks ?? [])].reverse();
    const text: string[] = [];
    let characters = 0;
    let visited = 0;
    while (blocks.length && characters < 4000 && visited++ < 10000) {
      const block = blocks.pop()!;
      if (block.text) { text.push(block.text); characters += block.text.length; }
      if (block.rows) {
        const table = block.rows.map((row) => row.join(' | ')).join('\n');
        text.push(table); characters += table.length;
      }
      if (block.content) blocks.push(...[...block.content].reverse());
    }
    const content = text.join('\n').slice(0, 4000);
    return content || '(No text in the saved document.)';
  }
</script>

<section class="recovery-panel" aria-label={archiveReviewOnly ? 'Collaboration archive review' : 'Collaboration recovery'}>
  {#if archiveReviewOnly}
    <p>Review retained collaboration archives for the selected document. Download any data needed for the approved rights-response procedure before deleting it.</p>
  {:else}
    <p>Keep a copy of your local draft before reviewing the saved document.</p>
  {/if}
  <div class="actions">
    {#if !archiveReviewOnly}
      <button type="button" class="btn btn-secondary" disabled={busy} onclick={captureLocalDraft}>Download local draft for recovery</button>
    {/if}
    <button type="button" class="btn btn-secondary" disabled={loading || busy} onclick={loadReview}>
      {loading ? 'Checking recovery access…' : archiveReviewOnly ? 'Refresh archive review' : 'Refresh recovery review'}
    </button>
  </div>

  {#if error}<p role="alert" class="recovery-error">{error}</p>{/if}
  {#if owner === false}
    {#if archiveReviewOnly}
      <p>An organization owner must review these collaboration archives.</p>
    {:else}
      <p>An organization owner must review and recover shared editing. Your local draft stays in this editor.</p>
    {/if}
  {:else if owner === true && review}
    {#if archiveReviewOnly || review.document_deleted || review.document.source_kind !== 'blocks' || review.document.status !== 'draft'}
      <p>Document: {review.document.name}</p>
      {#if review.document_deleted}
        <p>This document was deleted. Retained archives can be reviewed during the cleanup grace period; shared editing cannot be reset here.</p>
      {:else}
        <p>This view provides archive review, download and deletion.</p>
      {/if}
    {:else}
    <details open>
      <summary>Current saved document: {review.document.name}</summary>
      <p>Saved {review.document.updated_at}</p>
      <pre>{preview(review)}</pre>
      <p>The preview shows up to 4,000 characters. Recovery keeps this saved document and archives the older shared editing history; it does not merge the history into the document.</p>
      <button type="button" class="btn btn-secondary" disabled={busy} onclick={downloadReviewedDocument}>Download full saved document for review</button>
    </details>
    {#if successGeneration !== null}
      <p role="status">Shared editing was reset. Your local draft is still open. Reload the saved document when you are ready to reconnect.</p>
      <button type="button" class="btn btn-primary" disabled={!canReload} onclick={reloadSavedDocument}>Reload saved document</button>
      {#if successRevision !== editRevision}
        <p>You edited after the recovery review. Your draft is preserved; download it before leaving this editor.</p>
      {/if}
    {:else}
      {#if reviewedRevision !== editRevision}
        <p>Your local draft changed during the review. Refresh the review and download the current draft before continuing.</p>
      {/if}
      <label class="acknowledgement">
        <input type="checkbox" bind:checked={acknowledged} disabled={busy || reviewedRevision !== editRevision || capturedRevision !== editRevision} />
        I have downloaded my local draft and reviewed the saved document. Reset shared editing to this saved document and preserve the older server edits in recovery archives.
      </label>
      <button type="button" class="btn btn-primary" disabled={!canReset} onclick={resetSharedEditing}>
        {busy ? 'Recovering…' : 'Reset shared editing to saved document'}
      </button>
    {/if}
    {/if}

    {#if review.archives.length}
      <h3>Recovery archives</h3>
      <p>These files preserve server collaboration history for recovery and are not editable document exports. Download anything you need before its expiry.</p>
      <ul>
        {#each review.archives as archive (archive.id)}
          <li>
            <span>{archive.origin === 'active_room' ? 'Active shared editing history' : 'Stored shared editing history'} · {archive.size_bytes.toLocaleString()} bytes</span>
            <span>Created {archive.created_at}; expires {archive.expires_at}</span>
            <div class="actions">
              <a class="btn btn-secondary" href={collaborationArchiveURL(documentID, archive.id)}>Download archive</a>
              <button type="button" class="btn btn-secondary" disabled={busy} onclick={() => removeArchive(archive.id)}>Delete archive…</button>
            </div>
          </li>
        {/each}
      </ul>
    {:else}
      <p>No recovery archives are available for this document.</p>
    {/if}
  {/if}
</section>

<style>
  .recovery-panel { padding: 1rem; border: 1px solid var(--color-border-light, #d1d5db); border-radius: 0.5rem; margin-bottom: 1rem; }
  .recovery-panel p { margin: 0.5rem 0; }
  .actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0; }
  .acknowledgement { display: flex; align-items: flex-start; gap: 0.5rem; margin: 1rem 0; }
  .recovery-error { color: var(--color-red-600, #b91c1c); }
  pre { max-height: 16rem; overflow: auto; padding: 0.75rem; white-space: pre-wrap; overflow-wrap: anywhere; border: 1px solid var(--color-border-light, #d1d5db); }
  ul { list-style: none; padding: 0; }
  li { padding: 0.5rem 0; border-top: 1px solid var(--color-border-light, #d1d5db); }
  li > span { display: block; }
</style>
