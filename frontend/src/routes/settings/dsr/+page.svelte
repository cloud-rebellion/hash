<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    listDSR,
    transitionDSR,
    exportSubjectData,
    getMe,
    type DSRRequest,
  } from '$lib/api/client';
  import { UserSearch, Download, Check, X, Pause } from 'lucide-svelte';
  import RecoveryPanel from '$lib/components/BlockEditor/RecoveryPanel.svelte';

  let requests = $state<DSRRequest[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let statusFilter = $state<string>('open');
  let archiveOwnerOrgID = $state<string | null>(null);
  let archiveAccessChecked = $state(false);
  let selectedArchiveRequest = $state<Pick<DSRRequest, 'id' | 'document_id' | 'org_id'> | null>(null);
  let disposed = false;
  let refreshVersion = 0;

  let exportEmail = $state('');
  let exporting = $state(false);
  let exportResult = $state<string | null>(null);

  async function refresh() {
    const version = ++refreshVersion;
    const filter = statusFilter;
    loading = true;
    try {
      const res = await listDSR(filter);
      if (disposed || version !== refreshVersion || filter !== statusFilter) return;
      requests = res.requests ?? [];
      if (selectedArchiveRequest && !requests.some((request) => request.id === selectedArchiveRequest?.id
          && request.document_id === selectedArchiveRequest.document_id && request.org_id === selectedArchiveRequest.org_id)) {
        selectedArchiveRequest = null;
      }
    } catch (e) {
      if (!disposed && version === refreshVersion) error = (e as Error).message;
    } finally {
      if (!disposed && version === refreshVersion) loading = false;
    }
  }

  async function checkArchiveAccess() {
    try {
      const user = await getMe();
      if (disposed) return;
      archiveOwnerOrgID = user.role === 'owner' ? user.org_id : null;
    } catch {
      if (!disposed) archiveOwnerOrgID = null;
    } finally {
      if (!disposed) archiveAccessChecked = true;
    }
  }

  function reviewDocumentArchives(requestID: string) {
    if (disposed || !archiveOwnerOrgID) return;
    const selected = requests.find((request) => request.id === requestID);
    if (!selected?.document_id || selected.org_id !== archiveOwnerOrgID) return;
    selectedArchiveRequest = { id: selected.id, document_id: selected.document_id, org_id: selected.org_id };
  }

  onMount(() => { void refresh(); void checkArchiveAccess(); });
  onDestroy(() => { disposed = true; refreshVersion++; });

  async function transition(id: string, status: string) {
    const note = status === 'denied'
      ? prompt('Resolution note (visible to the data subject):') || ''
      : '';
    try {
      await transitionDSR(id, status, note);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function runExport() {
    if (!exportEmail.trim()) return;
    exporting = true;
    exportResult = null;
    try {
      const data = await exportSubjectData(exportEmail.trim());
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dsr-export-${exportEmail.trim()}-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      exportResult = 'Recipient metadata inventory downloaded. This is not a complete Article 15/20 response: review scope and attach the referenced documents under the approved procedure.';
    } catch (e) {
      exportResult = (e as Error).message;
    } finally {
      exporting = false;
    }
  }

  const dueClass = (due_at: string) => {
    const now = new Date();
    const due = new Date(due_at);
    const days = Math.floor((+due - +now) / 86_400_000);
    if (days < 0) return 'text-danger';
    if (days <= 7) return 'text-warning';
    return 'text-text-muted';
  };
</script>

<div class="px-6 py-10 max-w-5xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · Privacy</p>
    <h1 class="page-title">Data subject rights</h1>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Every request a signer raises from their signing page lands here.
    The displayed due date is an operational 30-day target, not a substitute for the applicable
    GDPR deadline, identity checks, or extension procedure. Erasure fulfillment anonymizes the
    recipient record while preserving the signed PDF for evidentiary
    retention.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  <section class="card p-5 mb-6">
    <h2 class="font-display font-extralight text-lg mb-3 flex items-center gap-2">
      <Download class="size-4" /> Recipient metadata inventory
    </h2>
    <p class="text-sm text-text-secondary mb-3">
      Pull every recipient row matching an email across this org. The JSON contains metadata and
      object keys, not attached signed documents, and must not be treated as a complete rights response.
    </p>
    <div class="flex gap-2">
      <input
        type="email"
        bind:value={exportEmail}
        placeholder="subject@example.com"
        class="flex-1 px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      />
      <button class="btn btn-primary" onclick={runExport} disabled={exporting || !exportEmail.trim()}>
        {exporting ? 'Exporting...' : 'Export JSON'}
      </button>
    </div>
    {#if exportResult}
      <p class="text-xs text-text-secondary mt-3">{exportResult}</p>
    {/if}
  </section>

  {#if selectedArchiveRequest?.document_id}
    <section class="card p-5 mb-6" aria-label="Selected request archive review">
      <div class="flex items-center justify-between gap-3 mb-3">
        <h2 class="font-display font-extralight text-lg">Document recovery archives</h2>
        <button type="button" class="btn btn-secondary" onclick={() => (selectedArchiveRequest = null)}>Close archive review</button>
      </div>
      <p class="text-sm text-text-secondary mb-3">
        Review the archives associated with this request, including deleted documents during cleanup grace.
        Archives may contain personal data. A downloaded archive alone is not a complete rights response;
        follow the approved scope and disclosure procedure.
      </p>
      {#key `${selectedArchiveRequest.id}:${selectedArchiveRequest.document_id}`}
        <RecoveryPanel documentID={selectedArchiveRequest.document_id} orgID={selectedArchiveRequest.org_id} archiveReviewOnly />
      {/key}
    </section>
  {/if}

  <section class="card p-5">
    <div class="flex items-center justify-between mb-4">
      <h2 class="font-display font-extralight text-lg flex items-center gap-2">
        <UserSearch class="size-4" /> Pending requests
      </h2>
      <select bind:value={statusFilter} onchange={refresh} class="text-sm px-3 py-1.5 rounded border border-border-light bg-bg-elevated">
        <option value="open">Open</option>
        <option value="in_progress">In progress</option>
        <option value="fulfilled">Fulfilled</option>
        <option value="denied">Denied</option>
        <option value="withdrawn">Withdrawn</option>
        <option value="">All</option>
      </select>
    </div>
    {#if archiveAccessChecked && !archiveOwnerOrgID}
      <p class="text-sm text-text-secondary mb-3">Document archive review requires an organization owner.</p>
    {/if}

    {#if loading}
      <p class="text-text-muted text-sm">Loading...</p>
    {:else if requests.length === 0}
      <p class="text-text-muted text-sm">No requests in this state.</p>
    {:else}
      <ul class="divide-y divide-border-light">
        {#each requests as r (r.id)}
          <li data-request-id={r.id} class="py-4 grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-3">
            <div class="space-y-1">
              <div class="text-sm">
                <span class="font-mono uppercase tracking-widest text-xs text-text-muted">{r.kind}</span>
                <span class="ml-2 font-medium">{r.subject_email}</span>
                {#if r.subject_name}
                  <span class="text-text-muted"> ({r.subject_name})</span>
                {/if}
              </div>
              {#if r.requested_note}
                <div class="text-xs text-text-secondary">{r.requested_note}</div>
              {/if}
              <div class="text-xs {dueClass(r.due_at)}">
                Due {new Date(r.due_at).toLocaleDateString()} ·
                requested {new Date(r.requested_at).toLocaleDateString()}
              </div>
              {#if r.document_id && archiveOwnerOrgID === r.org_id}
                <button type="button" class="btn btn-secondary text-xs" onclick={() => reviewDocumentArchives(r.id)}>
                  Review document archives
                </button>
              {/if}
            </div>
            <div class="flex gap-2 justify-end">
              {#if r.status === 'open' || r.status === 'in_progress'}
                <button class="btn btn-secondary text-xs" onclick={() => transition(r.id, 'in_progress')}>
                  <Pause class="size-3" /> In progress
                </button>
                {#if r.kind === 'erasure'}
                  <button class="btn btn-primary text-xs" onclick={() => transition(r.id, 'fulfilled')}>
                    <Check class="size-3" /> Run erasure &amp; fulfill
                  </button>
                {:else}
                  <span class="text-xs text-text-muted self-center" title="Complete under the approved external procedure; Hash cannot attest fulfillment.">
                    Manual procedure required
                  </span>
                {/if}
                <button class="btn btn-secondary text-xs" onclick={() => transition(r.id, 'denied')}>
                  <X class="size-3" /> Deny
                </button>
              {:else}
                <span class="text-xs font-mono uppercase tracking-widest text-text-muted self-center">{r.status}</span>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>
