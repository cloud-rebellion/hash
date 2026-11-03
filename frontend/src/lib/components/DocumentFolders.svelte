<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { APIError, getMe, listDocumentFolders, createDocumentFolder, renameDocumentFolder, deleteDocumentFolder, moveDocumentFolder, type DocumentFolder, type DocumentResponse } from '$lib/api/client';
  import { ui } from '$lib/staffPreferences';
  import { Folder, Files, Inbox, Plus, Pencil, Trash2, X, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-svelte';

  let { selected = 'all', disabled = false, movingDocument = null, onselect, onchange, oncloseMove, oncapability, onbusy } = $props<{
    selected?: string; disabled?: boolean; movingDocument?: DocumentResponse | null;
    onselect: (folder: string) => void; onchange: () => void | Promise<void>;
    oncloseMove: () => void; onbusy: (value: boolean) => void; oncapability: (available: boolean, canWrite: boolean) => void;
  }>();
  let folders = $state<DocumentFolder[]>([]);
  let total = $state(0);
  let offset = $state(0);
  const limit = 25;
  let loading = $state(true);
  let available = $state(false);
  let canWrite = $state(false);
  let busy = $state(false);
  let readError = $state<string | null>(null);
  let actionError = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let form = $state<'create' | 'rename' | null>(null);
  let name = $state('');
  let deleting = $state(false);
  let moveTarget = $state('choose');
  let nameInput = $state.raw<HTMLInputElement>();
  let movePanel = $state.raw<HTMLElement>();
  let disposed = false;
  let revision = 0;
  let reader: AbortController | null = null;
  const current = $derived(folders.find(folder => folder.id === selected));
  const locked = $derived(disabled || busy);

  async function loadFolders(nextOffset = offset, ownedRefresh = false) {
    if (disposed || (busy && !ownedRefresh) || nextOffset < 0) return;
    const ticket = ++revision;
    reader?.abort(); const controller = new AbortController(); reader = controller;
    loading = true; readError = null;
    try {
      const page = await listDocumentFolders(limit, nextOffset, controller.signal);
      if (disposed || ticket !== revision) return;
      if (!Array.isArray(page.folders) || page.limit !== limit || page.offset !== nextOffset || !Number.isSafeInteger(page.total) || page.total < 0) throw new Error('Unable to load folders.');
      if (nextOffset > 0 && page.folders.length === 0 && page.total <= nextOffset) {
        offset = Math.max(0, Math.floor(Math.max(0, page.total - 1) / limit) * limit);
        loading = false;
        await loadFolders(offset, ownedRefresh);
        return;
      }
      folders = page.folders; total = page.total; offset = page.offset;
      available = true; moveTarget = 'choose'; oncapability(true, canWrite);
    } catch (error) {
      if (disposed || ticket !== revision) return;
      available = false;
      readError = error instanceof APIError && error.status === 404 ? 'Folders are unavailable on this server.' : (error as Error).message;
      oncapability(false, false);
    } finally { if (!disposed && ticket === revision) loading = false; }
  }

  onMount(() => {
    void getMe().then(me => {
      if (disposed) return;
      canWrite = me.role === 'owner' || me.role === 'sender';
      oncapability(available, canWrite);
    }).catch(() => { if (!disposed) { canWrite = false; oncapability(available, false); } });
    void loadFolders(0);
    return () => { disposed = true; revision++; reader?.abort(); };
  });
  $effect(() => {
    const document = movingDocument;
    moveTarget = 'choose'; actionError = null;
    if (document) void tick().then(() => { if (!disposed && movingDocument?.id === document.id) { movePanel?.focus(); movePanel?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); } });
  });

  function selectFolder(folder: string) {
    if (locked || (!available && folder !== 'all')) return;
    form = null; deleting = false; actionError = null; notice = null;
    onselect(folder);
  }
  async function openForm(kind: 'create' | 'rename') {
    if (locked || !available || !canWrite || (kind === 'rename' && !current)) return;
    form = kind; name = kind === 'rename' ? current!.name : ''; deleting = false; actionError = null; notice = null;
    await tick(); if (!disposed && form === kind) nameInput?.focus();
  }
  function validName(value: string): boolean {
    return [...value.trim()].length > 0 && [...value.trim()].length <= 80 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
  }
  async function saveFolder(event: Event) {
    event.preventDefault();
    if (locked || !available || !canWrite || !form) return;
    const kind = form, folder = current, value = name.trim();
    if (!validName(value)) { actionError = 'Use 1–80 characters without control characters.'; return; }
    if (kind === 'rename' && !folder) return;
    busy = true; onbusy(true); actionError = null; notice = null;
    try {
      if (kind === 'create') await createDocumentFolder(value);
      else await renameDocumentFolder(folder!.id, value);
      if (disposed) return;
      form = null; name = '';
      notice = kind === 'create' ? 'Folder created.' : 'Folder renamed.';
      await loadFolders(kind === 'create' ? 0 : offset, true);
      await onchange();
    } catch (error) { if (!disposed) actionError = (error as Error).message; }
    finally { if (!disposed) { busy = false; onbusy(false); } }
  }
  async function removeFolder() {
    if (locked || !available || !canWrite || !deleting || !current || current.document_count !== 0) return;
    const id = current.id; busy = true; onbusy(true); actionError = null; notice = null;
    try {
      await deleteDocumentFolder(id);
      if (disposed) return;
      deleting = false; form = null; onselect('all'); notice = 'Empty folder deleted. Documents are kept.';
      await loadFolders(offset, true); await onchange();
    } catch (error) { if (!disposed) actionError = (error as Error).message; }
    finally { if (!disposed) { busy = false; onbusy(false); } }
  }
  async function moveDocument(event: Event) {
    event.preventDefault();
    if (locked || !available || !canWrite || !movingDocument || moveTarget === 'choose') return;
    const document = movingDocument, folder = moveTarget === 'unfiled' ? null : moveTarget;
    if (folder === (document.folder_id ?? null) || (folder !== null && !folders.some(row => row.id === folder))) return;
    busy = true; onbusy(true); actionError = null; notice = null;
    try {
      const result = await moveDocumentFolder(document.id, folder);
      if (result.document_id !== document.id || result.folder_id !== folder) throw new Error('The move could not be confirmed. Refresh before trying again.');
      if (disposed) return;
      oncloseMove(); notice = 'Document moved.';
      await loadFolders(offset, true); await onchange();
    } catch (error) { if (!disposed) actionError = (error as Error).message; }
    finally { if (!disposed) { busy = false; onbusy(false); } }
  }
</script>

<aside class="folder-navigation" aria-label={$ui('Document folders')}>
  <div class="flex items-center justify-between gap-3 mb-3"><h3 class="text-xs font-medium uppercase tracking-wider text-text-muted">{$ui('Folders')}</h3>{#if available && canWrite}<button type="button" class="folder-icon" disabled={locked} aria-label={$ui('Create folder')} onclick={() => openForm('create')}><Plus class="size-4" /></button>{/if}</div>
  <nav class="space-y-1" aria-label={$ui('Choose a document folder')}>
    <button type="button" class="folder-link" class:folder-selected={selected === 'all'} disabled={locked} aria-current={selected === 'all' ? 'page' : undefined} onclick={() => selectFolder('all')}><Files class="size-4 shrink-0" /><span>{$ui('All documents')}</span></button>
    <button type="button" class="folder-link" class:folder-selected={selected === 'unfiled'} disabled={locked || !available} aria-current={selected === 'unfiled' ? 'page' : undefined} onclick={() => selectFolder('unfiled')}><Inbox class="size-4 shrink-0" /><span>{$ui('Unfiled')}</span></button>
    {#each folders as folder (folder.id)}<button type="button" class="folder-link" class:folder-selected={selected === folder.id} disabled={locked || !available || loading} aria-current={selected === folder.id ? 'page' : undefined} onclick={() => selectFolder(folder.id)}><Folder class="size-4 shrink-0" /><span class="truncate flex-1 text-left" title={folder.name}>{folder.name}</span><span class="text-xs tabular-nums text-text-muted">{folder.document_count}</span></button>{/each}
  </nav>
  {#if loading}<p class="mt-3 text-xs text-text-muted" role="status">{$ui('Loading folders…')}</p>{/if}
  {#if readError}<div class="mt-3 space-y-2" role="alert"><p class="text-xs text-danger">{$ui(readError)}</p><button type="button" class="text-xs underline underline-offset-4" disabled={locked || loading} onclick={() => loadFolders(offset)}><RefreshCw class="size-3 inline mr-1" />{$ui('Try again')}</button></div>{/if}
  {#if available && total === 0 && !loading}<p class="text-xs text-text-muted mt-3 leading-5">{$ui('Keep related documents together. Folders do not change signed contracts.')}</p>{/if}
  {#if available && total > limit}<div class="flex items-center justify-between gap-2 mt-3 text-xs text-text-muted"><button type="button" class="folder-icon" disabled={locked || loading || offset === 0} aria-label={$ui('Previous folders')} onclick={() => loadFolders(Math.max(0, offset - limit))}><ChevronLeft class="size-4" /></button><span>{$ui('{start}–{end} of {total}', { start: offset + 1, end: Math.min(offset + folders.length, total), total })}</span><button type="button" class="folder-icon" disabled={locked || loading || offset + folders.length >= total} aria-label={$ui('Next folders')} onclick={() => loadFolders(offset + limit)}><ChevronRight class="size-4" /></button></div>{/if}
  {#if available && canWrite && current && !form && !movingDocument}<div class="flex gap-3 pt-3 mt-3 border-t border-border-light text-xs"><button type="button" class="inline-flex gap-1 items-center text-text-secondary hover:text-text-primary" disabled={locked} onclick={() => openForm('rename')}><Pencil class="size-3" />{$ui('Rename')}</button><button type="button" class="inline-flex gap-1 items-center text-text-secondary hover:text-danger disabled:opacity-40" disabled={locked || current.document_count !== 0} title={$ui('Only empty folders can be deleted.')} onclick={() => { deleting = true; actionError = null; }}><Trash2 class="size-3" />{$ui('Delete empty folder')}</button></div>{/if}
  {#if form}<form class="folder-editor mt-4" onsubmit={saveFolder} aria-busy={busy}><label for="folder-name" class="text-sm font-medium">{$ui(form === 'create' ? 'Create folder' : 'Rename folder')}</label><input id="folder-name" bind:this={nameInput} bind:value={name} disabled={locked} required maxlength="160" autocomplete="off" class="mt-2 w-full rounded-lg border border-border bg-bg-surface px-3 py-2 text-sm" /><p class="text-xs text-text-muted mt-2">{$ui('Up to 80 characters. Folder names must be unique.')}</p><div class="flex gap-2 mt-3"><button type="submit" class="btn btn-primary !text-xs !px-3 !py-2" disabled={locked || !validName(name)}>{$ui(busy ? 'Saving…' : 'Save')}</button><button type="button" class="btn btn-secondary !text-xs !px-3 !py-2" disabled={locked} onclick={() => { form = null; actionError = null; }}>{$ui('Cancel')}</button></div></form>{/if}
  {#if deleting && current}<div class="folder-editor mt-4"><p class="text-sm font-medium">{$ui('Delete “{name}”?', { name: current.name })}</p><p class="text-xs text-text-secondary mt-2">{$ui('Only the empty folder is removed. Documents are never deleted.')}</p><div class="flex gap-2 mt-3"><button type="button" class="btn btn-secondary !text-xs !px-3 !py-2 text-danger" disabled={locked || current.document_count !== 0} onclick={removeFolder}>{$ui(busy ? 'Deleting…' : 'Delete folder')}</button><button type="button" class="btn btn-secondary !text-xs !px-3 !py-2" disabled={locked} onclick={() => { deleting = false; actionError = null; }}>{$ui('Cancel')}</button></div></div>{/if}
  {#if movingDocument}<section class="folder-editor mt-4 focus:outline-none" bind:this={movePanel} tabindex="-1" aria-label={$ui('Move document')}><div class="flex items-start justify-between gap-2"><h4 class="font-medium text-sm break-words">{$ui('Move “{name}”', { name: movingDocument.name })}</h4><button type="button" class="folder-icon shrink-0" disabled={locked} aria-label={$ui('Close')} onclick={oncloseMove}><X class="size-4" /></button></div><form onsubmit={moveDocument} aria-busy={busy}><label for="folder-destination" class="text-xs text-text-secondary block mt-3 mb-2">{$ui('Destination folder')}</label><select id="folder-destination" bind:value={moveTarget} class="w-full rounded-lg border border-border bg-bg-surface p-2 text-sm" disabled={locked || !available || loading}><option value="choose" disabled>{$ui('Choose a folder')}</option><option value="unfiled" disabled={!movingDocument.folder_id}>{$ui('Unfiled')}</option>{#each folders as folder}<option value={folder.id} disabled={folder.id === movingDocument.folder_id}>{folder.name}</option>{/each}</select><p class="text-xs text-text-muted mt-2">{$ui('Use the folder arrows above to see more destinations.')}</p><button type="submit" class="btn btn-primary !text-xs !px-3 !py-2 mt-3" disabled={locked || !available || loading || moveTarget === 'choose'}>{$ui(busy ? 'Moving…' : 'Move document')}</button></form></section>{/if}
  {#if actionError}<p class="text-xs text-danger mt-3" role="alert">{$ui(actionError)}</p>{/if}
  {#if notice}<p class="text-xs text-text-secondary mt-3" role="status">{$ui(notice)}</p>{/if}
</aside>

<style>
  .folder-navigation { min-width: 0; }
  .folder-link { display: flex; align-items: center; gap: .625rem; width: 100%; min-height: 2.5rem; padding: .5rem .625rem; border-radius: .5rem; font-size: .8125rem; color: var(--color-text-secondary); }
  .folder-link:hover:not(:disabled) { background: var(--color-bg-hover); color: var(--color-text-primary); }
  .folder-selected { background: var(--color-bg-hover); color: var(--color-text-primary); font-weight: 500; }
  .folder-link:disabled { opacity: .5; cursor: not-allowed; }
  .folder-icon { display: inline-flex; align-items: center; justify-content: center; padding: .375rem; border-radius: .375rem; color: var(--color-text-secondary); }
  .folder-icon:hover:not(:disabled) { background: var(--color-bg-hover); color: var(--color-text-primary); }
  .folder-icon:disabled { opacity: .35; }
  .folder-editor { padding: .875rem; border: 1px solid var(--color-border-light); border-radius: .625rem; background: var(--color-bg-surface); }
</style>
