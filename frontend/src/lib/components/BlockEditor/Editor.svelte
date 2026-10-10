<!--
  Hash block editor v0.2 (TipTap).

  Wraps TipTap's ProseMirror editor and round-trips the canonical block
  tree on every save. Custom nodes (SignatureField, DynamicVariable,
  PageBreak) plus a blockId-preserving global attribute extension keep
  the editor and the Go renderer in lockstep.
-->
<script lang="ts">
  import { Editor } from '@tiptap/core';
  import StarterKit from '@tiptap/starter-kit';
  import { onDestroy, onMount, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import * as Y from 'yjs';
  import { WebsocketProvider } from 'y-websocket';
  import * as decoding from 'lib0/decoding';
  import * as encoding from 'lib0/encoding';
  import Collaboration from '@tiptap/extension-collaboration';
  import CollaborationCaret from '@tiptap/extension-collaboration-caret';
  import { Hash, FileText, Quote, Signature, Variable, Code as CodeIcon, Minus, Save, Users, Table as TableIcon, Plus, X } from 'lucide-svelte';
  import {
    importHTML, importMarkdown, getMe, getDocument, saveCollaborativeDocument, APIError, type BlockTree, type DocumentResponse
  } from '$lib/api/client';
  import { fromProseMirror, isCanonicalSignatureRole, toProseMirror } from './transform';
  import { bootstrapIfGranted, MESSAGE_BOOTSTRAP, readBootstrapGrant } from './bootstrap';
  import { MESSAGE_GENERATION, observeCanonicalGeneration, readCanonicalGeneration } from './generation';
  import { MESSAGE_SAVED, isNewerSaveReceipt, readCanonicalSaveReceipt } from './save-receipt';
  import { CheckpointRequests, MESSAGE_CHECKPOINT, readSaveCheckpoint } from './checkpoint';
  import { BlockIDExtension, DynamicVariable, OpaqueBlock, PageBreak, SignatureField, TableBlock } from './nodes';
  import RecoveryPanel from './RecoveryPanel.svelte';

  let { document: doc, onChange, userName, userColor, onEditorStateChange, externalBusy = false }: {
    document: DocumentResponse;
    onChange?: (d: DocumentResponse) => void;
    userName?: string;
    userColor?: string;
    onEditorStateChange?: (clean: boolean) => void;
    externalBusy?: boolean;
  } = $props();

  let editorEl: HTMLDivElement;
  let editor = $state.raw<Editor | null>(null);
  let saving = $state(false);
  let dirty = $state(false);
  let error = $state<string | null>(null);
  let saveTimer: ReturnType<typeof setTimeout> | null = null;
  let editRevision = $state(0);
  let saveQueued = $state(false);
  let saveConflict = $state(false);
 let mayBootstrap = false;
  let disposed = false;

  let showImport = $state<'none' | 'html' | 'md'>('none');
  let importText = $state('');
  let varName = $state('');
  let varDefault = $state('');

  // Table editor modal state. editingTable === 'new' inserts on save; a number
  // is the ProseMirror position of an existing tableBlock to update in place.
  let showTableModal = $state(false);
  let editingTable = $state<'new' | number | null>(null);
  let tCols = $state<string[]>([]);
  let tRows = $state<string[][]>([]);

  // Collab state
  let ydoc: Y.Doc | null = null;
  let provider = $state.raw<WebsocketProvider | null>(null);
  let peerCount = $state(1);
  let connected = $state(false);
  let collaborationRejected = $state(false);
  let canonicalGeneration = $state<string | null>(null);
  let syncReady = $state(false), externalQuiesced = $state(false);
  let wasExternallyBusy = false;
  const checkpointRequests = new CheckpointRequests();
  let accessCheckPending = false;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  $effect(() => {
    const clean = !!editor && !dirty && !saving && !saveQueued && !saveConflict && !collaborationRejected
      && showImport === 'none' && !showTableModal && !!canonicalGeneration
      && ((connected && syncReady) || (externalBusy && externalQuiesced));
    untrack(() => onEditorStateChange?.(clean));
  });
  $effect(() => {
    const locked = externalBusy, currentEditor = editor, currentProvider = provider, stamp = doc.updated_at;
    untrack(() => {
      currentEditor?.setEditable(!locked && doc.status === 'draft' && !saveConflict && !collaborationRejected);
      if (locked && !wasExternallyBusy) {
        externalQuiesced = !!currentEditor && connected && syncReady && !!canonicalGeneration && !dirty && !saving && !saveQueued
          && !saveConflict && !collaborationRejected && showImport === 'none' && !showTableModal;
        if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
        if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        checkpointRequests.cancel(new Error('Document information is being updated; your local draft is preserved'));
        currentProvider?.disconnect();
      } else if (!locked && wasExternallyBusy && !disposed && !saveConflict && !collaborationRejected) {
        if (currentProvider) { currentProvider.params.expected_updated_at = stamp; currentProvider.connect(); }
        if (dirty) scheduleSave();
      }
      if (!locked) externalQuiesced = false;
      wasExternallyBusy = locked;
    });
  });

  // Hash compaction extension: when the server's persisted log grows
  // past the configured threshold it sends a compact-request with a
  // 16-byte nonce; the chosen peer responds with Y.encodeStateAsUpdate
  // so the server can replace the bloated log with one snapshot.
  const MESSAGE_COMPACT = 4;
  const COMPACT_REQUEST = 0;
  const COMPACT_SNAPSHOT = 1;

  // Deterministic per-user colour so the remote-cursor caret stays
  // stable across sessions. Hash the user name into one of 8 pastels.
  function colourFor(name: string): string {
    const palette = ['#FF6B6B','#4ECDC4','#FFE66D','#A8E6CF','#FFD3B6','#C7B8EA','#95E1D3','#F38181'];
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return palette[h % palette.length];
  }

  function queueCollaborationReconnect(documentID: string) {
    if (disposed || externalBusy || saveConflict || collaborationRejected || doc.id !== documentID || reconnectTimer) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (!disposed && !externalBusy && !saveConflict && !collaborationRejected && doc.id === documentID) provider?.connect();
    }, 1000);
  }

  onMount(() => {
    ydoc = new Y.Doc();
    // Resolve the wss/ws scheme + base from window.location so dev (http)
    // + prod (https) both work without config.
    const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsBase = `${scheme}//${window.location.host}/api/v1/documents/${doc.id}`;
    provider = new WebsocketProvider(wsBase, 'collab', ydoc, {
      // y-websocket appends "/{room}" to the URL; we want the room
      // path to be the entire endpoint, so set room='' via the
      // override below. The library passes the constructor URL
      // unchanged when room is empty.
      connect: true,
      // A fresh empty collaboration generation may only be seeded from the
      // exact canonical document observed by this editor's initial HTTP read.
      params: { expected_updated_at: doc.updated_at },
      // Every replicated edit must cross the server's live authorization gate.
      // Same-origin BroadcastChannel traffic bypasses that document/session gate.
      disableBc: true
    });

    // Register our compact-request handler on the per-instance
    // messageHandlers array. Unknown message types are otherwise just
    // logged and dropped by y-websocket.
    // The handler writes the snapshot response into the encoder; the
    // surrounding readMessage() flushes the encoder to ws.send() when
    // it contains anything.
    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_COMPACT] = (
      encoder: encoding.Encoder,
      decoder: decoding.Decoder,
      prov: WebsocketProvider
    ) => {
      const subtype = decoding.readVarUint(decoder);
      if (subtype !== COMPACT_REQUEST || externalBusy) return;
      const nonce = decoding.readUint8Array(decoder, 16);
      const snapshot = Y.encodeStateAsUpdate(prov.doc);
      encoding.writeVarUint(encoder, MESSAGE_COMPACT);
      encoding.writeVarUint(encoder, COMPACT_SNAPSHOT);
      encoding.writeUint8Array(encoder, nonce);
      encoding.writeVarUint8Array(encoder, snapshot);
    };

    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_CHECKPOINT] = (
      _encoder: encoding.Encoder, decoder: decoding.Decoder
    ) => {
      try { checkpointRequests.receive(readSaveCheckpoint(decoder)); }
      catch (e) { checkpointRequests.cancel(e as Error); }
    };

    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_SAVED] = (
      _encoder: encoding.Encoder, decoder: decoding.Decoder
    ) => {
      try {
        const receipt = readCanonicalSaveReceipt(decoder);
        if (!disposed && isNewerSaveReceipt(canonicalGeneration, receipt)) {
          canonicalGeneration = receipt.generation;
          doc = { ...doc, updated_at: receipt.updatedAt };
          if (provider) provider.params.expected_updated_at = receipt.updatedAt;
        }
      } catch (e) {
        collaborationRejected = true;
        error = (e as Error).message;
        provider?.disconnect();
      }
    };

    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_GENERATION] = (
      _encoder: encoding.Encoder, decoder: decoding.Decoder
    ) => {
      try {
        canonicalGeneration = observeCanonicalGeneration(canonicalGeneration, readCanonicalGeneration(decoder));
      } catch (e) {
        collaborationRejected = true;
        connected = false;
        error = (e as Error).message;
        provider?.disconnect();
      }
    };

    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_BOOTSTRAP] = (
      _encoder: encoding.Encoder, decoder: decoding.Decoder
    ) => {
      mayBootstrap = readBootstrapGrant(decoder);
      if (!externalBusy && provider?.synced && editor && ydoc) {
        bootstrapIfGranted(ydoc, mayBootstrap, () => {
          editor!.commands.setContent(toProseMirror(doc.blocks_json) as never);
        });
      }
    };

    const label = userName?.trim() || 'You';
    const colour = userColor?.trim() || colourFor(label);

    provider.awareness.setLocalStateField('user', { name: label, color: colour });
    provider.on('status', (evt: { status: string }) => {
      connected = evt.status === 'connected';
      if (!connected) syncReady = false;
    });
    provider.on('connection-close', async (event: CloseEvent | null) => {
      checkpointRequests.cancel();
      if (disposed || externalBusy || saveConflict || collaborationRejected) return;
      const documentID = doc.id;
      // Pause y-websocket's reconnect timer until the HTTP observation has
      // been checked. disconnect() here would re-enter this close callback.
      if (provider) provider.shouldConnect = false;
      if (event?.code !== 1008) {
        if (accessCheckPending) return;
        accessCheckPending = true;
        // Browsers conceal failed-upgrade HTTP status, often exposing only
        // 1006. Distinguish revoked membership/session from transient outages.
        try {
          const current = await getMe();
          if (disposed || externalBusy || doc.id !== documentID || saveConflict || collaborationRejected) return;
          if (current.org_id === doc.org_id && (current.role === 'owner' || current.role === 'sender')) {
            const saved = await getDocument(documentID);
            if (disposed || externalBusy || doc.id !== documentID || saveConflict || collaborationRejected) return;
            if (saved.id === documentID && saved.org_id === doc.org_id && saved.source_kind === 'blocks'
                && saved.status === 'draft' && saved.updated_at === doc.updated_at
                && provider?.params.expected_updated_at === doc.updated_at) {
              queueCollaborationReconnect(documentID);
              return;
            }
            // Never adopt this GET's timestamp into the old Y.Doc or params:
            // that could let old content seed a newly recovered empty room.
          }
        } catch (e) {
          if (disposed || externalBusy || doc.id !== documentID || saveConflict || collaborationRejected) return;
          if (!(e instanceof APIError) || ![401, 403, 404].includes(e.status)) {
            queueCollaborationReconnect(documentID);
            return;
          }
        } finally {
          accessCheckPending = false;
        }
      }
      if (disposed || externalBusy || doc.id !== documentID) return;
      collaborationRejected = true;
      connected = false;
      // Policy rejection is terminal for this connection; repeatedly retrying
      // cannot repair authorization, document state or an oversized history.
      provider?.disconnect();
    });
    provider.awareness.on('change', () => {
      // Awareness map includes this client; size = collaborators count
      peerCount = provider!.awareness.getStates().size;
    });

    editor = new Editor({
      element: editorEl,
      editable: doc.status === 'draft' && !externalBusy,
      extensions: [
        // Collab replaces the default history (undo/redo) so disable
        // the StarterKit history extension to avoid duplicate stacks.
        StarterKit.configure({
          codeBlock: { HTMLAttributes: { class: 'hash-code' } },
          undoRedo: false
        }),
        BlockIDExtension,
        SignatureField,
        DynamicVariable,
        OpaqueBlock,
        PageBreak,
        TableBlock,
        Collaboration.configure({ document: ydoc }),
        CollaborationCaret.configure({
          provider,
          user: { name: label, color: colour }
        })
      ],
      onUpdate: () => {
        // The Y.Doc is the source of truth; we still write the
        // canonical blocks_json to the server on a debounced timer so
        // PDF render, audit cert, evidence bundle all keep working.
        editRevision++;
        dirty = true;
        scheduleSave();
      }
    });

    // The table nodeView dispatches this when its "Redigera" button is clicked.
    editorEl.addEventListener('hash-edit-table', ((e: CustomEvent) => {
      const d = e.detail as { pos: number; columns?: string[]; rows?: string[][] };
      openEditTable(d.pos, d.columns ?? [], d.rows ?? []);
    }) as EventListener);

    // Only the server-selected owner may seed a document with no Yjs history.
    provider.on('sync', (isSynced: boolean) => {
      syncReady = isSynced;
      if (externalBusy || !isSynced || !editor || !ydoc) return;
      bootstrapIfGranted(ydoc, mayBootstrap, () => {
        editor!.commands.setContent(toProseMirror(doc.blocks_json) as never);
      });
    });
  });

  onDestroy(() => {
    disposed = true;
    checkpointRequests.cancel(new Error('Editor closed'));
    if (saveTimer) clearTimeout(saveTimer);
    if (reconnectTimer) clearTimeout(reconnectTimer);
    editor?.destroy();
    provider?.destroy();
    ydoc?.destroy();
    onEditorStateChange?.(false);
  });

  beforeNavigate(({ cancel, willUnload }) => {
    if (!willUnload && dirty && !window.confirm('You have unsaved document changes. Leave this page and discard them?')) cancel();
  });

  function protectUnsavedDraft(event: BeforeUnloadEvent) {
    if (!dirty) return;
    event.preventDefault();
    event.returnValue = '';
  }

  function scheduleSave() {
    if (saveConflict || externalBusy) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(persist, 700);
  }

  function requestCheckpoint() {
    if (externalBusy || disposed || saveConflict) throw new Error('Document information is being updated; your local draft is preserved');
    return checkpointRequests.request((frame) => {
      const socket = provider?.ws;
      if (externalBusy || !socket || socket.readyState !== WebSocket.OPEN || !provider?.synced) {
        throw new Error('Collaboration is not synchronized; your draft is preserved');
      }
      socket.send(frame);
    });
  }

  async function persist() {
    if (!editor || disposed || saveConflict || externalBusy) return;
    if (saving) { saveQueued = true; return; }
    let submittedRevision = editRevision;
    saveQueued = false;
    saving = true;
    error = null;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const checkpoint = await requestCheckpoint();
          if (disposed || externalBusy) return;
          // The checkpoint response follows replay of the server's captured state.
          // Serialize that updated editor content, retaining edits made afterward.
          submittedRevision = editRevision;
          const json = editor.getJSON() as Record<string, unknown>;
          const tree = fromProseMirror(json);
          const receipt = await saveCollaborativeDocument(doc.id, {
            peer_id: checkpoint.peerID, checkpoint: checkpoint.token, generation: checkpoint.generation,
            expected_updated_at: doc.updated_at, blocks_json: tree
          });
          const updated = receipt.document;
          if (receipt.generation !== (BigInt(checkpoint.generation) + 1n).toString() || updated.id !== doc.id || !updated.updated_at) {
            throw new Error('Invalid canonical save receipt; your draft is preserved');
          }
          const currentReceipt = canonicalGeneration === null || BigInt(receipt.generation) >= BigInt(canonicalGeneration);
          if (!disposed && currentReceipt) {
            canonicalGeneration = receipt.generation;
            doc = { ...doc, updated_at: updated.updated_at };
            if (provider) provider.params.expected_updated_at = updated.updated_at;
          }
          if (!disposed && submittedRevision === editRevision) {
            if (currentReceipt) doc = updated;
            dirty = false;
            onChange?.(doc);
          }
          break;
        } catch (e) {
          if (!disposed && !externalBusy && e instanceof APIError && e.status === 409 && attempt < 2) {
            // Another accepted edit/save invalidated this checkpoint. Capture
            // again and serialize the replayed current state; never reuse a token.
            continue;
          }
          throw e;
        }
      }
    } catch (e) {
      if (!disposed) {
        error = (e as Error).message;
        if (e instanceof APIError && e.status === 412) {
          saveConflict = true;
          provider?.disconnect();
        }
      }
    } finally {
      saving = false;
      // Serialize writes and capture any subsequent save from current content.
      if (!disposed && !externalBusy && dirty && (saveQueued || submittedRevision !== editRevision)) scheduleSave();
    }
  }

  function downloadLocalDraft() {
    if (!editor || disposed) return false;
    const tree = fromProseMirror(editor.getJSON() as Record<string, unknown>);
    const blob = new Blob([JSON.stringify(tree, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `hash-local-draft-${doc.id}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return true;
  }

  function sharedEditingRecovered(documentID: string) {
    if (disposed || doc.id !== documentID) return;
    saveConflict = true;
    collaborationRejected = true;
    connected = false;
    if (saveTimer) clearTimeout(saveTimer);
    checkpointRequests.cancel();
    provider?.disconnect();
  }

  function reloadRecoveredDocument(documentID: string, revision: number) {
    if (disposed || doc.id !== documentID || revision !== editRevision) return;
    if (!window.confirm('Reload the current saved document? Your downloaded local draft is kept, and the local copy in this editor will be replaced.')) return;
    // Recheck after confirmation before permitting the unload. Recovery itself
    // never clears dirty state or replaces content in the current Y.Doc.
    if (disposed || doc.id !== documentID || revision !== editRevision) return;
    dirty = false;
    window.location.reload();
  }

  function manualSave() {
    if (externalBusy) return;
    if (saveTimer) clearTimeout(saveTimer);
    void persist();
  }

  function setHeading(level: 1 | 2) {
    if (externalBusy) return;
    editor?.chain().focus().toggleHeading({ level }).run();
  }
  function setParagraph() {
    if (externalBusy) return;
    editor?.chain().focus().setParagraph().run();
  }
  function toggleBullet() {
    if (externalBusy) return;
    editor?.chain().focus().toggleBulletList().run();
  }
  function toggleQuote() {
    if (externalBusy) return;
    editor?.chain().focus().toggleBlockquote().run();
  }
  function toggleCode() {
    if (externalBusy) return;
    editor?.chain().focus().toggleCodeBlock().run();
  }
  function insertHR() {
    if (externalBusy) return;
    editor?.chain().focus().setHorizontalRule().run();
  }
  function insertSignatureField() {
    if (externalBusy) return;
    const input = window.prompt(
      'Recipient role (lowercase letters, numbers, "_" or "-"; e.g. client, provider)?',
      'signer'
    );
    if (input === null) return;
    const role = input.trim();
    if (!isCanonicalSignatureRole(role)) {
      error =
        'Recipient role must start with a lowercase letter, use only lowercase letters, numbers, "_" or "-", and be at most 64 characters. Viewer and CC roles cannot sign.';
      return;
    }
    const label = window.prompt('Label (optional)?', 'Signature') || 'Signature';
    error = null;
    editor
      ?.chain()
      .focus()
      .insertContent({
        type: 'signatureField',
        attrs: { blockId: '', recipientRole: role, label, required: true }
      })
      .run();
  }
  function insertVariable() {
    if (externalBusy) return;
    if (!varName.trim()) return;
    editor
      ?.chain()
      .focus()
      .insertContent({
        type: 'dynamicVariable',
        attrs: { blockId: '', name: varName.trim(), fallback: varDefault.trim() }
      })
      .run();
    varName = '';
    varDefault = '';
  }
  function insertPageBreak() {
    if (externalBusy) return;
    editor?.chain().focus().insertContent({ type: 'pageBreak', attrs: { blockId: '' } }).run();
  }

  // ── Table authoring ──────────────────────────────────────────────────────
  function openNewTable() {
    if (externalBusy) return;
    editingTable = 'new';
    // Sensible starter: a services line-item grid the user can reshape.
    tCols = ['Tjänst', 'Beskrivning', 'Pris (kr ex moms)'];
    tRows = [['', '', ''], ['', '', '']];
    showTableModal = true;
  }
  function openEditTable(pos: number, columns: string[], rows: string[][]) {
    if (externalBusy) return;
    editingTable = pos;
    tCols = columns.length ? [...columns] : ['Kolumn 1'];
    tRows = rows.map((r) => [...r]);
    showTableModal = true;
  }
  function closeTableModal() {
    showTableModal = false;
    editingTable = null;
  }
  function addTableColumn() {
    tCols = [...tCols, `Kolumn ${tCols.length + 1}`];
    tRows = tRows.map((r) => [...r, '']);
  }
  function removeTableColumn(i: number) {
    if (tCols.length <= 1) return;
    tCols = tCols.filter((_, idx) => idx !== i);
    tRows = tRows.map((r) => r.filter((_, idx) => idx !== i));
  }
  function addTableRow() {
    tRows = [...tRows, tCols.map(() => '')];
  }
  function removeTableRow(i: number) {
    tRows = tRows.filter((_, idx) => idx !== i);
  }
  function saveTable() {
    if (!editor || externalBusy) return;
    // Keep rows rectangular against the columns (Go validation requires it).
    const columns = tCols.map((c) => c.trim() || ' ');
    const rows = tRows.map((r) => {
      const row = [...r];
      while (row.length < columns.length) row.push('');
      return row.slice(0, columns.length);
    });
    if (editingTable === 'new') {
      editor.chain().focus().insertContent({ type: 'tableBlock', attrs: { blockId: '', columns, rows } }).run();
    } else if (typeof editingTable === 'number') {
      editor.chain().focus().updateAttributes('tableBlock', { columns, rows }).run();
    }
    closeTableModal();
  }

  async function runImport() {
    if (saving || saveConflict || externalBusy || disposed || showImport === 'none') return;
    if (saveTimer) clearTimeout(saveTimer);
    const submittedRevision = editRevision;
    saving = true;
    saveQueued = false;
    error = null;
    try {
      const updated = showImport === 'html'
        ? await importHTML(doc.id, importText, doc.updated_at)
        : await importMarkdown(doc.id, importText, doc.updated_at);
      if (disposed || externalBusy) return;
      if (submittedRevision !== editRevision) {
        // Keep edits made during the import; the committed replacement needs
        // review before another canonical save can safely overwrite it.
        saveConflict = true;
        provider?.disconnect();
        error = 'The import was saved, but you edited while it was running. Download your local draft before reloading.';
        return;
      }
      doc = updated;
      editor?.commands.setContent(toProseMirror(updated.blocks_json) as never);
      dirty = false;
      showImport = 'none';
      importText = '';
      onChange?.(doc);
    } catch (e) {
      if (!disposed) {
        error = (e as Error).message;
        if (e instanceof APIError && e.status === 412) {
          saveConflict = true;
          provider?.disconnect();
        }
      }
    } finally {
      saving = false;
      if (!disposed && !externalBusy && !saveConflict && dirty && saveQueued) scheduleSave();
    }
  }

</script>

<svelte:window onbeforeunload={protectUnsavedDraft} />

<div class="block-editor-v2">
  {#if saveConflict}
    <div role="alert" class="collaboration-warning">
      <p>The document changed since your last save. Your edits have not been saved.
        Download your local draft before reloading the current document.</p>
      <button type="button" class="btn" onclick={downloadLocalDraft}>Download local draft</button>
    </div>
  {/if}
  {#if collaborationRejected}
    <div role="alert" class="collaboration-warning">
      <p>Live collaboration was stopped. Other editors may not receive your changes.
        Download your local draft before reloading, then check your access and document status.
        If access is valid, ask an administrator to check the document’s collaboration history.</p>
      <button type="button" class="btn" onclick={downloadLocalDraft}>Download local draft</button>
    </div>
  {/if}
  {#if collaborationRejected || saveConflict}
    {#key doc.id}
      <RecoveryPanel documentID={doc.id} orgID={doc.org_id} {editRevision}
        downloadDraft={downloadLocalDraft} onRecovered={sharedEditingRecovered} reloadDocument={reloadRecoveredDocument} />
    {/key}
  {/if}
  <fieldset disabled={externalBusy} class="min-w-0 border-0 p-0 m-0">
  {#if externalBusy}<p class="text-sm text-text-muted" role="status">Document information is being updated. Your local wording is retained.</p>{/if}
  <div class="toolbar">
    <button type="button" class="tool" onclick={() => setHeading(1)} title="H1"><Hash class="size-3.5" /> H1</button>
    <button type="button" class="tool" onclick={() => setHeading(2)} title="H2"><Hash class="size-3.5" /> H2</button>
    <button type="button" class="tool" onclick={setParagraph} title="Paragraph"><FileText class="size-3.5" /> P</button>
    <span class="sep"></span>
    <button type="button" class="tool" onclick={toggleBullet} title="Bullet list">• List</button>
    <button type="button" class="tool" onclick={toggleQuote} title="Quote"><Quote class="size-3.5" /></button>
    <button type="button" class="tool" onclick={toggleCode} title="Code"><CodeIcon class="size-3.5" /></button>
    <button type="button" class="tool" onclick={insertHR} title="Divider"><Minus class="size-3.5" /></button>
    <span class="sep"></span>
    <button type="button" class="tool tool-accent" onclick={insertSignatureField} title="Signature field">
      <Signature class="size-3.5" /> Sig field
    </button>
    <button type="button" class="tool" onclick={insertPageBreak} title="Page break">⤓ Page break</button>
    <button type="button" class="tool" onclick={openNewTable} title="Insert table"><TableIcon class="size-3.5" /> Table</button>
    <span class="sep"></span>

    <div class="var-form">
      <Variable class="size-3.5" />
      <input bind:value={varName} placeholder="var.name" class="var-input" />
      <input bind:value={varDefault} placeholder="default" class="var-input narrow" />
      <button type="button" class="tool" onclick={insertVariable} disabled={!varName.trim()}>Insert</button>
    </div>

    <span class="sep"></span>
    <button type="button" class="tool" onclick={() => (showImport = 'html')}>Import HTML</button>
    <button type="button" class="tool" onclick={() => (showImport = 'md')}>Import MD</button>

    <div class="status">
      <span class="status-text" title={connected ? `${peerCount} collaborator${peerCount === 1 ? '' : 's'}` : 'Connecting…'}>
        <Users class="size-3.5 inline" />
        {peerCount}
        {#if !connected}<span class="status-error"> · offline</span>{/if}
      </span>
      {#if saving}
        <span class="status-text">Saving…</span>
      {:else if saveConflict}
        <button type="button" class="tool tool-primary" onclick={downloadLocalDraft}>Download local draft</button>
      {:else if dirty}
        <button type="button" class="tool tool-primary" onclick={manualSave}>
          <Save class="size-3.5" /> Save
        </button>
      {:else}
        <span class="status-text">Saved</span>
      {/if}
      {#if error}
        <span class="status-text status-error">{error}</span>
      {/if}
    </div>
  </div>

  {#if showImport !== 'none'}
    <div class="card p-4 mb-3">
      <label class="block text-sm font-medium mb-1" for="import-text">
        Replace document with {showImport === 'html' ? 'HTML' : 'Markdown'}
      </label>
      <textarea
        id="import-text"
        bind:value={importText}
        rows="8"
        class="w-full p-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs"
      ></textarea>
      <div class="flex gap-2 mt-2">
        <button type="button" class="btn btn-primary" onclick={runImport}>Replace</button>
        <button type="button" class="btn btn-secondary" onclick={() => (showImport = 'none')}>Cancel</button>
      </div>
    </div>
  {/if}

  <div bind:this={editorEl} class="prose-host"></div>
  </fieldset>
</div>

{#if showTableModal}
  <div class="tbl-backdrop" role="dialog" aria-modal="true">
    <div class="tbl-modal">
      <fieldset disabled={externalBusy} class="min-w-0 border-0 p-0 m-0">
      <div class="tbl-modal-head">
        <h3>{editingTable === 'new' ? 'Insert table' : 'Edit table'}</h3>
        <button type="button" class="tbl-x" onclick={closeTableModal} aria-label="Close"><X class="size-4" /></button>
      </div>
      <p class="tbl-hint">
        Each column is a header; each row is a line item. Type <code>{'{{namn}}'}</code> in any cell
        to drop in a placeholder that gets filled per document.
      </p>

      <div class="tbl-scroll">
        <table class="tbl-grid">
          <thead>
            <tr>
              <th class="tbl-rownum"></th>
              {#each tCols as _col, ci (ci)}
                <th>
                  <div class="tbl-colhead">
                    <input class="tbl-input tbl-input-head" bind:value={tCols[ci]} placeholder={`Kolumn ${ci + 1}`} />
                    <button type="button" class="tbl-mini" title="Remove column" onclick={() => removeTableColumn(ci)} disabled={tCols.length <= 1}>
                      <X class="size-3" />
                    </button>
                  </div>
                </th>
              {/each}
              <th class="tbl-addcol">
                <button type="button" class="tbl-mini" title="Add column" onclick={addTableColumn}><Plus class="size-3" /></button>
              </th>
            </tr>
          </thead>
          <tbody>
            {#each tRows as _row, ri (ri)}
              <tr>
                <td class="tbl-rownum">{ri + 1}</td>
                {#each tCols as _c, ci (ci)}
                  <td><input class="tbl-input" bind:value={tRows[ri][ci]} placeholder="…" /></td>
                {/each}
                <td class="tbl-rowdel">
                  <button type="button" class="tbl-mini" title="Remove row" onclick={() => removeTableRow(ri)}><X class="size-3" /></button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <div class="tbl-actions">
        <button type="button" class="tool" onclick={addTableRow}><Plus class="size-3.5" /> Add row</button>
        <span style="flex:1"></span>
        <button type="button" class="btn btn-secondary" onclick={closeTableModal}>Cancel</button>
        <button type="button" class="btn btn-primary" onclick={saveTable}>
          {editingTable === 'new' ? 'Insert table' : 'Save table'}
        </button>
      </div>
      </fieldset>
    </div>
  </div>
{/if}

<style>
  .block-editor-v2 {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .collaboration-warning { padding: 1rem; border: 1px solid currentColor; margin-bottom: 1rem; }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    align-items: center;
    padding: 0.5rem;
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.75rem;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .tool {
    background: transparent;
    border: 1px solid var(--t-border-light);
    border-radius: 0.375rem;
    padding: 0.3rem 0.6rem;
    font-size: 0.8rem;
    color: var(--t-text-primary);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    transition: background 150ms ease;
  }
  .tool:hover { background: var(--t-bg-hover); }
  .tool:disabled { opacity: 0.4; cursor: not-allowed; }
  .tool-primary { background: var(--t-accent); color: var(--t-accent-foreground); border-color: var(--t-accent); }
  .tool-primary:hover { background: var(--t-accent-hover); }
  .tool-accent { color: var(--t-accent); border-color: var(--t-accent); }
  .sep { width: 1px; height: 18px; background: var(--t-border-light); margin: 0 0.25rem; }
  .var-form { display: inline-flex; align-items: center; gap: 0.25rem; padding: 0 0.25rem; }
  .var-input {
    width: 110px;
    padding: 0.2rem 0.4rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.25rem;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    background: var(--t-bg-elevated);
  }
  .var-input.narrow { width: 70px; }
  .status { margin-left: auto; display: inline-flex; gap: 0.5rem; align-items: center; }
  .status-text { font-size: 0.7rem; color: var(--t-text-muted); font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.1em; }
  .status-error { color: var(--t-danger); }

  .prose-host :global(.ProseMirror) {
    min-height: 60vh;
    padding: 2rem 2.5rem;
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    outline: none;
    line-height: 1.6;
    font-family: var(--font-sans);
  }
  .prose-host :global(.ProseMirror h1) {
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 2rem;
    margin: 1.5rem 0 0.75rem;
  }
  .prose-host :global(.ProseMirror h2) {
    font-family: var(--font-display);
    font-weight: 300;
    font-size: 1.5rem;
    margin: 1.25rem 0 0.5rem;
  }
  .prose-host :global(.ProseMirror p) { margin: 0.6rem 0; }
  .prose-host :global(.ProseMirror ul) { padding-left: 1.5rem; list-style: disc; }
  .prose-host :global(.ProseMirror ol) { padding-left: 1.5rem; list-style: decimal; }
  .prose-host :global(.ProseMirror blockquote) {
    border-left: 3px solid var(--t-border);
    padding-left: 0.75rem;
    color: var(--t-text-secondary);
    font-style: italic;
    margin: 0.75rem 0;
  }
  .prose-host :global(.ProseMirror hr) {
    border: 0;
    border-top: 1px solid var(--t-border);
    margin: 1.25rem 0;
  }
  .prose-host :global(.ProseMirror pre) {
    background: var(--t-bg-elevated);
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 0.75rem;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    overflow-x: auto;
  }
  .prose-host :global(.hash-sig-chip) {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.4rem 0.75rem;
    margin: 0.4rem 0;
    background: var(--t-bg-elevated);
    border: 1px dashed var(--t-accent);
    border-radius: 0.5rem;
    font-size: 0.85rem;
    color: var(--t-accent);
    font-family: var(--font-mono);
  }
  .prose-host :global(.hash-var-chip) {
    display: inline-block;
    padding: 0.05rem 0.35rem;
    background: var(--t-info);
    color: white;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-family: var(--font-mono);
    margin: 0 0.1rem;
  }
  .prose-host :global(.hash-pagebreak-chip) {
    display: block;
    padding: 0.5rem 0.75rem;
    margin: 1rem 0;
    text-align: center;
    background: var(--t-bg-elevated);
    border: 1px dashed var(--t-border);
    border-radius: 0.5rem;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    color: var(--t-text-muted);
  }
  .prose-host :global(.hash-sig-chip.ProseMirror-selectednode),
  .prose-host :global(.hash-pagebreak-chip.ProseMirror-selectednode),
  .prose-host :global(.hash-table-block.ProseMirror-selectednode) {
    outline: 2px solid var(--t-accent);
    outline-offset: 2px;
  }

  /* Table block: live preview inside the editor */
  .prose-host :global(.hash-table-block) {
    margin: 0.9rem 0;
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    overflow: hidden;
    background: var(--t-bg-surface);
  }
  .prose-host :global(.hash-table-bar) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.35rem 0.6rem;
    background: var(--t-bg-elevated);
    border-bottom: 1px solid var(--t-border-light);
  }
  .prose-host :global(.hash-table-tag) {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--t-text-muted);
  }
  .prose-host :global(.hash-table-btn) {
    border: 1px solid var(--t-accent);
    color: var(--t-accent);
    background: transparent;
    border-radius: 0.3rem;
    padding: 0.15rem 0.55rem;
    font-size: 0.72rem;
    cursor: pointer;
  }
  .prose-host :global(.hash-table-btn:hover) { background: var(--t-bg-hover); }
  .prose-host :global(.hash-table-block table) {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }
  .prose-host :global(.hash-table-block th),
  .prose-host :global(.hash-table-block td) {
    border: 1px solid var(--t-border-light);
    padding: 0.35rem 0.55rem;
    text-align: left;
    vertical-align: top;
  }
  .prose-host :global(.hash-table-block th) {
    background: var(--t-bg-elevated);
    font-weight: 600;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--t-text-secondary);
  }

  /* Table editor modal */
  .tbl-backdrop {
    position: fixed; inset: 0; z-index: 50;
    background: rgba(10, 10, 10, 0.5);
    display: flex; align-items: center; justify-content: center;
    padding: 1.5rem;
  }
  .tbl-modal {
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.9rem;
    width: 100%; max-width: 880px;
    max-height: 86vh; display: flex; flex-direction: column;
    box-shadow: 0 24px 70px rgba(0,0,0,0.3);
  }
  .tbl-modal-head {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1rem 1.25rem 0.5rem;
  }
  .tbl-modal-head h3 { font-family: var(--font-display); font-weight: 300; font-size: 1.25rem; margin: 0; }
  .tbl-x { background: transparent; border: 0; cursor: pointer; color: var(--t-text-muted); padding: 0.25rem; border-radius: 0.3rem; }
  .tbl-x:hover { background: var(--t-bg-hover); }
  .tbl-hint { padding: 0 1.25rem; font-size: 0.8rem; color: var(--t-text-muted); margin: 0 0 0.75rem; }
  .tbl-hint code { font-family: var(--font-mono); background: var(--t-bg-elevated); padding: 0.05rem 0.3rem; border-radius: 0.25rem; }
  .tbl-scroll { overflow: auto; padding: 0 1.25rem; }
  .tbl-grid { border-collapse: separate; border-spacing: 0; width: 100%; }
  .tbl-grid th, .tbl-grid td { padding: 0.15rem; vertical-align: middle; }
  .tbl-rownum { width: 1.6rem; text-align: center; font-size: 0.7rem; color: var(--t-text-muted); font-family: var(--font-mono); }
  .tbl-colhead { display: flex; align-items: center; gap: 0.2rem; }
  .tbl-input {
    width: 100%; min-width: 120px;
    padding: 0.4rem 0.5rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.35rem;
    background: var(--t-bg-elevated);
    font-size: 0.82rem; color: var(--t-text-primary);
  }
  .tbl-input-head { font-weight: 600; }
  .tbl-input:focus { outline: none; border-color: var(--t-accent); }
  .tbl-mini {
    flex: none;
    width: 1.4rem; height: 1.4rem;
    display: inline-flex; align-items: center; justify-content: center;
    border: 1px solid var(--t-border-light); border-radius: 0.3rem;
    background: var(--t-bg-surface); color: var(--t-text-muted); cursor: pointer;
  }
  .tbl-mini:hover:not(:disabled) { background: var(--t-bg-hover); color: var(--t-text-primary); }
  .tbl-mini:disabled { opacity: 0.3; cursor: not-allowed; }
  .tbl-addcol, .tbl-rowdel { width: 1.6rem; }
  .tbl-actions {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 1rem 1.25rem; border-top: 1px solid var(--t-border-light); margin-top: 0.75rem;
  }

  /* Remote collaborator cursors (y-prosemirror + CollaborationCaret) */
  .prose-host :global(.collaboration-carret-caret) {
    border-left: 1px solid currentColor;
    border-right: 1px solid currentColor;
    margin-left: -1px;
    margin-right: -1px;
    pointer-events: none;
    position: relative;
    word-break: normal;
  }
  .prose-host :global(.collaboration-carret-label) {
    position: absolute;
    top: -1.4em;
    left: -1px;
    font-size: 0.65rem;
    font-family: var(--font-mono);
    padding: 0.05rem 0.35rem;
    border-radius: 0.25rem;
    color: white;
    white-space: nowrap;
    user-select: none;
    pointer-events: none;
    line-height: 1;
  }
  .prose-host :global(.collaboration-carret-selection) {
    background-color: color-mix(in srgb, currentColor 20%, transparent);
  }
</style>
