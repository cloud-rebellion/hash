<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { page } from '$app/stores';
  import { beforeNavigate } from '$app/navigation';
  import {
    getDocument,
    getMe,
    updateDocument,
    createBlocksTemplate,
    documentSignatureFields,
    listChangeRequests,
    reviseDocument,
    approveChangeRequest,
    denyChangeRequest,
    setChangeApprovalMode,
    listComments,
    postComment,
    previewURL,
    documentPdfURL,
    type DocumentResponse,
    type ChangeRequest,
    type DocComment,
  } from '$lib/api/client';
  import BlockEditor from '$lib/components/BlockEditor/Editor.svelte';
  import RiskPanel from '$lib/components/RiskPanel.svelte';
  import AgentTokensPanel from '$lib/components/AgentTokensPanel.svelte';
  import EnvelopePanel from '$lib/components/EnvelopePanel.svelte';
  import SenderPanel from '$lib/components/SenderPanel.svelte';
  import TimelinePanel from '$lib/components/TimelinePanel.svelte';
  import PdfFieldDesigner from '$lib/components/PdfFieldDesigner.svelte';
  import SavePDFTemplate from '$lib/components/SavePDFTemplate.svelte';
  import HtmlPDFReview from '$lib/components/HtmlPDFReview.svelte';
  import HtmlDocumentRevision from '$lib/components/HtmlDocumentRevision.svelte';
  import HtmlDocumentHistory from '$lib/components/HtmlDocumentHistory.svelte';
  import { htmlUUID } from '$lib/htmlRevision';
  import { ArrowLeft, Eye, Sparkles, Save } from 'lucide-svelte';

  let doc = $state<DocumentResponse | null>(null);
  let userName = $state('You');
  let viewerRole = $state('');
  let viewerUserID = $state('');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let showPreview = $state(false);
  let recipientRevision = $state(0);
  let savingTemplate = $state(false);
  let savedTemplateFlash = $state(false);
  let showPDFSave = $state(false);
  let pdfSignatureFields = $state<{ role: string; label: string }[]>([]);
  let htmlRevisionBlocked = $state(true);
  let changeRequests = $state<ChangeRequest[]>([]);
  let revising = $state(false);
  let approvalMode = $state<'accept' | 'auto_apply'>('accept');
  let resolvingId = $state<string | null>(null);
  let comments = $state<DocComment[]>([]);
  let commentBody = $state('');
  let postingComment = $state(false);
  let commentLoadRevision = 0;
  let commentRefreshError = $state<string | null>(null);
  let savingMode = $state(false);
  let changeRequestRefreshError = $state<string | null>(null);
  let refreshingChanges = $state(false);
  let savingApprovalMode = $state(false);
  let changeRequestLoadRevision = 0;
  let routeRevision = $state(0);
  let documentRevision = $state(0);
  let disposed = false;
  let templateFlashTimer: ReturnType<typeof setTimeout> | null = null;
  const routeDocumentID = $derived($page.params.id);

  type DocumentScope = { id: string; routeRevision: number; documentRevision: number };
  function isCurrentRoute(id: string, revision: number): boolean {
    return !disposed && revision === routeRevision && id === $page.params.id;
  }
  function captureDocument(): DocumentScope | null {
    if (!doc || !isCurrentRoute(doc.id, routeRevision)) return null;
    return { id: doc.id, routeRevision, documentRevision };
  }
  function isCurrentDocument(scope: DocumentScope, unchanged = false): boolean {
    return isCurrentRoute(scope.id, scope.routeRevision) && doc?.id === scope.id
      && (!unchanged || scope.documentRevision === documentRevision);
  }
  function receiveDocument(updated: DocumentResponse, scope: DocumentScope): boolean {
    if (!isCurrentDocument(scope, true) || updated.id !== scope.id || updated.org_id !== doc?.org_id) return false;
    resetPDFPlacement(updated);
    doc = updated;
    documentRevision++;
    return true;
  }
  function receiveEditorDocument(updated: DocumentResponse, scope: DocumentScope) {
    if (!isCurrentDocument(scope) || updated.id !== scope.id || updated.org_id !== doc?.org_id) return;
    resetPDFPlacement(updated);
    doc = updated;
    documentRevision++;
  }
  function resetPDFPlacement(updated: DocumentResponse) {
    if (!doc || doc.id !== updated.id || doc.pdf_sha256 !== updated.pdf_sha256
        || doc.html_source_commitment !== updated.html_source_commitment || doc.html_materialization_revision !== updated.html_materialization_revision) {
      pdfSignatureFields = [];
      htmlRevisionBlocked = true;
      recipientRevision++;
      showPDFSave = false;
    }
  }
  async function refreshHTMLDocument() {
    const scope = captureDocument();
    if (!scope) return;
    try { receiveDocument(await getDocument(scope.id), scope); }
    catch (e) { if (isCurrentDocument(scope)) error = (e as Error).message; }
  }
  function receiveStatus(next: string, scope: DocumentScope) {
    if (!doc || !isCurrentDocument(scope)) return;
    doc = { ...doc, status: next };
    documentRevision++;
  }
  async function changeDefaultLocale(locale: string, scope: DocumentScope) {
    if (!doc || !isCurrentDocument(scope)) return;
    const actionScope = captureDocument();
    if (!actionScope) return;
    try {
      const updated = await updateDocument(actionScope.id, { expected_updated_at: doc.updated_at, default_locale: locale });
      receiveDocument(updated, actionScope);
    } catch (e) {
      if (isCurrentDocument(actionScope)) error = (e as Error).message;
    }
  }

  async function toggleSignatureMode() {
    const scope = captureDocument();
    if (!scope || !doc || doc.status !== 'draft' || savingMode || revising || resolvingId) return;
    savingMode = true;
    error = null;
    try {
      const updated = await updateDocument(scope.id, { expected_updated_at: doc.updated_at, requires_signature: !doc.requires_signature });
      receiveDocument(updated, scope);
    } catch (e) {
      if (isCurrentDocument(scope)) error = (e as Error).message;
    } finally {
      if (isCurrentDocument(scope)) savingMode = false;
    }
  }

  async function loadComments(id: string) {
    const scope = captureDocument();
    if (!scope || scope.id !== id) return;
    const revision = ++commentLoadRevision;
    try {
      const res = await listComments(id);
      if (revision === commentLoadRevision && isCurrentDocument(scope)) {
        comments = res.comments;
        commentRefreshError = null;
      }
    } catch (e) {
      if (revision === commentLoadRevision && isCurrentDocument(scope)) {
        commentRefreshError = `Messages could not be refreshed. ${(e as Error).message}`;
      }
    }
  }

  async function sendComment() {
    const scope = captureDocument();
    if (!scope || postingComment || !commentBody.trim()) return;
    const documentID = scope.id;
    const submittedBody = commentBody;
    postingComment = true;
    error = null;
    try {
      await postComment(documentID, submittedBody.trim());
      if (!isCurrentDocument(scope)) return;
      if (commentBody === submittedBody) commentBody = '';
      await loadComments(documentID);
    } catch (e) {
      if (isCurrentDocument(scope)) error = (e as Error).message;
    } finally {
      if (isCurrentDocument(scope)) postingComment = false;
    }
  }

  async function loadChangeRequests(id: string) {
    const scope = captureDocument();
    if (!scope || scope.id !== id) return;
    const revision = ++changeRequestLoadRevision;
    refreshingChanges = true;
    try {
      const res = await listChangeRequests(id);
      if (revision === changeRequestLoadRevision && isCurrentDocument(scope, true)) {
        changeRequests = res.change_requests;
        changeRequestRefreshError = null;
      }
    } catch (e) {
      if (revision === changeRequestLoadRevision && isCurrentDocument(scope, true)) {
        changeRequestRefreshError = `Change requests could not be refreshed. ${(e as Error).message}`;
      }
    } finally {
      if (revision === changeRequestLoadRevision && isCurrentDocument(scope)) refreshingChanges = false;
    }
  }

  async function resolveCr(cr: ChangeRequest, approve: boolean) {
    const scope = captureDocument();
    if (!scope || doc?.status !== 'changes_requested' || resolvingId || revising || savingMode || !changeRequests.some((request) => request.id === cr.id && request.status === 'open')) return;
    resolvingId = cr.id;
    error = null;
    try {
      if (approve) await approveChangeRequest(scope.id, cr.id);
      else await denyChangeRequest(scope.id, cr.id);
      if (isCurrentDocument(scope)) await loadChangeRequests(scope.id);
    } catch (e) {
      if (isCurrentDocument(scope)) error = (e as Error).message;
    } finally {
      if (isCurrentDocument(scope)) resolvingId = null;
    }
  }

  async function changeApprovalMode(mode: 'accept' | 'auto_apply') {
    const scope = captureDocument();
    if (!scope || savingApprovalMode) return;
    const previousMode = approvalMode;
    savingApprovalMode = true;
    approvalMode = mode;
    try {
      await setChangeApprovalMode(mode);
    } catch (e) {
      if (isCurrentDocument(scope)) {
        approvalMode = previousMode;
        error = (e as Error).message;
      }
    } finally {
      if (isCurrentDocument(scope)) savingApprovalMode = false;
    }
  }

  async function revise() {
    const scope = captureDocument();
    if (!scope || doc?.status !== 'changes_requested' || revising || resolvingId || savingMode) return;
    revising = true;
    error = null;
    try {
      const updated = await reviseDocument(scope.id);
      if (!receiveDocument(updated, scope)) return;
      changeRequests = [];
      showPreview = false; // back to the editor so the sender can make the changes
    } catch (e) {
      if (isCurrentDocument(scope)) error = (e as Error).message;
    } finally {
      if (isCurrentDocument(scope)) revising = false;
    }
  }

  async function saveAsTemplate() {
    const scope = captureDocument();
    if (!scope || !doc || savingTemplate) return;
    const submittedDocument = doc;
    const name = window.prompt('Template name?', `${doc.name} (mall)`);
    if (!name) return;
    savingTemplate = true;
    error = null;
    try {
      await createBlocksTemplate(name, {
        blocks_json: submittedDocument.blocks_json,
        variables_json: submittedDocument.variables_json,
      });
      if (!isCurrentDocument(scope)) return;
      savedTemplateFlash = true;
      if (templateFlashTimer) clearTimeout(templateFlashTimer);
      templateFlashTimer = setTimeout(() => {
        if (isCurrentDocument(scope)) savedTemplateFlash = false;
      }, 3000);
    } catch (e) {
      if (isCurrentDocument(scope)) error = (e as Error).message;
    } finally {
      if (isCurrentDocument(scope)) savingTemplate = false;
    }
  }

  async function loadDocument(id: string, revision: number) {
    if (!id) {
      error = 'Missing document id';
      loading = false;
      return;
    }
    try {
      const [d, me] = await Promise.all([getDocument(id), getMe().catch(() => null)]);
      if (!isCurrentRoute(id, revision)) return;
      if (d.id !== id) throw new Error('The server returned a different document.');
      resetPDFPlacement(d); doc = d;
      documentRevision++;
      const verifiedIdentity = me && htmlUUID(me.org_id) && htmlUUID(me.user_id) && me.org_id === d.org_id && ['owner', 'sender', 'viewer'].includes(me.role);
      viewerRole = verifiedIdentity ? me.role : '';
      viewerUserID = verifiedIdentity ? me.user_id : '';
      // A draft opens in the editor; anything already sent opens read-only so
      // the sender reviews the frozen content rather than appearing to edit it.
      showPreview = d.status !== 'draft';
      if (d.status === 'changes_requested') {
        void loadChangeRequests(d.id);
      }
      if (d.status !== 'draft' || d.has_html_source) {
        void loadComments(d.id);
      }
      if (me?.email) {
        userName = me.email.split('@')[0] || me.email;
      }
      if (me?.change_approval_mode === 'auto_apply' || me?.change_approval_mode === 'accept') {
        approvalMode = me.change_approval_mode;
      }
    } catch (e) {
      if (isCurrentRoute(id, revision)) error = (e as Error).message;
    } finally {
      if (isCurrentRoute(id, revision)) loading = false;
    }
  }

  function resetRouteState() {
    doc = null;
    userName = 'You';
    viewerRole = '';
    viewerUserID = '';
    loading = true;
    error = null;
    showPreview = false;
    savingTemplate = false;
    savedTemplateFlash = false;
    showPDFSave = false;
    pdfSignatureFields = [];
    htmlRevisionBlocked = true;
    changeRequests = [];
    revising = false;
    approvalMode = 'accept';
    resolvingId = null;
    comments = [];
    commentBody = '';
    postingComment = false;
    commentRefreshError = null;
    savingMode = false;
    changeRequestRefreshError = null;
    refreshingChanges = false;
    savingApprovalMode = false;
    commentLoadRevision++;
    changeRequestLoadRevision++;
    documentRevision++;
    if (templateFlashTimer) clearTimeout(templateFlashTimer);
    templateFlashTimer = null;
  }

  $effect(() => {
    const id = routeDocumentID;
    const revision = untrack(() => ++routeRevision);
    untrack(() => {
      resetRouteState();
      if (!id) {
        error = 'Missing document id';
        loading = false;
        return;
      }
      void loadDocument(id, revision);
    });
    return () => { untrack(() => routeRevision++); };
  });

  beforeNavigate(({ cancel, willUnload, from, to }) => {
    if (!willUnload && to?.url.pathname !== from?.url.pathname && commentBody.trim()
        && !window.confirm('You have an unsent comment. Leave this document and discard the draft?')) cancel();
  });
  function protectCommentDraft(event: BeforeUnloadEvent) {
    if (!commentBody.trim()) return;
    event.preventDefault();
    event.returnValue = '';
  }
  onMount(() => {
    window.addEventListener('beforeunload', protectCommentDraft);
    return () => window.removeEventListener('beforeunload', protectCommentDraft);
  });
  onDestroy(() => {
    disposed = true;
    routeRevision++;
    if (templateFlashTimer) clearTimeout(templateFlashTimer);
  });
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <a class="text-sm text-text-secondary hover:underline inline-flex items-center gap-1 mb-4" href="/documents">
    <ArrowLeft class="size-3" /> Back to documents
  </a>

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if error && !doc}
    <div class="card p-6 text-danger">{error}</div>
  {:else if doc && doc.id === $page.params.id}
    {#key doc.id}
    {@const documentScope = { id: doc.id, routeRevision, documentRevision }}
    {#if error}<div role="alert" class="card p-4 text-danger mb-4">{error}</div>{/if}
    <div class="mb-6 space-y-2">
      <p class="page-eyebrow">Document · {doc.status}</p>
      <div class="flex flex-col items-start gap-4 sm:flex-row sm:items-baseline sm:justify-between">
        <h1 class="page-title min-w-0 w-full break-words sm:flex-1">{doc.name}</h1>
        <div class="flex max-w-full flex-wrap gap-2">
          <button class="btn btn-secondary" onclick={() => (showPreview = !showPreview)}>
            <Eye class="size-4" /> {showPreview ? 'Edit' : 'Preview'}
          </button>
          {#if doc.source_kind === 'blocks'}
            <button class="btn btn-secondary" disabled={savingTemplate} onclick={saveAsTemplate}>
              <Save class="size-4" /> {savedTemplateFlash ? 'Saved!' : savingTemplate ? 'Saving…' : 'Save as template'}
            </button>
          {:else if doc.status === 'draft' && !doc.has_html_source}
            <button class="btn btn-secondary" onclick={() => (showPDFSave = !showPDFSave)}>
              <Save class="size-4" /> {savedTemplateFlash ? 'Saved!' : 'Save as template'}
            </button>
          {/if}
          <a class="btn btn-secondary" href="/settings/api-keys">
            <Sparkles class="size-4" /> Attach AI
          </a>
        </div>
      </div>
    </div>

    {#if showPDFSave && doc.status === 'draft' && doc.source_kind === 'pdf' && !doc.has_html_source}
      <SavePDFTemplate document={doc} onClose={() => (showPDFSave = false)} onSaved={() => {
        if (isCurrentDocument(documentScope)) { showPDFSave = false; savedTemplateFlash = true; }
      }} />
    {/if}

    {#if doc.status === 'draft' && doc.has_html_source}
      {#key doc.id}
        <HtmlDocumentRevision document={doc} onRevised={(updated) => receiveDocument(updated, documentScope)}
          onStateChange={(blocked) => { if (isCurrentDocument(documentScope)) htmlRevisionBlocked = blocked; }} />
      {/key}
      {#key `${doc.id}:${doc.updated_at}:${doc.pdf_sha256}:${doc.html_source_commitment}`}
        <HtmlPDFReview document={doc} revisionBlocked={htmlRevisionBlocked}
          canReview={viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id)}
          onReviewed={(updated) => receiveDocument(updated, documentScope)} onRefresh={refreshHTMLDocument} />
      {/key}
    {/if}
    {#if doc.has_html_source}{#key doc.id}<HtmlDocumentHistory document={doc} />{/key}{/if}

    {#if doc.status === 'draft'}
      <div class="card p-4 mb-6 flex items-center justify-between gap-4">
        <div>
          <p class="text-sm font-medium">Signeringsläge</p>
          <p class="text-xs text-text-muted">
            {doc.requires_signature
              ? 'Kräver signatur: mottagarna signerar dokumentet.'
              : 'Bara läsa och acceptera: mottagarna öppnar och klickar Acceptera. Ingen signatur.'}
          </p>
        </div>
        <button class="btn btn-secondary whitespace-nowrap" disabled={savingMode} onclick={toggleSignatureMode}>
          {savingMode ? 'Sparar…' : doc.requires_signature ? 'Byt till acceptera' : 'Kräv signatur'}
        </button>
      </div>
    {/if}

    {#if doc.status === 'changes_requested'}
      <div class="card p-5 mb-6 border-l-4 border-warning">
        <h2 class="font-display font-extralight text-lg mb-1">Ändringar begärda</h2>
        <p class="text-sm text-text-secondary mb-3 leading-relaxed">
          En part har begärt ändringar. Signering är pausad. Revidera dokumentet,
          gör ändringarna och skicka det för signering igen.
        </p>
        {#if !doc.has_html_source}<div class="flex flex-wrap items-center gap-2 mb-4 text-xs">
          <span class="uppercase tracking-widest text-text-muted font-mono">Vid godkännande</span>
          <button
            class="px-2 py-1 rounded-md border {approvalMode === 'accept' ? 'border-accent text-accent' : 'border-border-light text-text-muted'}"
            onclick={() => changeApprovalMode('accept')}
            disabled={savingApprovalMode}
          >Markera godkänd (ändra vid revidering)</button>
          <button
            class="px-2 py-1 rounded-md border {approvalMode === 'auto_apply' ? 'border-accent text-accent' : 'border-border-light text-text-muted'}"
            onclick={() => changeApprovalMode('auto_apply')}
            disabled={savingApprovalMode}
          >Tillämpa föreslagen text automatiskt</button>
          <span class="text-text-muted">(global inställning)</span>
        </div>{:else}<p class="text-sm text-text-secondary mb-4">Approving a request records your decision. It does not apply proposed wording. Reopen the document, update its declared values or wording, and review the newly rendered PDF before sending again.</p>{/if}

        {#if changeRequestRefreshError}
          <div role="alert" class="text-danger mb-4">
            <p>{changeRequestRefreshError}</p>
            <button type="button" class="btn btn-secondary" disabled={refreshingChanges} onclick={() => doc && loadChangeRequests(doc.id)}>Retry change request refresh</button>
          </div>
        {/if}
        <button type="button" class="btn btn-secondary mb-4" disabled={refreshingChanges} onclick={() => doc && loadChangeRequests(doc.id)}>
          {refreshingChanges ? 'Refreshing change requests…' : 'Refresh change requests'}
        </button>

        {#if changeRequests.length}
          <ul class="space-y-3 mb-4">
            {#each changeRequests as cr (cr.id)}
              <li data-change-request-id={cr.id} class="rounded-md border border-border-light bg-bg-elevated p-3">
                <p class="text-xs text-text-muted mb-1">
                  {cr.recipient_name || 'Mottagare'}{cr.recipient_email ? ` · ${cr.recipient_email}` : ''}
                  · {new Date(cr.created_at).toLocaleString()}
                  {#if cr.resolution === 'approved'}· <span class="text-success">godkänd</span>{:else if cr.resolution === 'denied'}· <span class="text-danger">nekad</span>{/if}
                </p>
                {#if cr.quote}
                  <p class="text-sm border-l-2 border-accent pl-2 mb-1"><span class="text-text-muted text-xs">Markerat: </span>{cr.quote}</p>
                {/if}
                {#if cr.message}<p class="text-sm whitespace-pre-wrap mb-1">{cr.message}</p>{/if}
                {#if cr.proposed}<p class="text-sm text-success"><span class="text-text-muted text-xs">Föreslår: </span>{cr.proposed}</p>{/if}
                {#if cr.status === 'open'}
                  <div class="flex gap-2 mt-2">
                    <button class="btn btn-primary text-xs" disabled={!!resolvingId || revising} onclick={() => resolveCr(cr, true)}>Godkänn</button>
                    <button class="btn btn-secondary text-xs" disabled={!!resolvingId || revising} onclick={() => resolveCr(cr, false)}>Neka</button>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
        <button class="btn btn-primary" disabled={revising || !!resolvingId} onclick={revise}>
          {revising ? 'Reviderar…' : 'Revidera och redigera'}
        </button>
      </div>
    {/if}

    {#if doc.status === 'draft' && doc.source_kind === 'blocks'}
      <div hidden={showPreview}>
        <BlockEditor document={doc} onChange={(d) => receiveEditorDocument(d, documentScope)} {userName} />
      </div>
      {#if showPreview}
        <p class="text-sm text-text-muted mb-3" role="note">Preview shows the saved document. Unsaved edits remain available when you return to editing.</p>
        <iframe title="preview" src={previewURL(doc.id)} sandbox="" class="w-full h-[80vh] card"></iframe>
      {/if}
    {:else if doc.status === 'draft' && doc.source_kind === 'pdf'}
      <div hidden={showPreview}>
        {#key `${doc.id}:${doc.pdf_sha256}:${doc.html_source_commitment}:${doc.html_materialization_revision}`}<PdfFieldDesigner documentID={doc.id} {recipientRevision}
          hasHTMLSource={doc.has_html_source === true} pdfSHA256={doc.pdf_sha256} htmlSourceCommitment={doc.html_source_commitment} onSignatureFieldsChange={(fields) => {
          if (isCurrentDocument(documentScope)) pdfSignatureFields = fields;
        }} />{/key}
      </div>
      {#if showPreview}
        <iframe title="preview" src={documentPdfURL(doc.id)} class="w-full h-[80vh] card"></iframe>
      {/if}
    {:else if showPreview}
      <iframe
        title="preview"
        src={doc.source_kind === 'pdf' ? documentPdfURL(doc.id) : previewURL(doc.id)}
        sandbox={doc.source_kind === 'blocks' ? '' : undefined}
        class="w-full h-[80vh] card"
      ></iframe>
    {:else if doc.source_kind === 'blocks'}
      <BlockEditor document={doc} onChange={(d) => receiveEditorDocument(d, documentScope)} {userName} />
    {:else}
      {#key `${doc.id}:${doc.pdf_sha256}:${doc.html_source_commitment}:${doc.html_materialization_revision}`}<PdfFieldDesigner documentID={doc.id} {recipientRevision}
        hasHTMLSource={doc.has_html_source === true} pdfSHA256={doc.pdf_sha256} htmlSourceCommitment={doc.html_source_commitment} onSignatureFieldsChange={(fields) => {
        if (isCurrentDocument(documentScope)) pdfSignatureFields = fields;
      }} />{/key}
    {/if}

    <div class="mt-8">
      <SenderPanel
        documentID={doc.id}
        status={doc.status}
        requiresSignature={doc.requires_signature !== false}
        reviewRequired={doc.has_html_source === true && doc.html_review_required === true}
        revisionBlocked={doc.has_html_source === true && htmlRevisionBlocked}
        defaultLocale={doc.default_locale}
        signatureFields={doc.source_kind === 'blocks' ? documentSignatureFields(doc) : pdfSignatureFields}
        onStatusChange={(next) => receiveStatus(next, documentScope)}
        onRecipientsChange={() => { if (isCurrentDocument(documentScope)) recipientRevision++; }}
        onDefaultLocaleChange={(locale) => changeDefaultLocale(locale, documentScope)}
      />
      {#if doc.status !== 'draft' || doc.has_html_source}
        <section class="card p-5 mb-6">
          <h2 class="font-display font-extralight text-lg mb-1">Kommentarer</h2>
          <p class="text-sm text-text-secondary mb-4 leading-relaxed">
            Ställ och besvara frågor med motparten. Varje inlägg mejlas till den andra parten.
          </p>
          {#if commentRefreshError}
            <div role="alert" class="text-danger mb-4">
              <p>{commentRefreshError}</p>
              <button type="button" class="btn btn-secondary" onclick={() => doc && loadComments(doc.id)}>Retry message refresh</button>
            </div>
          {/if}
          {#if comments.length}
            <ul class="space-y-3 mb-4">
              {#each comments as c (c.id)}
                <li class="rounded-md border border-border-light p-3 {c.author_side === 'sender' ? 'bg-bg-elevated' : ''}">
                  <p class="text-xs text-text-muted mb-1">
                    {c.author_name}
                    <span class="uppercase tracking-wide">· {c.author_side === 'sender' ? 'vi' : 'motpart'}</span>
                    · {new Date(c.created_at).toLocaleString()}
                  </p>
                  <p class="text-sm whitespace-pre-wrap">{c.body}</p>
                </li>
              {/each}
            </ul>
          {:else}
            <p class="text-text-muted text-sm mb-4">Inga kommentarer än.</p>
          {/if}
          <textarea
            bind:value={commentBody}
            rows="2"
            placeholder="Skriv en kommentar…"
            class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm mb-2"
          ></textarea>
          <button class="btn btn-primary" disabled={postingComment || !commentBody.trim()} onclick={sendComment}>
            {postingComment ? 'Skickar…' : 'Skicka kommentar'}
          </button>
        </section>
      {/if}
      <RiskPanel documentID={doc.id} />
      <EnvelopePanel documentID={doc.id} isEnvelope={!!doc.is_envelope} />
      <TimelinePanel documentID={doc.id} />
      <AgentTokensPanel documentID={doc.id} />
    </div>
    {/key}
  {/if}
</div>
