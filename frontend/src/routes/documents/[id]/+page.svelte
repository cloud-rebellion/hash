<script lang="ts">
 import type { PackageSendObservation } from '$lib/packageSend';
  import { preSignDocumentMatchesResult, type PreSignResult } from '$lib/presignExecution';
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
    type HTMLDocumentSource,
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
  import CRMDocumentPanel from '$lib/components/CRMDocumentPanel.svelte';
  import DocumentAttachmentsPanel from '$lib/components/DocumentAttachmentsPanel.svelte';
  import DocumentAmendmentsPanel from '$lib/components/DocumentAmendmentsPanel.svelte';
  import PreSignSupersession from '$lib/components/PreSignSupersession.svelte';
  import { currentHTMLSource, htmlUUID } from '$lib/htmlRevision';
  import { createCommentHistory, latestComments, type CommentSelection } from '$lib/commentHistory';
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
  let generatedPlacementReady = $state(false);
  let htmlRevisionBlocked = $state(true);
  let htmlEditorClean = $state(false), blocksEditorClean = $state(false);
  let crmBlocked = $state(true), crmBusy = $state(false), crmReviewRequired = $state(false), senderMutationBusy = $state(false);
  let attachmentPackageSend=$state<PackageSendObservation | undefined>(undefined);
  let attachmentReviewRequest=$state({ revision: 0, inspect: false }), attachmentReviewRevision=$state(0);
  let attachmentBusy=$state(false), attachmentDirty=$state(false), attachmentSendBlocked=$state(true), attachmentMessage=$state('Load saved attachments before sending.');
  let crmLocalIntent=$state(false), senderDraftDirty=$state(false), pdfLayoutBusy=$state(false), pdfLayoutDirty=$state(false);
  let amendmentLookupBlocked = $state(true), amendmentLinked = $state(false), amendmentNotice = $state(false), amendmentBusy = $state(false), amendmentDirty = $state(false);
  let supersessionBusy = $state(false), supersessionPending = $state(false);
  let seenAmendmentScope = '';
  const amendmentScope = $derived(doc ? JSON.stringify([doc.id, doc.org_id, doc.updated_at, viewerUserID, viewerRole]) : '');
  const amendmentReadOnly = $derived(amendmentLookupBlocked || amendmentLinked || amendmentBusy || supersessionBusy || supersessionPending);
  $effect.pre(() => { const scope = amendmentScope; untrack(() => { if (seenAmendmentScope !== scope) { seenAmendmentScope = scope; amendmentLookupBlocked = true; amendmentLinked = false; amendmentNotice = false; amendmentBusy = false; amendmentDirty = false; supersessionBusy = false; supersessionPending = false; } }); });
  let crmRefreshRevision = $state(0), crmReviewRevision = $state(0), crmEditorRevision = $state(0);
  let htmlSource = $state.raw<HTMLDocumentSource | null>(null);
  let changeRequests = $state<ChangeRequest[]>([]);
  let revising = $state(false);
  let approvalMode = $state<'accept' | 'auto_apply'>('accept');
  let resolvingId = $state<string | null>(null);
  let comments = $state<DocComment[]>([]);
  let commentBody = $state('');
  let postingComment = $state(false);
  let commentSendRevision = 0;
  let commentDocumentKey = '';
  let commentLoading = $state(false);
  let olderCommentCursor = $state<string | null>(null);
  let newerCommentCursor = $state<string | null>(null);
  const commentHistory = createCommentHistory<CommentScope>({
    readPage: (scope, selection, signal) => listComments(scope.id, selection, signal),
    isCurrent: isCurrentCommentScope,
    changed: view => {
      comments = view.comments; olderCommentCursor = view.olderCursor; newerCommentCursor = view.newerCursor;
      commentLoading = view.loading; commentRefreshError = view.error;
    },
  });
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
  const crmEditable = $derived(!amendmentReadOnly && !!doc && doc.status === 'draft' && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id)));
  const crmEditorClean = $derived(doc?.has_html_source ? htmlEditorClean : doc?.source_kind === 'blocks' ? blocksEditorClean : false);
  const htmlSiblingMutationBusy=$derived(crmBusy || attachmentBusy || senderMutationBusy || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || pdfLayoutBusy);
  const attachmentBarrier=$derived(attachmentBusy || attachmentDirty);
  const attachmentEligible=$derived(!!doc && doc.status==='draft' && (viewerRole==='owner' || (viewerRole==='sender' && viewerUserID===doc.sender_id)) && doc?.source_kind==='pdf' && !doc.is_envelope && !doc.parent_envelope_id);
  const attachmentReconciliationBusy=$derived(crmBusy || senderMutationBusy || senderDraftDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || pdfLayoutBusy || pdfLayoutDirty);
  const crmReconciliationBusy=$derived(senderMutationBusy || senderDraftDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || attachmentBusy || pdfLayoutBusy || pdfLayoutDirty);
  const attachmentOtherBusy=$derived(amendmentBusy || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || pdfLayoutBusy || pdfLayoutDirty);
  const crmOtherBusy = $derived(senderMutationBusy || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || attachmentBarrier);
  let preSignPresentationBlocked = $state(false);

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
    if (crmBusy) return;
    if (!isCurrentDocument(scope) || updated.id !== scope.id || updated.org_id !== doc?.org_id) return;
    resetPDFPlacement(updated);
    doc = updated;
    documentRevision++;
  }
  function receiveCRMDocument(updated: DocumentResponse, scope: DocumentScope, reconciliation=false): boolean {
    if (!doc || !isCurrentDocument(scope, true) || !crmEditorClean || (reconciliation ? crmReconciliationBusy : crmOtherBusy)) return false;
    const changedSource = doc.has_html_source && (updated.html_source_commitment !== doc.html_source_commitment || updated.pdf_sha256 !== doc.pdf_sha256);
    if (!receiveDocument(updated, scope)) return false;
    crmReviewRequired = false; crmReviewRevision++;
    if (changedSource) { crmEditorRevision++; htmlEditorClean = false; }
    return true;
  }
  function receiveAttachmentDocument(updated: DocumentResponse, expectedUpdatedAt: string, scope: DocumentScope, reconciliation=false): boolean {
    if (!doc || !isCurrentDocument(scope,true) || doc.updated_at!==expectedUpdatedAt || (reconciliation ? attachmentReconciliationBusy : attachmentOtherBusy) || (doc.has_html_source && !htmlEditorClean)) return false;
    // Controller validates ordinary attachment-only readback against the entire
    // prior source. Explicit inspected adoption may load a newer saved source.
    const adopted = receiveDocument(updated,scope);
    if (adopted && reconciliation) attachmentReviewRevision++;
    return adopted;
  }
  function requestPackageReview(inspect: boolean, scope: DocumentScope) {
    if (!isCurrentDocument(scope) || doc?.status !== 'draft' || (inspect && (attachmentReconciliationBusy || attachmentBusy))) return;
    attachmentPackageSend=undefined; attachmentSendBlocked=true;
    attachmentReviewRequest={ revision: attachmentReviewRequest.revision + 1, inspect };
  }
  function requestCRMReview(scope: DocumentScope) {
    if (!isCurrentDocument(scope)) return;
    crmReviewRequired = true; crmRefreshRevision++;
  }
  function resetPDFPlacement(updated: DocumentResponse) {
    if (!doc || doc.id !== updated.id || doc.pdf_sha256 !== updated.pdf_sha256
        || doc.html_source_commitment !== updated.html_source_commitment || doc.html_materialization_revision !== updated.html_materialization_revision) {
      pdfSignatureFields = [];
      pdfLayoutBusy=false; pdfLayoutDirty=false;
      generatedPlacementReady = false;
      htmlRevisionBlocked = true;
      htmlSource = null;
      recipientRevision++;
      showPDFSave = false;
    }
  }
  function receiveHTMLSource(source: HTMLDocumentSource | null, scope: DocumentScope) {
    if (!doc || !isCurrentDocument(scope)) return;
    if (!source) { htmlSource = null; generatedPlacementReady = false; return; }
    try {
      const verified = currentHTMLSource(source, doc);
      if (verified.html_source_commitment !== htmlSource?.html_source_commitment || verified.pdf_sha256 !== htmlSource?.pdf_sha256
          || verified.source_schema_version !== htmlSource?.source_schema_version) generatedPlacementReady = false;
      htmlSource = verified;
    }
    catch { htmlSource = null; htmlRevisionBlocked = true; generatedPlacementReady = false; }
  }
  function receiveHTMLDocument(updated: DocumentResponse, scope: DocumentScope): boolean {
    if (htmlSiblingMutationBusy) return false;
    return receiveDocument(updated,scope);
  }
  async function refreshHTMLDocument() {
    const scope = captureDocument();
    if (!scope || htmlSiblingMutationBusy) return;
    try { receiveHTMLDocument(await getDocument(scope.id), scope); }
    catch (e) { if (isCurrentDocument(scope)) error = (e as Error).message; }
  }
  function receivePlacementProof(proof: { documentID: string; pdfSHA256: string; htmlSourceCommitment: string; ready: boolean }, scope: DocumentScope) {
    if (!doc || !isCurrentDocument(scope) || proof.documentID !== doc.id || proof.pdfSHA256 !== doc.pdf_sha256
        || proof.htmlSourceCommitment !== doc.html_source_commitment || htmlSource?.source_schema_version !== 3 || htmlRevisionBlocked) return;
    generatedPlacementReady = proof.ready;
  }
  function receiveStatus(next: string, scope: DocumentScope) {
    if (!doc || !isCurrentDocument(scope)) return;
    doc = { ...doc, status: next };
    documentRevision++;
  }
  async function receivePreSignCommit(result: PreSignResult) {
    const scope = captureDocument();
    if (!scope || !doc || result.document_id !== scope.id) return false;
    const baseSHA = doc.pdf_sha256;
    preSignPresentationBlocked = true;
    try {
      const updated = await getDocument(scope.id);
      if (!isCurrentDocument(scope, true)) return false;
      const proof = updated.pre_sign;
      if (!proof || !preSignDocumentMatchesResult(proof, result) || updated.pdf_sha256 !== baseSHA
          || updated.html_source_commitment !== result.source_commitment || updated.html_materialization_revision !== result.materialization_revision) throw new Error('The provider-signed PDF could not be matched to the original request. Inspect that request before continuing.');
      if (!receiveDocument(updated, scope)) return false;
      preSignPresentationBlocked = false;
      return true;
    } catch (failure) { if (isCurrentDocument(scope)) error = (failure as Error).message; return false; }
  }
  async function changeDefaultLocale(locale: string, scope: DocumentScope) {
    if (!doc || crmBusy || attachmentBarrier || crmLocalIntent || !isCurrentDocument(scope)) return;
    const actionScope = captureDocument();
    if (!actionScope) return;
    try {
      const updated = await updateDocument(actionScope.id, { expected_updated_at: doc.updated_at, default_locale: locale });
      receiveDocument(updated, actionScope);
    } catch (e) {
      if (isCurrentDocument(actionScope)) error = (e as Error).message;
    }
  }

  type CommentScope = DocumentScope & { orgID: string };
  function captureCommentScope(): CommentScope | null {
    const scope = captureDocument();
    return scope && doc ? { ...scope, orgID: doc.org_id } : null;
  }
  function isCurrentCommentScope(scope: CommentScope): boolean {
    return isCurrentDocument(scope) && doc?.org_id === scope.orgID;
  }

  async function toggleSignatureMode() {
    const scope = captureDocument();
    if (!scope || !doc || amendmentReadOnly || crmBusy || attachmentBarrier || crmLocalIntent || doc.status !== 'draft' || savingMode || revising || resolvingId
        || (doc.has_html_source && (htmlRevisionBlocked || !htmlSource || htmlSource.contract_profile))) return;
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

  async function loadComments(id: string, selection: CommentSelection = latestComments) {
    const scope = captureCommentScope();
    if (scope && scope.id === id) await commentHistory.load(scope, selection);
  }

  async function sendComment() {
    const scope = captureCommentScope();
    if (!scope || postingComment || !commentBody.trim()) return;
    const ticket = ++commentSendRevision;
    const current = () => ticket === commentSendRevision && isCurrentCommentScope(scope);
    const submittedBody = commentBody;
    commentHistory.invalidate();
    postingComment = true;
    error = null;
    try {
      await postComment(scope.id, submittedBody.trim());
      if (!current()) return;
      if (commentBody === submittedBody) commentBody = '';
      postingComment = false;
      await loadComments(scope.id);
    } catch (e) {
      if (current()) error = (e as Error).message;
    } finally {
      if (current()) postingComment = false;
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
    if (!scope || amendmentReadOnly || doc?.status !== 'changes_requested' || revising || resolvingId || savingMode) return;
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
    if (!scope || !doc || crmBusy || savingTemplate) return;
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
    preSignPresentationBlocked = false;
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
    generatedPlacementReady = false;
    htmlRevisionBlocked = true;
    htmlEditorClean = false; blocksEditorClean = false;
    crmBlocked = true; crmBusy = false; crmReviewRequired = false; senderMutationBusy = false;
    attachmentPackageSend=undefined;attachmentReviewRequest={revision:attachmentReviewRequest.revision+1,inspect:false};attachmentReviewRevision++;attachmentBusy=false;attachmentDirty=false;attachmentSendBlocked=true;attachmentMessage='Load saved attachments before sending.';
    crmLocalIntent=false;senderDraftDirty=false;pdfLayoutBusy=false;pdfLayoutDirty=false;
    crmRefreshRevision++; crmReviewRevision++; crmEditorRevision++;
    htmlSource = null;
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
    commentSendRevision++;
    commentDocumentKey = '';
    commentHistory.reset();
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
    return () => { untrack(() => { routeRevision++; commentSendRevision++; commentHistory.invalidate(); }); };
  });

  $effect.pre(() => {
    const key = doc ? JSON.stringify([doc.id, doc.org_id]) : '';
    untrack(() => {
      if (commentDocumentKey && commentDocumentKey !== key && !disposed) {
        commentSendRevision++; commentHistory.reset(); postingComment = false;
      }
      commentDocumentKey = key;
    });
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
    commentSendRevision++;
    commentHistory.dispose();
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
            <Eye class="size-4" /> {showPreview ? (doc.status !== 'draft' && doc.source_kind === 'pdf' ? 'Signature locations' : 'Edit') : 'Preview'}
          </button>
          {#if doc.source_kind === 'blocks'}
            <button class="btn btn-secondary" disabled={savingTemplate || crmBusy} onclick={saveAsTemplate}>
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

    {#if viewerUserID && viewerRole}
      {#key amendmentScope}
       {@const capturedAmendmentScope = amendmentScope}
       <DocumentAmendmentsPanel document={doc} actor={{org_id:doc.org_id,user_id:viewerUserID,role:viewerRole}}
        externalBusy={crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBarrier || pdfLayoutBusy || pdfLayoutDirty || savingMode || revising || !!resolvingId || savingApprovalMode || supersessionBusy || supersessionPending}
        onStateChange={(state)=>{if(capturedAmendmentScope===amendmentScope && isCurrentDocument(documentScope)){amendmentLookupBlocked=state.blocked;amendmentLinked=state.linked;amendmentNotice=state.notice;amendmentBusy=state.busy;amendmentDirty=state.dirty;}}} />
      {/key}
    {/if}
    {#if amendmentNotice}<p class="card p-4 mb-6 text-sm" role="note">This document accompanies an agreed notice. Review and issue its email notice in Later amendments above. It does not use the signing or acknowledgement Send action.</p>{/if}
    {#if crmEditable}
      <CRMDocumentPanel document={doc} actor={{ org_id: doc.org_id, user_id: viewerUserID, role: viewerRole === 'owner' ? 'owner' : 'sender' }}
        editorClean={crmEditorClean} otherBusy={crmOtherBusy} reconciliationBusy={crmReconciliationBusy} refreshRevision={crmRefreshRevision}
        onApplied={(updated,reconciliation) => receiveCRMDocument(updated, documentScope,reconciliation)}
        onStateChange={(blocked, busy, localIntent) => { if (isCurrentDocument(documentScope)) { crmBlocked = blocked; crmBusy = busy; crmLocalIntent=localIntent===true; } }} />
    {/if}
    {#if doc.has_html_source}
      {#if doc.status !== 'draft'}<details class="mb-6"><summary class="cursor-pointer text-sm text-text-secondary">Saved document information and intended parties</summary>
        <HtmlDocumentRevision document={doc} onRevised={(updated) => receiveHTMLDocument(updated, documentScope)}
          onStateChange={(blocked) => { if (isCurrentDocument(documentScope)) htmlRevisionBlocked = blocked; }}
          onSourceChange={(source) => receiveHTMLSource(source, documentScope)} />
      </details>{:else}
      {#key `${doc.id}:${crmEditorRevision}`}
        <HtmlDocumentRevision document={doc} onRevised={(updated) => receiveHTMLDocument(updated, documentScope)}
          externalBusy={crmBusy} mutationBlocked={attachmentBarrier || amendmentReadOnly} reconciliationBusy={htmlSiblingMutationBusy} onEditorStateChange={(clean) => { if (isCurrentDocument(documentScope)) htmlEditorClean = clean; }}
          onStateChange={(blocked) => { if (isCurrentDocument(documentScope)) htmlRevisionBlocked = blocked; }}
          onSourceChange={(source) => receiveHTMLSource(source, documentScope)} />
      {/key}
      {/if}
      {#if doc.status === 'draft'}
      {#key `${doc.id}:${doc.updated_at}:${doc.pdf_sha256}:${doc.html_source_commitment}`}
        <HtmlPDFReview document={doc} revisionBlocked={htmlRevisionBlocked || attachmentBarrier}
          expectedPages={htmlSource?.page_count} hasSigningPage={htmlSource?.source_schema_version === 3}
          canReview={!amendmentReadOnly && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id))}
          onReviewed={(updated) => { if(!receiveHTMLDocument(updated, documentScope)) throw new Error('The displayed agreement changed. Refresh and reconcile the saved review.'); }} onRefresh={refreshHTMLDocument} />
      {/key}
      {/if}
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
        <button class="btn btn-secondary whitespace-nowrap" disabled={amendmentReadOnly || savingMode || crmBusy || attachmentBarrier || crmLocalIntent || (doc.has_html_source === true && (htmlRevisionBlocked || !htmlSource || !!htmlSource.contract_profile))} onclick={toggleSignatureMode}>
          {savingMode ? 'Sparar…' : doc.requires_signature ? 'Byt till acceptera' : 'Kräv signatur'}
        </button>
      </div>
      {#if htmlSource?.contract_profile}<p class="text-sm text-text-secondary mb-6" role="note">The reviewed contract design requires both parties to sign. Its ceremony cannot be changed to acknowledgement.</p>{/if}
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
        <button class="btn btn-primary" disabled={amendmentReadOnly || revising || !!resolvingId} onclick={revise}>
          {revising ? 'Reviderar…' : 'Revidera och redigera'}
        </button>
      </div>
    {/if}

    {#if preSignPresentationBlocked}
      <p role="alert" class="text-sm text-warning">The original pre-signing result needs inspection. The current PDF remains hidden until its exact retained derivative is confirmed.</p>
    {:else if doc.pre_sign}
      {#if doc.pre_sign.publication === 'sealing'}
        <p role="status" class="text-sm text-text-secondary">Hash is securing the provider-signed agreement. The original source is retained in history; the current derivative is not available yet.</p>
      {:else}
        {#if ['completed', 'declined', 'voided', 'expired'].includes(doc.status) && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id))}
          {#key `${amendmentScope}:${doc.pre_sign.execution.sha256}`}
            {@const supersessionScope = amendmentScope}
            <PreSignSupersession documentID={doc.id} actor={{ org_id: doc.org_id, user_id: viewerUserID }}
              blocked={amendmentBusy || amendmentDirty || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBarrier || pdfLayoutBusy || pdfLayoutDirty || savingMode || revising || !!resolvingId || savingApprovalMode}
              onStateChange={(state) => { if (supersessionScope === amendmentScope && isCurrentDocument(documentScope)) { supersessionBusy = state.busy; supersessionPending = state.pending; } }} />
          {/key}
        {/if}
        <p class="text-sm text-text-secondary mb-3">Provider-signed agreement · {doc.pre_sign.page_count} pages</p>
        <p class="text-xs text-text-muted break-all mb-3">PDF SHA-256: {doc.pre_sign.visible_pdf_sha256}</p>
        {#key `${doc.id}:${doc.pre_sign.execution.sha256}:${doc.pre_sign.visible_pdf_sha256}`}
          <iframe title="Provider-signed agreement" src={documentPdfURL(doc.id)} class="w-full h-[80vh] card"></iframe>
        {/key}
      {/if}
    {:else if doc.status === 'draft' && doc.source_kind === 'blocks'}
      <div hidden={showPreview}>
        <BlockEditor document={doc} onChange={(d) => receiveEditorDocument(d, documentScope)} {userName} externalBusy={crmBusy}
          onEditorStateChange={(clean) => { if (isCurrentDocument(documentScope)) blocksEditorClean = clean; }} />
      </div>
      {#if showPreview}
        <p class="text-sm text-text-muted mb-3" role="note">Preview shows the saved document. Unsaved edits remain available when you return to editing.</p>
        <iframe title="preview" src={previewURL(doc.id)} sandbox="" class="w-full h-[80vh] card"></iframe>
      {/if}
    {:else if doc.status === 'draft' && doc.source_kind === 'pdf'}
      <div hidden={showPreview}>
        {#if doc.has_html_source && (htmlRevisionBlocked || !htmlSource)}<p role="note" class="text-sm text-text-secondary">Load and reconcile the retained document values before viewing or changing signature locations.</p>
        {:else}
        {#key `${doc.id}:${doc.pdf_sha256}:${doc.html_source_commitment}:${doc.html_materialization_revision}`}<PdfFieldDesigner documentID={doc.id} {recipientRevision}
          hasHTMLSource={doc.has_html_source === true} pdfSHA256={doc.pdf_sha256} htmlSourceCommitment={doc.html_source_commitment} {htmlSource}
          readonly={attachmentBarrier || amendmentReadOnly} onStateChange={(state)=>{if(isCurrentDocument(documentScope,true)){pdfLayoutBusy=state.busy;pdfLayoutDirty=state.dirty;}}}
          onPlacementProof={(proof) => receivePlacementProof(proof, documentScope)} onSignatureFieldsChange={(fields) => {
          if (isCurrentDocument(documentScope)) pdfSignatureFields = fields;
        }} />{/key}
        {/if}
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
      {#if doc.has_html_source && (htmlRevisionBlocked || !htmlSource)}<p role="note" class="text-sm text-text-secondary">Loading and verifying the saved signature locations…</p>
      {:else}
      {#key `${doc.id}:${doc.pdf_sha256}:${doc.html_source_commitment}:${doc.html_materialization_revision}`}<PdfFieldDesigner documentID={doc.id} {recipientRevision}
        hasHTMLSource={doc.has_html_source === true} pdfSHA256={doc.pdf_sha256} htmlSourceCommitment={doc.html_source_commitment} {htmlSource} readonly={true} onSignatureFieldsChange={(fields) => {
        if (isCurrentDocument(documentScope)) pdfSignatureFields = fields;
      }} />{/key}
      {/if}
    {/if}

    <div class="mt-8">
      {#if attachmentEligible}
       <DocumentAttachmentsPanel document={doc} actor={{org_id:doc.org_id,user_id:viewerUserID,role:viewerRole==='owner'?'owner':'sender'}}
        readonly={amendmentReadOnly} mainEditorClean={!doc.has_html_source || htmlEditorClean} externalBusy={attachmentOtherBusy} reconciliationBusy={attachmentReconciliationBusy} packageReviewRequest={attachmentReviewRequest}
        onSaved={(updated,expected,reconciliation)=>receiveAttachmentDocument(updated,expected,documentScope,reconciliation)}
        onStateChange={(state)=>{if(isCurrentDocument(documentScope)){attachmentBusy=state.busy;attachmentDirty=state.dirty;attachmentSendBlocked=state.blocked;attachmentMessage=state.message;attachmentPackageSend=state.packageSend;}}} />
      {/if}
      <SenderPanel
        documentID={doc.id}
        status={doc.status}
        requiresSignature={doc.requires_signature !== false}
        reviewRequired={doc.has_html_source === true && doc.html_review_required === true}
        revisionBlocked={amendmentLookupBlocked || amendmentNotice || amendmentBusy || (doc.has_html_source === true && htmlRevisionBlocked) || (crmEditable && doc.source_kind === 'blocks' && !blocksEditorClean)}
        attachmentsBlocked={doc.status==='draft' && doc.source_kind==='pdf' && !doc.is_envelope && !doc.parent_envelope_id && (!attachmentEligible || attachmentSendBlocked)} attachmentsMessage={attachmentMessage} packageSend={attachmentPackageSend} packageReviewRevision={attachmentReviewRevision} packageReconciliationBusy={attachmentReconciliationBusy || attachmentBusy} onPackageReviewRequired={(inspect)=>requestPackageReview(inspect,documentScope)}
        externalMutationBusy={attachmentBarrier || amendmentBusy} onDraftStateChange={(dirty)=>{if(isCurrentDocument(documentScope))senderDraftDirty=dirty;}}
        crmBlocked={crmEditable && (crmBlocked || crmReviewRequired)} {crmBusy} {crmReviewRevision}
        onCRMReviewRequired={() => requestCRMReview(documentScope)}
        onMutationStateChange={(busy) => { if (isCurrentDocument(documentScope)) senderMutationBusy = busy; }}
        generatedPlacementRequired={htmlSource?.source_schema_version === 3}
        {generatedPlacementReady}
        intendedParties={htmlSource?.contract_parties ?? []}
        recipientIdentityLocked={amendmentReadOnly || (doc.has_html_source === true && (htmlRevisionBlocked || !htmlSource || !!htmlSource.contract_profile))}
        sourceCommitment={doc.html_source_commitment ?? ''}
        onPreSignCommitted={receivePreSignCommit}
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
          <nav aria-label="Message history" class="flex gap-2 mb-3">
            <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment || !olderCommentCursor}
              onclick={() => doc && olderCommentCursor && loadComments(doc.id, { kind: 'before', cursor: olderCommentCursor })}>Older</button>
            <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment || !newerCommentCursor}
              onclick={() => doc && newerCommentCursor && loadComments(doc.id, { kind: 'after', cursor: newerCommentCursor })}>Newer</button>
            <button type="button" class="btn btn-secondary" disabled={postingComment} onclick={() => doc && loadComments(doc.id)}>Latest</button>
          </nav>
          <p role="status" aria-live="polite">{commentLoading ? 'Loading messages…' : ''}</p>
          {#if commentRefreshError}
            <div role="alert" class="text-danger mb-4">
              <p>{commentRefreshError}</p>
              <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment} onclick={() => commentHistory.retry()}>Retry message refresh</button>
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
