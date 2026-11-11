<script lang="ts">
  import { ui, staffLocale } from '$lib/staffPreferences';
 import type { PackageSendObservation } from '$lib/packageSend';
  import { preSignDocumentMatchesResult, type PreSignResult } from '$lib/presignExecution';
  import { onDestroy, onMount, tick, untrack } from 'svelte';
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
  import DocumentDownload from '$lib/components/DocumentDownload.svelte';
  import ReminderPolicySettings from '$lib/components/ReminderPolicySettings.svelte';
  import type { ReminderSnapshot } from '$lib/automationSettings';
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
  import { ArrowLeft, Eye, Save } from 'lucide-svelte';
  import DocumentPurposeSelect from '$lib/components/DocumentPurposeSelect.svelte';
  import { documentPurpose, purposeLabel, requireDocumentPurpose, type DocumentPurpose } from '$lib/documentPurpose';

  let doc = $state<DocumentResponse | null>(null);
  let selectedPurpose = $state<DocumentPurpose | ''>('');
  let changingPurpose = $state(false), purposeUnconfirmed = $state(false);
  let purposeError = $state<string | null>(null);
  const savedPurpose = $derived(documentPurpose(doc?.purpose));
  const signingPurpose = $derived(savedPurpose === 'signing');
  let userName = $state('You');
  let viewerRole = $state('');
  let viewerUserID = $state('');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let showPreview = $state(false);
  let recipientRevision = $state(0);
  let senderPanel = $state.raw<{ openRecipientForm(): Promise<boolean> } | null>(null);
  let savingTemplate = $state(false);
  let savedTemplateFlash = $state(false);
  let showTemplateName = $state(false);
  let templateName = $state('');
  let templateNameError = $state<string | null>(null);
  let templateSource = $state.raw<{ scope: DocumentScope; document: DocumentResponse } | null>(null);
  let templateNameInput = $state.raw<HTMLInputElement>();
  let templateNameTrigger = $state.raw<HTMLButtonElement>();
  let showPDFSave = $state(false);
  let pdfSignatureFields = $state<{ role: string; label: string }[]>([]);
  let generatedPlacementReady = $state(false);
  let htmlRevisionBlocked = $state(true);
  let htmlEditorClean = $state(false), blocksEditorClean = $state(false);
  let crmDetailsOpen = $state(false);
  let crmBlocked = $state(true), crmBusy = $state(false), crmReviewRequired = $state(false), senderMutationBusy = $state(false);
  let attachmentPackageSend=$state<PackageSendObservation | undefined>(undefined);
  let attachmentReviewRequest=$state({ revision: 0, inspect: false }), attachmentReviewRevision=$state(0);
  let attachmentBusy=$state(false), attachmentDirty=$state(false), attachmentSendBlocked=$state(true), attachmentMessage=$state('Load saved attachments before sending.');
  let crmLocalIntent=$state(false), senderDraftDirty=$state(false), pdfLayoutBusy=$state(false), pdfLayoutDirty=$state(false);
  let amendmentLookupBlocked = $state(true), amendmentLinked = $state(false), amendmentNotice = $state(false), amendmentBusy = $state(false), amendmentDirty = $state(false);
  let supersessionBusy = $state(false), supersessionPending = $state(false);
  let seenAmendmentScope = '';
  const amendmentScope = $derived(doc ? JSON.stringify([doc.id, doc.org_id, doc.updated_at, viewerUserID, viewerRole]) : '');
  const amendmentReadOnly = $derived(!savedPurpose || purposeUnconfirmed || changingPurpose || (signingPurpose && (amendmentLookupBlocked || amendmentLinked || amendmentBusy || supersessionBusy || supersessionPending)));
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
  const crmEditable = $derived(savedPurpose !== null && !purposeUnconfirmed && !changingPurpose && !amendmentReadOnly && !!doc && doc.status === 'draft' && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id)));
  const pdfReviewGate = $derived(doc?.status === 'draft' && doc.source_kind === 'pdf' && doc.has_html_source === true && doc.html_review_required === true);
  const crmEditorClean = $derived(doc?.has_html_source ? htmlEditorClean : doc?.source_kind === 'blocks' ? blocksEditorClean : false);
  const htmlSiblingMutationBusy=$derived(changingPurpose || purposeUnconfirmed || crmBusy || attachmentBusy || senderMutationBusy || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || pdfLayoutBusy);
  const attachmentBarrier=$derived(attachmentBusy || attachmentDirty);
  const attachmentEligible=$derived(signingPurpose && !purposeUnconfirmed && !changingPurpose && !!doc && doc.status==='draft' && (viewerRole==='owner' || (viewerRole==='sender' && viewerUserID===doc.sender_id)) && doc?.source_kind==='pdf' && !doc.is_envelope && !doc.parent_envelope_id);
  const attachmentReconciliationBusy=$derived(changingPurpose || purposeUnconfirmed || crmBusy || senderMutationBusy || senderDraftDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || pdfLayoutBusy || pdfLayoutDirty);
  const crmReconciliationBusy=$derived(changingPurpose || purposeUnconfirmed || senderMutationBusy || senderDraftDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || attachmentBusy || pdfLayoutBusy || pdfLayoutDirty);
  const attachmentOtherBusy=$derived(changingPurpose || purposeUnconfirmed || amendmentBusy || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || pdfLayoutBusy || pdfLayoutDirty);
  const crmOtherBusy = $derived(changingPurpose || purposeUnconfirmed || senderMutationBusy || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || attachmentBarrier);
  let preSignPresentationBlocked = $state(false);
  let reminderBlocked = $state(true), reminderBusy = $state(false), reminderDirty = $state(false), reminderUnconfirmed = $state(false);
  const reminderApplies = $derived(!!doc && signingPurpose && viewerUserID === doc.sender_id && ['owner','sender'].includes(viewerRole) && !doc.parent_envelope_id);
  const reminderScope = $derived(doc ? JSON.stringify([doc.id,doc.org_id,viewerUserID,viewerRole]) : '');
  let seenReminderScope = '';
  $effect.pre(() => { const scope = reminderScope; untrack(() => { if (scope !== seenReminderScope) { seenReminderScope = scope; reminderBlocked = true; reminderBusy = false; reminderDirty = false; reminderUnconfirmed = false; } }); });
  const reminderOtherBusy = $derived(changingPurpose || purposeUnconfirmed || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBarrier || pdfLayoutBusy || pdfLayoutDirty || savingMode || savingTemplate || revising || !!resolvingId || savingApprovalMode || amendmentBusy || amendmentDirty || supersessionBusy || supersessionPending || (doc?.source_kind === 'blocks' && !blocksEditorClean) || (doc?.has_html_source === true && (!htmlEditorClean || htmlRevisionBlocked)));
  async function receiveReminderPolicy(saved: ReminderSnapshot, scope: DocumentScope) {
    if (!doc || !isCurrentDocument(scope,true) || saved.scope !== 'document' || saved.id !== doc.id) throw new Error('Reminder source changed');
    if (saved.updated_at !== doc.updated_at) {
      await loadDocument(doc.id,scope.routeRevision);
      if (!doc || !isCurrentRoute(saved.id,scope.routeRevision) || doc.updated_at !== saved.updated_at) throw new Error('Reminder source refresh unconfirmed');
    }
  }

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
  async function openRecipientsForFields(): Promise<boolean> {
    const scope = captureDocument(), panel = senderPanel;
    if (!signingPurpose || changingPurpose || purposeUnconfirmed || !scope || !panel) return false;
    const opened = await panel.openRecipientForm();
    return isCurrentDocument(scope) && senderPanel === panel && opened;
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

  async function changePurpose(event: Event) {
    event.preventDefault();
    const scope = captureDocument();
    if (!scope || !doc || !savedPurpose || purposeUnconfirmed || changingPurpose || doc.status !== 'draft'
      || !(viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id))
      || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBusy || attachmentDirty || pdfLayoutBusy || pdfLayoutDirty || savingMode || savingTemplate || revising || resolvingId || savingApprovalMode || amendmentBusy || amendmentDirty || supersessionBusy || supersessionPending
      || (doc.source_kind === 'blocks' && !blocksEditorClean) || (doc.has_html_source && (!htmlEditorClean || htmlRevisionBlocked))) return;
    let purpose: DocumentPurpose;
    try { purpose = requireDocumentPurpose(selectedPurpose); } catch (failure) { purposeError = (failure as Error).message; return; }
    if (purpose !== 'signing' && htmlSource?.contract_profile) { purposeError = 'This reviewed contract design requires Signing. Choose another design for a document or presentation.'; return; }
    if (purpose === savedPurpose) return;
    const before = doc;
    changingPurpose = true; purposeError = null;
    try {
      const updated = await updateDocument(scope.id, { expected_updated_at: before.updated_at, purpose });
      if (!isCurrentDocument(scope, true)) { if (isCurrentDocument(scope)) purposeUnconfirmed = true; return; }
      if (updated.purpose !== purpose || !receiveDocument(updated, scope)) throw new Error('The saved document purpose could not be confirmed. Reload this document before making further changes.');
      selectedPurpose = '';
    } catch (failure) { if (isCurrentDocument(scope)) { purposeError = (failure as Error).message; purposeUnconfirmed = true; } }
    finally { if (isCurrentDocument(scope)) changingPurpose = false; }
  }

  async function toggleSignatureMode() {
    const scope = captureDocument();
    if (!scope || !doc || !signingPurpose || changingPurpose || purposeUnconfirmed || amendmentReadOnly || crmBusy || attachmentBarrier || crmLocalIntent || doc.status !== 'draft' || savingMode || revising || resolvingId
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
    if (!scope || !doc || doc.source_kind !== 'blocks' || crmBusy || savingTemplate || showTemplateName) return;
    if (doc.status === 'draft' && !blocksEditorClean) {
      error = 'Wait for the document to finish saving before creating a template.';
      return;
    }
    const source = { scope, document: doc };
    templateSource = source;
    templateName = doc.name;
    templateNameError = null;
    showTemplateName = true;
    error = null;
    await tick();
    if (templateSource === source && showTemplateName && isCurrentDocument(scope)) {
      templateNameInput?.focus();
      templateNameInput?.select();
    }
  }

  function templateSourceCurrent(): boolean {
    return !!templateSource && isCurrentDocument(templateSource.scope, true)
      && doc === templateSource.document && doc.source_kind === 'blocks'
      && (doc.status !== 'draft' || blocksEditorClean);
  }

  async function closeTemplateName() {
    if (savingTemplate || !showTemplateName) return;
    const source = templateSource;
    showTemplateName = false;
    templateSource = null;
    templateNameError = null;
    await tick();
    if (source && isCurrentDocument(source.scope)) templateNameTrigger?.focus();
  }

  function templateNameKeydown(event: KeyboardEvent) {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    void closeTemplateName();
  }

  async function submitTemplateName(event: Event) {
    event.preventDefault();
    if (!showTemplateName || !templateSource || crmBusy || savingTemplate) return;
    if (!templateSourceCurrent()) {
      templateNameError = 'The document changed. Close this form and reopen it to use the current saved content.';
      return;
    }
    const name = templateName.trim();
    if (!name || name.length > 200) {
      templateNameError = 'Enter a template name of up to 200 characters.';
      templateNameInput?.focus();
      return;
    }
    const { scope, document: submittedDocument } = templateSource;
    savingTemplate = true;
    templateNameError = null;
    let saved = false;
    try {
      await createBlocksTemplate(name, {
        blocks_json: submittedDocument.blocks_json,
        variables_json: submittedDocument.variables_json,
      });
      if (!isCurrentDocument(scope)) return;
      showTemplateName = false;
      templateSource = null;
      savedTemplateFlash = true;
      if (templateFlashTimer) clearTimeout(templateFlashTimer);
      templateFlashTimer = setTimeout(() => {
        if (isCurrentDocument(scope)) savedTemplateFlash = false;
      }, 3000);
      saved = true;
    } catch (e) {
      if (isCurrentDocument(scope)) templateNameError = (e as Error).message;
    } finally {
      if (isCurrentDocument(scope)) savingTemplate = false;
    }
    if (saved) {
      await tick();
      if (isCurrentDocument(scope)) templateNameTrigger?.focus();
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
    selectedPurpose = ''; changingPurpose = false; purposeUnconfirmed = false; purposeError = null;
    savingTemplate = false;
    savedTemplateFlash = false;
    showTemplateName = false;
    templateName = '';
    templateNameError = null;
    templateSource = null;
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
    if (to?.url.pathname !== from?.url.pathname && (reminderBusy || reminderUnconfirmed)) { cancel(); return; }
    if (to?.url.pathname !== from?.url.pathname && reminderDirty && !window.confirm($ui('Discard unsaved reminder changes?'))) { cancel(); return; }
    if (!willUnload && to?.url.pathname !== from?.url.pathname && commentBody.trim()
        && !window.confirm('You have an unsent comment. Leave this document and discard the draft?')) cancel();
  });
  function protectCommentDraft(event: BeforeUnloadEvent) {
    if (!commentBody.trim() && !reminderDirty && !reminderBusy && !reminderUnconfirmed) return;
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
    <ArrowLeft class="size-3" /> {$ui("Back to documents")}
  </a>

  {#if loading}
    <p class="text-text-muted">{$ui("Loading…")}</p>
  {:else if error && !doc}
    <div class="card p-6 text-danger">{$ui(error)}</div>
  {:else if doc && doc.id === $page.params.id}
    {#key doc.id}
    {@const documentScope = { id: doc.id, routeRevision, documentRevision }}
    {#if error}<div role="alert" class="card p-4 text-danger mb-4">{$ui(error)}</div>{/if}
    <div class="mb-6 space-y-2">
      {#if doc.source_kind === 'blocks' && doc.status === 'draft' && !blocksEditorClean}<p class="text-sm text-text-secondary" role="status">{$ui("Save as template becomes available after this document is fully saved.")}</p>{/if}
      <p class="page-eyebrow">{$ui('Document')} · {$ui(doc.status)}</p>
      <div class="flex flex-col items-start gap-4 sm:flex-row sm:items-baseline sm:justify-between">
        <h1 class="page-title min-w-0 w-full break-words sm:flex-1">{doc.name}</h1>
        <div class="flex max-w-full flex-wrap items-start gap-2">
          <DocumentDownload document={doc} blocked={changingPurpose || purposeUnconfirmed || (doc.status === 'draft' && ((savedPurpose !== null && doc.source_kind === 'blocks' && !blocksEditorClean) || (savedPurpose !== null && doc.has_html_source && !htmlEditorClean) || senderMutationBusy || pdfLayoutBusy || pdfLayoutDirty || crmBusy || attachmentBusy || revising || supersessionBusy))} />
          <button class="btn btn-secondary" disabled={pdfReviewGate} onclick={() => (showPreview = !showPreview)}>
            <Eye class="size-4" /> {$ui(showPreview ? (doc.status !== 'draft' && doc.source_kind === 'pdf' ? 'Signature locations' : 'Edit') : 'Preview')}
          </button>
          {#if doc.source_kind === 'blocks'}
            <button bind:this={templateNameTrigger} type="button" class="btn btn-secondary" aria-expanded={showTemplateName} aria-controls="document-template-name" disabled={savingTemplate || crmBusy || (doc.status === 'draft' && !blocksEditorClean)} onclick={saveAsTemplate}>
              <Save class="size-4" /> {$ui(savedTemplateFlash ? 'Saved!' : savingTemplate ? 'Saving…' : 'Save as template')}
            </button>
          {:else if doc.status === 'draft' && !doc.has_html_source}
            <button class="btn btn-secondary" onclick={() => (showPDFSave = !showPDFSave)}>
              <Save class="size-4" /> {$ui(savedTemplateFlash ? 'Saved!' : 'Save as template')}
            </button>
          {/if}
        </div>
      </div>
    </div>

    <section class="card p-4 mb-6 space-y-3" aria-label={$ui('Document purpose')}>
      <p class="text-sm font-medium">{$ui('Document purpose')}: {$ui(purposeLabel(savedPurpose))}</p>
      {#if doc.status === 'draft' && savedPurpose && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id))}
        <details><summary class="cursor-pointer text-sm text-text-secondary">{$ui('Change purpose')}</summary>
          <form onsubmit={changePurpose} class="mt-4 max-w-xl space-y-3" aria-label={$ui('Change document purpose')}>
            <DocumentPurposeSelect value={selectedPurpose} signingOnly={!!htmlSource?.contract_profile} onChange={value => { selectedPurpose = value; purposeError = null; }} disabled={changingPurpose || purposeUnconfirmed} />
            <p class="text-xs text-text-secondary">{$ui('Save content first. Existing recipients, signing fields or prepared envelopes must be removed before leaving Signing.')}</p>
            <button type="submit" class="btn btn-secondary" disabled={changingPurpose || purposeUnconfirmed || !selectedPurpose || selectedPurpose === savedPurpose || htmlSiblingMutationBusy || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBarrier || pdfLayoutBusy || pdfLayoutDirty || (doc.source_kind === 'blocks' && !blocksEditorClean) || (doc.has_html_source && (!htmlEditorClean || htmlRevisionBlocked))}>{$ui(changingPurpose ? 'Saving…' : 'Save purpose')}</button>
          </form>
        </details>
      {/if}
      {#if purposeError}<p role="alert" class="text-sm text-danger">{$ui(purposeError)}</p>{/if}
      {#if purposeUnconfirmed}<p role="alert" class="text-sm text-warning">{$ui('The purpose change is unconfirmed. Preserve local edits and reload this document before another change.')}</p><a href={`/documents/${doc.id}`} data-sveltekit-reload class="btn btn-secondary">{$ui('Reload document')}</a>{/if}
    </section>

    {#if showTemplateName && doc.source_kind === 'blocks'}
      <section id="document-template-name" class="card p-6 mb-6 space-y-4" aria-labelledby="document-template-name-title">
        <div>
          <h2 id="document-template-name-title" class="font-display text-lg">{$ui('Save as template')}</h2>
          <p class="mt-1 text-sm text-text-secondary">{$ui('Create a reusable copy of this saved document.')}</p>
        </div>
        <form onsubmit={submitTemplateName} aria-label={$ui('Save as template')} aria-busy={savingTemplate} class="space-y-4">
          <label class="block text-sm" for="document-template-name-input">{$ui('Template name')}</label>
          <input id="document-template-name-input" bind:this={templateNameInput} bind:value={templateName} onkeydown={templateNameKeydown} required maxlength="200" disabled={savingTemplate}
            aria-invalid={!!templateNameError} aria-describedby={templateNameError ? 'document-template-name-error' : undefined}
            class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" />
          {#if templateNameError}<p id="document-template-name-error" role="alert" class="text-sm text-danger">{$ui(templateNameError)}</p>{/if}
          {#if !templateSourceCurrent()}<p role="alert" class="text-sm text-danger">{$ui('The document changed. Close this form and reopen it to use the current saved content.')}</p>{/if}
          <div class="flex flex-wrap gap-2">
            <button type="submit" class="btn btn-primary" onkeydown={templateNameKeydown} disabled={savingTemplate || crmBusy || !templateSourceCurrent()}>{$ui(savingTemplate ? 'Saving…' : 'Save template')}</button>
            <button type="button" class="btn btn-secondary" onkeydown={templateNameKeydown} disabled={savingTemplate} onclick={closeTemplateName}>{$ui('Cancel')}</button>
          </div>
        </form>
      </section>
    {/if}

    {#if showPDFSave && doc.status === 'draft' && doc.source_kind === 'pdf' && !doc.has_html_source}
      <SavePDFTemplate document={doc} onClose={() => (showPDFSave = false)} onSaved={() => {
        if (isCurrentDocument(documentScope)) { showPDFSave = false; savedTemplateFlash = true; }
      }} />
    {/if}

    {#if viewerUserID && viewerRole}
      {#key amendmentScope}
       {@const capturedAmendmentScope = amendmentScope}
       <DocumentAmendmentsPanel document={doc} actor={{org_id:doc.org_id,user_id:viewerUserID,role:viewerRole}}
        externalBusy={changingPurpose || purposeUnconfirmed || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBarrier || pdfLayoutBusy || pdfLayoutDirty || savingMode || revising || !!resolvingId || savingApprovalMode || supersessionBusy || supersessionPending}
        onStateChange={(state)=>{if(capturedAmendmentScope===amendmentScope && isCurrentDocument(documentScope)){amendmentLookupBlocked=state.blocked;amendmentLinked=state.linked;amendmentNotice=state.notice;amendmentBusy=state.busy;amendmentDirty=state.dirty;}}} />
      {/key}
    {/if}
    {#if amendmentNotice}<p class="card p-4 mb-6 text-sm" role="note">{$ui("This document accompanies an agreed notice. Review and issue its email notice in Later amendments above. It does not use the signing or acknowledgement Send action.")}</p>{/if}
    {#if crmEditable}
      <details bind:open={crmDetailsOpen} class="mb-6 rounded-xl border border-border-light bg-bg-surface">
        <summary class="cursor-pointer px-5 py-4 text-sm font-medium">{$ui('CRM data')}<span class="ml-2 text-xs text-text-muted">{$ui('Optional connection')}{#if crmBlocked || crmReviewRequired} · {$ui('Review required')}{/if}</span></summary>
        <div class="px-4 pb-4">
      <CRMDocumentPanel document={doc} actor={{ org_id: doc.org_id, user_id: viewerUserID, role: viewerRole === 'owner' ? 'owner' : 'sender' }}
        editorClean={crmEditorClean} otherBusy={crmOtherBusy} reconciliationBusy={crmReconciliationBusy} refreshRevision={crmRefreshRevision}
        onApplied={(updated,reconciliation) => receiveCRMDocument(updated, documentScope,reconciliation)}
        onStateChange={(blocked, busy, localIntent) => { if (isCurrentDocument(documentScope)) { crmBlocked = blocked; crmBusy = busy; crmLocalIntent=localIntent===true; } }} />
        </div>
      </details>
    {/if}
    {#if doc.has_html_source}
      {#if doc.status !== 'draft'}<details class="mb-6"><summary class="cursor-pointer text-sm text-text-secondary">{$ui("Saved document information and intended parties")}</summary>
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
      {#if doc.status === 'draft' && doc.html_review_required}
      {#key `${doc.id}:${doc.updated_at}:${doc.pdf_sha256}:${doc.html_source_commitment}`}
        <HtmlPDFReview document={doc} revisionBlocked={htmlRevisionBlocked || attachmentBarrier}
          expectedPages={htmlSource?.page_count} hasSigningPage={htmlSource?.source_schema_version === 3}
          canReview={!amendmentReadOnly && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id))}
          onReviewed={(updated) => { if(!receiveHTMLDocument(updated, documentScope)) throw new Error('The displayed agreement changed. Refresh and reconcile the saved review.'); }} onRefresh={refreshHTMLDocument} />
      {/key}
      {:else if doc.status === 'draft' && doc.source_kind === 'pdf'}
        <p class="text-sm text-success mb-4" role="status">{$ui("This exact PDF has been reviewed.")}{#if signingPurpose} {$ui(htmlSource?.source_schema_version === 3 ? 'Verify both generated signature locations below before sending.' : 'Add recipients and any required signature fields below before sending.')}{/if}</p>
      {/if}
    {/if}
    {#if doc.has_html_source}{#key doc.id}<HtmlDocumentHistory document={doc} />{/key}{/if}

    {#if signingPurpose && doc.status === 'draft'}
      <div class="card p-4 mb-6 flex items-center justify-between gap-4">
        <div>
          <p class="text-sm font-medium">{$ui("Signing mode")}</p>
          <p class="text-xs text-text-muted">
            {$ui(doc.requires_signature
              ? 'Signature required: recipients sign the document.'
              : 'Read and acknowledge: recipients open the document and click Accept. No signature.')}
          </p>
        </div>
        <button class="btn btn-secondary whitespace-nowrap" disabled={amendmentReadOnly || savingMode || crmBusy || attachmentBarrier || crmLocalIntent || (doc.has_html_source === true && (htmlRevisionBlocked || !htmlSource || !!htmlSource.contract_profile))} onclick={toggleSignatureMode}>
          {$ui(savingMode ? "Saving…" : doc.requires_signature ? "Switch to acknowledgement" : "Require signature")}
        </button>
      </div>
      {#if htmlSource?.contract_profile}<p class="text-sm text-text-secondary mb-6" role="note">{$ui("The reviewed contract design requires both parties to sign. Its ceremony cannot be changed to acknowledgement.")}</p>{/if}
    {/if}

    {#if doc.status === 'changes_requested'}
      <div class="card p-5 mb-6 border-l-4 border-warning">
        <h2 class="font-display font-extralight text-lg mb-1">{$ui("Changes requested")}</h2>
        <p class="text-sm text-text-secondary mb-3 leading-relaxed">
          {$ui("A party requested changes. Signing is paused. Revise the document, make the changes and send it for signature again.")}
        </p>
        {#if !doc.has_html_source}<div class="flex flex-wrap items-center gap-2 mb-4 text-xs">
          <span class="uppercase tracking-widest text-text-muted font-mono">{$ui("On approval")}</span>
          <button
            class="px-2 py-1 rounded-md border {approvalMode === 'accept' ? 'border-accent text-accent' : 'border-border-light text-text-muted'}"
            onclick={() => changeApprovalMode('accept')}
            disabled={savingApprovalMode}
          >{$ui("Mark approved (edit when revising)")}</button>
          <button
            class="px-2 py-1 rounded-md border {approvalMode === 'auto_apply' ? 'border-accent text-accent' : 'border-border-light text-text-muted'}"
            onclick={() => changeApprovalMode('auto_apply')}
            disabled={savingApprovalMode}
          >{$ui("Apply proposed text automatically")}</button>
          <span class="text-text-muted">{$ui("(workspace setting)")}</span>
        </div>{:else}<p class="text-sm text-text-secondary mb-4">{$ui("Approving a request records your decision. It does not apply proposed wording. Reopen the document, update its declared values or wording, and review the newly rendered PDF before sending again.")}</p>{/if}

        {#if changeRequestRefreshError}
          <div role="alert" class="text-danger mb-4">
            <p>{$ui(changeRequestRefreshError)}</p>
            <button type="button" class="btn btn-secondary" disabled={refreshingChanges} onclick={() => doc && loadChangeRequests(doc.id)}>{$ui("Retry change request refresh")}</button>
          </div>
        {/if}
        <button type="button" class="btn btn-secondary mb-4" disabled={refreshingChanges} onclick={() => doc && loadChangeRequests(doc.id)}>
          {$ui(refreshingChanges ? 'Refreshing change requests…' : 'Refresh change requests')}
        </button>

        {#if changeRequests.length}
          <ul class="space-y-3 mb-4">
            {#each changeRequests as cr (cr.id)}
              <li data-change-request-id={cr.id} class="rounded-md border border-border-light bg-bg-elevated p-3">
                <p class="text-xs text-text-muted mb-1">
                  {cr.recipient_name || $ui('Recipient')}{cr.recipient_email ? ` · ${cr.recipient_email}` : ''}
                  · {new Date(cr.created_at).toLocaleString($staffLocale === 'sv' ? 'sv-SE' : 'en-GB')}
                  {#if cr.resolution === 'approved'}· <span class="text-success">{$ui("approved")}</span>{:else if cr.resolution === 'denied'}· <span class="text-danger">{$ui("declined")}</span>{/if}
                </p>
                {#if cr.quote}
                  <p class="text-sm border-l-2 border-accent pl-2 mb-1"><span class="text-text-muted text-xs">{$ui("Selected:")} </span>{cr.quote}</p>
                {/if}
                {#if cr.message}<p class="text-sm whitespace-pre-wrap mb-1">{cr.message}</p>{/if}
                {#if cr.proposed}<p class="text-sm text-success"><span class="text-text-muted text-xs">{$ui("Proposed:")} </span>{cr.proposed}</p>{/if}
                {#if cr.status === 'open'}
                  <div class="flex gap-2 mt-2">
                    <button class="btn btn-primary text-xs" disabled={!!resolvingId || revising} onclick={() => resolveCr(cr, true)}>{$ui("Approve")}</button>
                    <button class="btn btn-secondary text-xs" disabled={!!resolvingId || revising} onclick={() => resolveCr(cr, false)}>{$ui("Decline")}</button>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
        <button class="btn btn-primary" disabled={amendmentReadOnly || revising || !!resolvingId} onclick={revise}>
          {$ui(revising ? "Revising…" : "Revise and edit")}
        </button>
      </div>
    {/if}

    {#if preSignPresentationBlocked}
      <p role="alert" class="text-sm text-warning">{$ui("The original pre-signing result needs inspection. The current PDF remains hidden until its exact retained derivative is confirmed.")}</p>
    {:else if doc.pre_sign}
      {#if doc.pre_sign.publication === 'sealing'}
        <p role="status" class="text-sm text-text-secondary">{$ui("Hash is securing the provider-signed agreement. The original source is retained in history; the current derivative is not available yet.")}</p>
      {:else}
        {#if ['completed', 'declined', 'voided', 'expired'].includes(doc.status) && (viewerRole === 'owner' || (viewerRole === 'sender' && viewerUserID === doc.sender_id))}
          {#key `${amendmentScope}:${doc.pre_sign.execution.sha256}`}
            {@const supersessionScope = amendmentScope}
            <PreSignSupersession documentID={doc.id} actor={{ org_id: doc.org_id, user_id: viewerUserID }}
              blocked={amendmentBusy || amendmentDirty || crmBusy || crmLocalIntent || senderMutationBusy || senderDraftDirty || attachmentBarrier || pdfLayoutBusy || pdfLayoutDirty || savingMode || revising || !!resolvingId || savingApprovalMode}
              onStateChange={(state) => { if (supersessionScope === amendmentScope && isCurrentDocument(documentScope)) { supersessionBusy = state.busy; supersessionPending = state.pending; } }} />
          {/key}
        {/if}
        <p class="text-sm text-text-secondary mb-3">{$ui("Provider-signed agreement ·")} {doc.pre_sign.page_count} {$ui("pages")}</p>
        <p class="text-xs text-text-muted break-all mb-3">{$ui("PDF SHA-256:")} {doc.pre_sign.visible_pdf_sha256}</p>
        {#key `${doc.id}:${doc.pre_sign.execution.sha256}:${doc.pre_sign.visible_pdf_sha256}`}
          <iframe title={$ui("Provider-signed agreement")} src={documentPdfURL(doc.id)} class="w-full h-[80vh] card"></iframe>
        {/key}
      {/if}
    {:else if !savedPurpose}
      <p role="alert" class="card p-4 text-warning mb-4">{$ui('This document purpose is unavailable. Reload before changing content or signing settings. Saved previews and downloads remain available.')}</p>
      <iframe title={$ui('Saved document')} src={doc.source_kind === 'pdf' ? documentPdfURL(doc.id) : previewURL(doc.id)} sandbox={doc.source_kind === 'blocks' ? '' : undefined} class="w-full h-[80vh] card"></iframe>
    {:else if doc.status === 'draft' && doc.source_kind === 'blocks'}
      <div hidden={showPreview}>
        <BlockEditor signingFieldsEnabled={signingPurpose} document={doc} onChange={(d) => receiveEditorDocument(d, documentScope)} {userName} externalBusy={crmBusy || changingPurpose || purposeUnconfirmed || !savedPurpose}
          onEditorStateChange={(clean) => { if (isCurrentDocument(documentScope)) blocksEditorClean = clean; }} />
      </div>
      {#if showPreview}
        <p class="text-sm text-text-muted mb-3" role="note">{$ui("Preview shows the saved document. Unsaved edits remain available when you return to editing.")}</p>
        <iframe title={$ui("preview")} src={previewURL(doc.id)} sandbox="" class="w-full h-[80vh] card"></iframe>
      {/if}
    {:else if pdfReviewGate}
      <!-- Review is the only view until the exact PDF is approved; the designer and preview mount afterwards. -->
    {:else if doc.status === 'draft' && doc.source_kind === 'pdf'}
      <div hidden={showPreview}>
        {#if doc.has_html_source && (htmlRevisionBlocked || !htmlSource)}<p role="note" class="text-sm text-text-secondary">{$ui(signingPurpose ? "Load and reconcile the retained document values before viewing or changing signature locations." : "Load and reconcile the retained document values before viewing the saved PDF.")}</p>
        {:else}
        {#key `${doc.id}:${savedPurpose}:${doc.pdf_sha256}:${doc.html_source_commitment}:${doc.html_materialization_revision}`}<PdfFieldDesigner documentID={doc.id} {recipientRevision}
          hasHTMLSource={doc.has_html_source === true} pdfSHA256={doc.pdf_sha256} htmlSourceCommitment={doc.html_source_commitment} {htmlSource}
          fieldsEnabled={signingPurpose} readonly={!signingPurpose || changingPurpose || purposeUnconfirmed || attachmentBarrier || amendmentReadOnly} onAddRecipient={openRecipientsForFields} onStateChange={(state)=>{if(isCurrentDocument(documentScope,true)){pdfLayoutBusy=state.busy;pdfLayoutDirty=state.dirty;}}}
          onPlacementProof={(proof) => receivePlacementProof(proof, documentScope)} onSignatureFieldsChange={(fields) => {
          if (isCurrentDocument(documentScope)) pdfSignatureFields = fields;
        }} />{/key}
        {/if}
      </div>
      {#if showPreview}
        <iframe title={$ui("preview")} src={documentPdfURL(doc.id)} class="w-full h-[80vh] card"></iframe>
      {/if}
    {:else if showPreview}
      <iframe
        title={$ui("preview")}
        src={doc.source_kind === 'pdf' ? documentPdfURL(doc.id) : previewURL(doc.id)}
        sandbox={doc.source_kind === 'blocks' ? '' : undefined}
        class="w-full h-[80vh] card"
      ></iframe>
    {:else if doc.source_kind === 'blocks'}
      <BlockEditor signingFieldsEnabled={signingPurpose} document={doc} onChange={(d) => receiveEditorDocument(d, documentScope)} {userName} />
    {:else}
      {#if doc.has_html_source && (htmlRevisionBlocked || !htmlSource)}<p role="note" class="text-sm text-text-secondary">{$ui("Loading and verifying the saved signature locations…")}</p>
      {:else}
      {#key `${doc.id}:${savedPurpose}:${doc.pdf_sha256}:${doc.html_source_commitment}:${doc.html_materialization_revision}`}<PdfFieldDesigner documentID={doc.id} {recipientRevision}
        hasHTMLSource={doc.has_html_source === true} pdfSHA256={doc.pdf_sha256} htmlSourceCommitment={doc.html_source_commitment} {htmlSource} fieldsEnabled={signingPurpose} readonly={true} onSignatureFieldsChange={(fields) => {
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
      {#if reminderApplies}
        {#key reminderScope}{@const capturedReminderScope = reminderScope}
          <div class="mb-5"><ReminderPolicySettings scope="document" id={doc.id} documentUpdatedAt={doc.updated_at} readonly={amendmentReadOnly || doc.status !== 'draft'} externalBlocked={reminderOtherBusy}
            onStateChange={(state) => { if(capturedReminderScope === reminderScope && isCurrentDocument(documentScope)){ reminderBlocked = state.blocked; reminderBusy = state.busy; reminderDirty = state.dirty; reminderUnconfirmed = state.unconfirmed; } }}
            onSaved={(saved) => receiveReminderPolicy(saved,documentScope)} /></div>
        {/key}
      {/if}
      {#if signingPurpose}
      <SenderPanel bind:this={senderPanel}
        documentID={doc.id}
        status={doc.status}
        requiresSignature={doc.requires_signature !== false}
        reviewRequired={doc.has_html_source === true && doc.html_review_required === true}
        revisionBlocked={(reminderApplies && reminderBlocked) || amendmentLookupBlocked || amendmentNotice || amendmentBusy || (doc.has_html_source === true && htmlRevisionBlocked) || (crmEditable && doc.source_kind === 'blocks' && !blocksEditorClean)}
        attachmentsBlocked={doc.status==='draft' && doc.source_kind==='pdf' && !doc.is_envelope && !doc.parent_envelope_id && (!attachmentEligible || attachmentSendBlocked)} attachmentsMessage={attachmentMessage} packageSend={attachmentPackageSend} packageReviewRevision={attachmentReviewRevision} packageReconciliationBusy={attachmentReconciliationBusy || attachmentBusy} onPackageReviewRequired={(inspect)=>requestPackageReview(inspect,documentScope)}
        externalMutationBusy={(reminderApplies && (reminderBusy || reminderUnconfirmed)) || changingPurpose || purposeUnconfirmed || attachmentBarrier || amendmentBusy} onDraftStateChange={(dirty)=>{if(isCurrentDocument(documentScope))senderDraftDirty=dirty;}}
        crmBlocked={crmEditable && (crmBlocked || crmReviewRequired)} {crmBusy} {crmReviewRevision}
        onCRMReviewRequired={() => { crmDetailsOpen = true; requestCRMReview(documentScope); }}
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
      {/if}
      {#if signingPurpose && !changingPurpose && !purposeUnconfirmed && (doc.status !== 'draft' || doc.has_html_source)}
        <section class="card p-5 mb-6">
          <h2 class="font-display font-extralight text-lg mb-1">{$ui("Comments")}</h2>
          <p class="text-sm text-text-secondary mb-4 leading-relaxed">
            {$ui("Ask and answer questions with the other party. Each message is emailed to the other party.")}
          </p>
          <nav aria-label={$ui("Message history")} class="flex gap-2 mb-3">
            <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment || !olderCommentCursor}
              onclick={() => doc && olderCommentCursor && loadComments(doc.id, { kind: 'before', cursor: olderCommentCursor })}>{$ui("Older")}</button>
            <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment || !newerCommentCursor}
              onclick={() => doc && newerCommentCursor && loadComments(doc.id, { kind: 'after', cursor: newerCommentCursor })}>{$ui("Newer")}</button>
            <button type="button" class="btn btn-secondary" disabled={postingComment} onclick={() => doc && loadComments(doc.id)}>{$ui("Latest")}</button>
          </nav>
          <p role="status" aria-live="polite">{$ui(commentLoading ? 'Loading messages…' : '')}</p>
          {#if commentRefreshError}
            <div role="alert" class="text-danger mb-4">
              <p>{$ui(commentRefreshError)}</p>
              <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment} onclick={() => commentHistory.retry()}>{$ui("Retry message refresh")}</button>
            </div>
          {/if}
          {#if comments.length}
            <ul class="space-y-3 mb-4">
              {#each comments as c (c.id)}
                <li class="rounded-md border border-border-light p-3 {c.author_side === 'sender' ? 'bg-bg-elevated' : ''}">
                  <p class="text-xs text-text-muted mb-1">
                    {c.author_name}
                    <span class="uppercase tracking-wide">· {$ui(c.author_side === 'sender' ? "us" : "other party")}</span>
                    · {new Date(c.created_at).toLocaleString($staffLocale === 'sv' ? 'sv-SE' : 'en-GB')}
                  </p>
                  <p class="text-sm whitespace-pre-wrap">{c.body}</p>
                </li>
              {/each}
            </ul>
          {:else}
            <p class="text-text-muted text-sm mb-4">{$ui("No comments yet.")}</p>
          {/if}
          <textarea
            bind:value={commentBody}
            rows="2"
            placeholder={$ui("Write a comment…")}
            class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm mb-2"
          ></textarea>
          <button class="btn btn-primary" disabled={postingComment || !commentBody.trim()} onclick={sendComment}>
            {$ui(postingComment ? "Sending…" : "Send comment")}
          </button>
        </section>
      {/if}
      <details class="mb-6 rounded-xl border border-border-light bg-bg-surface"><summary class="cursor-pointer px-5 py-4 text-sm font-medium">{$ui("AI review")}</summary><div class="px-4 pb-4"><RiskPanel documentID={doc.id} /></div></details>
      {#if signingPurpose && !changingPurpose && !purposeUnconfirmed}<details open={!!doc.is_envelope} class="mb-6 rounded-xl border border-border-light bg-bg-surface"><summary class="cursor-pointer px-5 py-4 text-sm font-medium">{$ui("Multi-document signing")}</summary><div class="px-4 pb-4"><EnvelopePanel documentID={doc.id} isEnvelope={!!doc.is_envelope} /></div></details>{/if}
      <TimelinePanel documentID={doc.id} />
    </div>
    {/key}
  {/if}
</div>
