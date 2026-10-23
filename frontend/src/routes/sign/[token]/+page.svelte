<script lang="ts">
  import { createCommentHistory, commentQuery, latestComments, type CommentSelection } from '$lib/commentHistory';
  import { onMount, onDestroy, tick, untrack } from 'svelte';
  import { page } from '$app/stores';
  import { CheckCircle2, FileSignature, ShieldCheck, X } from 'lucide-svelte';
  import SignerFields from '$lib/components/SignerFields.svelte';
  import PdfSignerView from '$lib/components/PdfSignerView.svelte';
  import A13Notice from '$lib/components/A13Notice.svelte';
  import SignerPackageReview from '$lib/components/SignerPackageReview.svelte';
  import SignerAmendmentContext from '$lib/components/SignerAmendmentContext.svelte';
  import { validateSignerAmendmentContext, type SignerAmendmentDisclosure } from '$lib/signerAmendment';
  import { validateSignerPreSignContext, type SignerPreSignDisclosure } from '$lib/signerPreSign';
  import type { SignerPackageResponse } from '$lib/signerPackage';
  import { signerNoticeHeaders } from '$lib/api/signerNotice';
  import { signerCeremonyKey, validateSignerPDFObservation, type SignerPDFObservation, type SignerPDFScope } from '$lib/signerPDF';
  import { createSignerViewRecorder, type SignerViewScope, type SignerViewState } from '$lib/signerView';
  import { t, setLocale } from '$lib/i18n';
  import { completionArtifactLinks, type CompletionArtifactLinks } from '$lib/completionArtifacts';

  type Privacy = {
    controller: string;
    controller_contact: string;
    processor: string;
    processor_email: string;
    purpose_summary: string;
    legal_basis: string;
    retention_years: number;
    jurisdiction_dp: string;
    policy_url: string;
    dsr_endpoint: string;
    notice_digest: string;
    copy: {
      title: string;
      intro: string;
      controller_label: string;
      controller_contact_label: string;
      processor_label: string;
      purpose_label: string;
      legal_basis_label: string;
      retention_label: string;
      retention_value: string;
      authority_label: string;
      rights_summary: string;
      rights_body: string;
      submit_request_label: string;
      kind_label: string;
      dsr_access_label: string;
      dsr_rectification_label: string;
      dsr_erasure_label: string;
      dsr_restriction_label: string;
      dsr_portability_label: string;
      dsr_objection_label: string;
      note_label: string;
      note_placeholder: string;
      send_request_label: string;
      request_received: string;
      read_policy_label: string;
      acknowledgement_label: string;
      fine_print: string;
    };
  };

  type Ctx = {
    document_id: string;
    document_name: string;
    status: string;
    source_kind: string;
    requires_signature: boolean;
    routing_tier?: string;
    recipient: { id: string; email: string; name: string; role: string; status: string; locale: string };
    fonts: string[];
    privacy: Privacy;
    pdf_observation?: SignerPDFObservation;
    amendment_context?: SignerAmendmentDisclosure | null;
    pre_sign_context?: SignerPreSignDisclosure | null;
  };

  // Acknowledgement state must never turn the bearer magic-link token into a
  // persistent browser credential. Document + recipient IDs are opaque,
  // non-secret identifiers; the version forces a fresh acknowledgement when
  // the notice contract changes.
  const A13_NOTICE_VERSION = 'v3';

  function a13AcknowledgementKey(context: Ctx): string {
    return `hash_signer_a13:${A13_NOTICE_VERSION}:${context.document_id}:${context.recipient.id}:${context.privacy.notice_digest}`;
  }

  function clearLegacyA13Acknowledgement(token: string) {
    try {
      if (typeof localStorage !== 'undefined') {
        // Delete, but never migrate or retain, the legacy key whose suffix was
        // the raw bearer token.
        localStorage.removeItem(`hash_signer_a13:${token}`);
      }
    } catch {
      // Storage failures keep the notice fail-closed and visible.
    }
  }

  let ctx = $state<Ctx | null>(null);
  let loadError = $state<string | null>(null);
  let documentHTML = $state<string>('');

  let typedName = $state('');
  let chosenFont = $state('Caveat');
  let showAdoptModal = $state(false);
  let signing = $state(false);
  let signError = $state<string | null>(null);
  let completed = $state<{ terminal: boolean; links: CompletionArtifactLinks | null } | null>(null);
  let accepted = $state(false);
  let accepting = $state(false);
  let noticeAcknowledged = $state(false);
  let packageReview = $state<{ key: string; ready: boolean; settled: boolean; response?: SignerPackageResponse }>({ key: '', ready: false, settled: false });

  let showDeclineModal = $state(false);
  let declineReason = $state('');
  let declined = $state(false);
  let declining = $state(false);

  let showChangesModal = $state(false);
  let changesMessage = $state('');
  let changesRequested = $state(false);
  let requestingChanges = $state(false);

  // Inline annotation: the signer marks a span of text and proposes a change.
  let showAnno = $state(false);
  let annoQuote = $state('');
  let annoContext = $state('');
  let annoBlockId = $state('');
  let annoComment = $state('');
  let annoProposed = $state('');
  let annoTop = $state(0);
  let annoLeft = $state(0);
  let annoCount = $state(0);
  let annoError = $state<string | null>(null);

  // Comment thread (Q&A with the sender).
  type DocComment = { id: string; author_name: string; author_side: string; body: string; created_at: string };
  let comments = $state<DocComment[]>([]);
  let commentBody = $state('');
  let postingComment = $state(false);
  let commentRouteEpoch = 0;
  let commentSendRevision = 0;
  let commentScopeKey = '';
  let initialCommentKey = '';
  let commentLoading = $state(false);
  let olderCommentCursor = $state<string | null>(null);
  let newerCommentCursor = $state<string | null>(null);
  const commentHistory = createCommentHistory<CommentScope>({
    readPage: async (scope, selection, signal) => {
      const res = await fetch(`/sign/${encodeURIComponent(scope.token)}/comments${commentQuery(selection)}`, { signal, cache: 'no-store' });
      if (!res.ok) throw new Error(`Message history request failed (HTTP ${res.status}).`);
      return res.json();
    },
    isCurrent: isCurrentCommentScope,
    changed: view => {
      comments = view.comments; olderCommentCursor = view.olderCursor; newerCommentCursor = view.newerCursor;
      commentLoading = view.loading; commentRefreshError = view.error;
    },
  });
  let commentRefreshError = $state<string | null>(null);

  type CommentScope = { epoch: number; token: string; documentID: string; recipientID: string;
    noticeDigest: string; sourceKind: string; ceremonyKey: string };
  function invalidateCommentScope() {
    commentRouteEpoch++; commentSendRevision++; commentScopeKey = ''; initialCommentKey = '';
    commentHistory.reset(); postingComment = false;
    noticeAcknowledged = false; viewerScopeKey = ''; documentReady = false; showAdoptModal = false;
  }
  function synchronizeCommentScope(key: string, kind: string) {
    const next = key ? JSON.stringify([key, kind]) : '';
    if (commentScopeKey && commentScopeKey !== next) invalidateCommentScope();
    commentScopeKey = next;
  }
  function captureCommentScope(): CommentScope | null {
    const ceremonyKey = currentCeremonyKey();
    synchronizeCommentScope(ceremonyKey, ctx?.source_kind ?? '');
    if (!ctx || !ceremonyKey || !loadedToken) return null;
    return { epoch: commentRouteEpoch, token: loadedToken, documentID: ctx.document_id, recipientID: ctx.recipient.id,
      noticeDigest: ctx.privacy.notice_digest, sourceKind: ctx.source_kind, ceremonyKey };
  }
  function isCurrentCommentScope(scope: CommentScope): boolean {
    return !routeDisposed && scope.epoch === commentRouteEpoch && scope.token === loadedToken && scope.token === $page.params.token
      && scope.documentID === ctx?.document_id && scope.recipientID === ctx?.recipient.id
      && scope.noticeDigest === ctx?.privacy.notice_digest && scope.sourceKind === ctx?.source_kind
      && scope.ceremonyKey === currentCeremonyKey();
  }

  async function loadComments(token = $page.params.token, signal?: AbortSignal, selection: CommentSelection = latestComments) {
    const scope = captureCommentScope();
    if (scope && scope.token === token) await commentHistory.load(scope, selection, signal);
  }

  async function sendComment() {
    const scope = captureCommentScope();
    if (!scope || postingComment || !commentBody.trim()) return;
    const ticket = ++commentSendRevision;
    const current = () => ticket === commentSendRevision && isCurrentCommentScope(scope);
    const submittedBody = commentBody;
    commentHistory.invalidate();
    postingComment = true;
    signError = null;
    try {
      if (!noticeAcknowledged || acknowledgedScopeKey !== scope.ceremonyKey) throw new Error('Acknowledge the current privacy notice before continuing.');
      const res = await fetch(`/sign/${encodeURIComponent(scope.token)}/comments`, {
        method: 'POST', headers: signerNoticeHeaders(scope.noticeDigest, true),
        body: JSON.stringify({ body: submittedBody.trim() })
      });
      if (!current()) return;
      if (!res.ok) throw new Error(`Message could not be sent (HTTP ${res.status}). Your draft has been kept.`);
      if (commentBody === submittedBody) commentBody = '';
      postingComment = false;
      await loadComments(scope.token);
    } catch (e) {
      if (current()) signError = (e as Error).message;
    } finally {
      if (current()) postingComment = false;
    }
  }

  function onDocMouseUp() {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) return;
    const text = sel.toString().trim();
    if (!text) return;
    const node = sel.anchorNode;
    const startEl = node && node.nodeType === 3 ? node.parentElement : (node as Element | null);
    const blockEl = startEl?.closest('[data-block-id]') ?? null;
    if (!blockEl) return;
    annoBlockId = blockEl.getAttribute('data-block-id') ?? '';
    annoQuote = text;
    annoContext = (blockEl.textContent ?? '').trim().slice(0, 600);
    annoComment = '';
    annoProposed = '';
    annoError = null;
    const rect = sel.getRangeAt(0).getBoundingClientRect();
    annoTop = Math.min(rect.bottom + 8, window.innerHeight - 280);
    annoLeft = Math.max(12, Math.min(rect.left, window.innerWidth - 360));
    showAnno = true;
  }

  async function submitAnno() {
    if (requestingChanges) return;
    if (!annoComment.trim() && !annoProposed.trim()) {
      annoError = $t('changes.placeholder');
      return;
    }
    if (!ctx) return;
    const token = $page.params.token;
    const recipientID = ctx.recipient.id;
    const noticeDigest = ctx.privacy.notice_digest;
    if (!token) return;
    requestingChanges = true;
    try {
      if (!noticeAcknowledged) throw new Error('Acknowledge the current privacy notice before continuing.');
      const res = await fetch(`/sign/${token}/request-changes`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify({
          message: annoComment,
          block_id: annoBlockId,
          quote: annoQuote,
          context: annoContext,
          proposed: annoProposed
        })
      });
      if (token !== $page.params.token || recipientID !== ctx?.recipient.id) return;
      if (!res.ok) {
        const message = await res.text();
        if (token === $page.params.token && recipientID === ctx?.recipient.id) {
          annoError = message;
        }
        return;
      }
      if (token !== $page.params.token || recipientID !== ctx?.recipient.id) return;
      annoCount += 1;
      pauseSigningForChanges();
      window.getSelection()?.removeAllRanges();
    } catch (e) {
      if (token === $page.params.token && recipientID === ctx?.recipient.id) {
        annoError = (e as Error).message;
      }
    } finally {
      if (token === $page.params.token && recipientID === ctx?.recipient.id) requestingChanges = false;
    }
  }

  function pauseSigningForChanges() {
    changesRequested = true;
    showAdoptModal = false;
    showDeclineModal = false;
    showChangesModal = false;
    showAnno = false;
  }

  // v1.2: block-source field filling keeps its existing gate; PDF documents
  // additionally require a verified, completely rendered current artifact.
  let fieldsFilled = $state(false);
  let documentReady = $state(false);
  let loadedToken = $state('');
  let viewerScopeKey = $state('');
  let routeDisposed = false;
  let acknowledgedScopeKey = '';
  let acknowledgedSourceKind = '';
  let ceremonyEpoch = $state(0);
  let viewState = $state<SignerViewState>({ pending: false, confirmed: false, error: null });
  const viewRecorder = createSignerViewRecorder({
    fetch: (input, init) => fetch(input, init),
    current: scope => viewScopeCurrent(scope),
    changed: state => { viewState = state; }
  });

  function currentCeremonyKey(): string {
    if (!ctx || loadedToken !== $page.params.token || routeDisposed) return '';
    return signerCeremonyKey(loadedToken, ctx.privacy.notice_digest, ctx.document_id, ctx.recipient.id, ctx.pdf_observation);
  }

  function documentDisplayed(): boolean {
    if (!ctx || loadedToken !== $page.params.token || routeDisposed || loadError || completed || accepted || declined) return false;
    return ctx.source_kind === 'pdf'
      ? !!ctx.pdf_observation && viewerScopeKey === currentCeremonyKey()
      : documentReady;
  }

  function viewerReady(): boolean {
    return documentDisplayed() && !commentLoading && (ctx?.source_kind !== 'pdf' || fieldsFilled);
  }

  function packageReady(): boolean {
    return !!currentCeremonyKey() && packageReview.key === currentCeremonyKey() && packageReview.ready;
  }

  function packageCanLoad(): boolean {
    return documentDisplayed() && viewState.confirmed;
  }

  function updatePackageReview(next: { key: string; ready: boolean; settled: boolean; response?: SignerPackageResponse }, epoch: number) {
    if (epoch !== ceremonyEpoch || next.key !== currentCeremonyKey()) return;
    if (packageReview.key === next.key && packageReview.ready === next.ready && packageReview.settled === next.settled
      && JSON.stringify(packageReview.response) === JSON.stringify(next.response)) return;
    packageReview = { ...next, ...(next.response ? { response: { ...next.response } } : {}) };
    if (next.settled && packageCanLoad() && initialCommentKey !== next.key) {
      initialCommentKey = next.key;
      void loadComments(loadedToken);
    }
  }

  function updatePDFGate(filled: boolean, scope: SignerPDFScope, epoch = ceremonyEpoch) {
    const key = signerCeremonyKey(scope.token, scope.noticeDigest, scope.observation.document_id, scope.observation.recipient_id, scope.observation);
    if (epoch !== ceremonyEpoch || ctx?.source_kind !== 'pdf' || !key || key !== currentCeremonyKey()) return;
    fieldsFilled = filled;
  }

  function updatePDFReady(ready: boolean, scope: SignerPDFScope, epoch = ceremonyEpoch) {
    const key = signerCeremonyKey(scope.token, scope.noticeDigest, scope.observation.document_id, scope.observation.recipient_id, scope.observation);
    if (epoch !== ceremonyEpoch || ctx?.source_kind !== 'pdf' || !key || key !== currentCeremonyKey()) return;
    viewerScopeKey = ready ? key : '';
  }

  function adoptPDF(scope: SignerPDFScope, epoch = ceremonyEpoch) {
    if (epoch === ceremonyEpoch && signerCeremonyKey(scope.token, scope.noticeDigest, scope.observation.document_id, scope.observation.recipient_id, scope.observation) === currentCeremonyKey()) void adopt();
  }

  function currentViewScope(): SignerViewScope | null {
    const key = currentCeremonyKey();
    if (!key || !ctx) return null;
    return { epoch: ceremonyEpoch, key, kind: ctx.source_kind, token: loadedToken, noticeDigest: ctx.privacy.notice_digest };
  }

  function viewScopeCurrent(scope: SignerViewScope): boolean {
    return scope.epoch === ceremonyEpoch && scope.key === currentCeremonyKey()
      && scope.kind === ctx?.source_kind && scope.token === loadedToken
      && scope.noticeDigest === ctx?.privacy.notice_digest;
  }

  $effect.pre(() => {
    const key = currentCeremonyKey();
    const kind = ctx?.source_kind ?? '';
    untrack(() => {
      synchronizeCommentScope(key, kind);
      if (key !== acknowledgedScopeKey || kind !== acknowledgedSourceKind) {
        ceremonyEpoch += 1;
        viewRecorder.invalidate();
        acknowledgedScopeKey = key;
        acknowledgedSourceKind = kind;
        noticeAcknowledged = false;
        packageReview = { key: '', ready: false, settled: false };
        initialCommentKey = '';
        fieldsFilled = false;
        viewerScopeKey = '';
        documentReady = false;
        showAdoptModal = false;
      }
    });
  });

  $effect(() => {
    const scope = currentViewScope();
    const ready = documentDisplayed();
    const acknowledged = noticeAcknowledged;
    // Confirmation state must not become a dependency or trigger HTTP retries.
    untrack(() => viewRecorder.update(scope, ready, acknowledged));
  });

  $effect(() => {
    if (ctx?.recipient.name) typedName = ctx.recipient.name;
  });

  function resetRouteState() {
    ceremonyEpoch += 1;
    viewRecorder.invalidate();
    ctx = null;
    loadError = null;
    documentHTML = '';
    typedName = '';
    chosenFont = 'Caveat';
    showAdoptModal = false;
    signing = false;
    signError = null;
    completed = null;
    accepted = false;
    accepting = false;
    noticeAcknowledged = false;
    packageReview = { key: '', ready: false, settled: false };
    initialCommentKey = '';
    showDeclineModal = false;
    declineReason = '';
    declined = false;
    declining = false;
    showChangesModal = false;
    changesMessage = '';
    changesRequested = false;
    requestingChanges = false;
    showAnno = false;
    annoQuote = '';
    annoContext = '';
    annoBlockId = '';
    annoComment = '';
    annoProposed = '';
    annoCount = 0;
    annoError = null;
    comments = [];
    commentRefreshError = null;
    invalidateCommentScope();
    acknowledgedScopeKey = '';
    acknowledgedSourceKind = '';
    commentBody = '';
    postingComment = false;
    fieldsFilled = false;
    documentReady = false;
    viewerScopeKey = '';
    loadedToken = '';
  }

  async function load(token: string, signal: AbortSignal) {
    let currentLoad = () => !signal.aborted && !routeDisposed && token === $page.params.token;
    try {
      const res = await fetch(`/sign/${token}`, { signal, cache: 'no-store' });
      if (signal.aborted) return;
      if (!res.ok) {
        loadError = 'This link is invalid or has expired.';
        return;
      }
      const loaded = await res.json() as Ctx;
      if (signal.aborted || token !== $page.params.token) return;
	  if (!loaded.privacy?.notice_digest) {
		loadError = 'The required privacy notice is unavailable.';
		return;
	  }
      // Ordinary absent/null disclosure remains compatible. A present relation
      // must match this exact candidate and ceremony before any viewer opens.
      if (loaded.amendment_context !== undefined && loaded.amendment_context !== null) {
        loaded.amendment_context = validateSignerAmendmentContext(loaded.amendment_context, loaded.document_id, loaded.requires_signature, loaded.source_kind);
      } else delete loaded.amendment_context;
      if (loaded.source_kind === 'pdf') {
        loaded.pdf_observation = validateSignerPDFObservation(loaded.pdf_observation, loaded.document_id, loaded.recipient.id);
        fieldsFilled = false;
      } else {
        fieldsFilled = true;
      }
      if (loaded.pre_sign_context !== undefined && loaded.pre_sign_context !== null) {
        loaded.pre_sign_context = validateSignerPreSignContext(loaded.pre_sign_context, loaded.document_id, loaded.requires_signature, loaded.source_kind, loaded.pdf_observation);
      } else delete loaded.pre_sign_context;
      loadedToken = token;
      ctx = loaded;
      const installedContext = ctx;

	  // Legal translations have not all received counsel review. Keep the
	  // complete signer ceremony in English until an approved catalog ships;
	  // mixing translated chrome with English legal text is misleading.
	  setLocale('en');

      // Reflect what this recipient has already done without fabricating a
      // download credential. Completion invalidates the magic-link token, so
      // only the fresh final_pdf_url returned by the terminal sign/accept call
      // may expose the artifact. A signer who completed while others remain
      // pending sees the recorded state without a premature download.
      const rs = loaded.recipient.status;
      const docDone = loaded.status === 'completed';
      if (rs === 'declined') {
        declined = true;
	  } else if (rs === 'accepted' && !docDone) {
		accepted = true;
      } else if (rs === 'signed' || docDone) {
        completed = { terminal: docDone, links: null };
      } else if (loaded.status === 'changes_requested') {
        // A change request paused signing; show the pending state on return.
        changesRequested = true;
      }

      // Terminal recipients must not briefly mount a live document viewer.
      // Capture the installed Svelte proxy, not the raw response object.
      const loadKey = currentCeremonyKey();
      const loadKind = ctx.source_kind;
      currentLoad = () => !signal.aborted && !routeDisposed && token === $page.params.token
        && ctx === installedContext && loadKey === currentCeremonyKey() && loadKind === ctx.source_kind;
      await tick();
      if (!currentLoad()) return;
      const loadEpoch = ceremonyEpoch;
      const sameContext = currentLoad;
      currentLoad = () => sameContext() && loadEpoch === ceremonyEpoch;
      if (completed || accepted || declined) return;

      // Block-source documents render server-side HTML; pdf-source documents
      // render via pdf.js in PdfSignerView, so skip the HTML endpoint (it
      // refuses pdf-source).
      if (loaded.source_kind === 'blocks') {
        const docRes = await fetch(`/sign/${token}/document`, { signal, cache: 'no-store' });
        if (!currentLoad()) return;
        if (!docRes.ok) throw new Error('The document could not be loaded. Please reopen your signing link.');
        const html = await docRes.text();
        if (!currentLoad()) return;
        if (!html.trim()) throw new Error('The document is empty. Please contact the sender.');
        documentHTML = html;
        await tick();
        if (!currentLoad()) return;
        documentReady = true;
      }
      if (!currentLoad()) return;
      // The current package descriptor starts comments after view confirmation.
    } catch (e) {
      if (currentLoad()) {
        fieldsFilled = false;
        documentReady = false;
        viewerScopeKey = '';
        loadError = (e as Error).message;
      }
    }
  }

  onMount(() => {
	setLocale('en');
  });
  onDestroy(() => { routeDisposed = true; viewRecorder.dispose(); invalidateCommentScope(); commentHistory.dispose(); });

  // SvelteKit keeps this page component alive when only [token] changes.
  // Scope every load to that token and tear down all recipient-specific UI
  // state first, otherwise a late response can put the previous recipient's
  // completion credential or Article 13 state onto the next ceremony.
  $effect(() => {
    const token = $page.params.token;
    const controller = new AbortController();
    untrack(() => {
      resetRouteState();
      if (!token) {
        loadError = 'Missing sign token';
        return;
      }
      clearLegacyA13Acknowledgement(token);
      void load(token, controller.signal);
    });
    return () => { controller.abort(); untrack(() => { viewRecorder.invalidate(); invalidateCommentScope(); }); };
  });

  async function adopt() {
    if (!ctx || changesRequested || requestingChanges) return;
    if (signing || accepting || declining || !viewerReady() || !packageReady() || !fieldsFilled || !noticeAcknowledged || completed || accepted || declined) return;
    if (!typedName.trim()) {
      signError = 'Please type your name first.';
      return;
    }
    showAdoptModal = true;
  }

  function acknowledgeCurrentNotice() {
    if (!currentCeremonyKey()) return;
    noticeAcknowledged = true;
  }

  async function confirmSign() {
    if (!ctx || changesRequested || requestingChanges) return;
    if (signing || accepting || declining || !viewerReady() || !packageReady() || !fieldsFilled || !noticeAcknowledged || completed || accepted || declined || !typedName.trim()) return;
    const token = $page.params.token;
    const recipientID = ctx.recipient.id;
    const noticeDigest = ctx.privacy.notice_digest;
    const ceremonyKey = currentCeremonyKey();
    const packageResponse = packageReview.response ? { ...packageReview.response } : undefined;
    const requiresPackagePortal = packageResponse !== undefined;
    if (!token) return;
    signing = true;
    signError = null;
    try {
      if (!noticeAcknowledged) throw new Error('Acknowledge the current privacy notice before continuing.');
      const res = await fetch(`/sign/${token}/sign`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify({ typed_name: typedName, font: chosenFont, ...(packageResponse ? { package_response: packageResponse } : {}) })
      });
      if (ceremonyKey !== currentCeremonyKey()) return;
      if (!res.ok) {
        const message = await res.text();
        if (ceremonyKey === currentCeremonyKey()) {
          signError = message;
        }
        return;
      }
      const body = await res.json();
      if (ceremonyKey !== currentCeremonyKey()) return;
      if (body.completed === true) {
        completed = { terminal: true, links: completionArtifactLinks(body, token, requiresPackagePortal) };
      } else {
        // Other signers still pending.
        completed = { terminal: false, links: null };
      }
      showAdoptModal = false;
    } catch (e) {
      if (ceremonyKey === currentCeremonyKey()) {
        signError = (e as Error).message;
      }
    } finally {
      if (ceremonyKey === currentCeremonyKey()) signing = false;
    }
  }

  async function decline() {
    if (changesRequested || requestingChanges) return;
    signError = null;
    showDeclineModal = true;
  }

  async function accept() {
    if (!ctx || changesRequested || requestingChanges) return;
    if (signing || accepting || declining || !viewerReady() || !packageReady() || !noticeAcknowledged || completed || accepted || declined) return;
    const token = $page.params.token;
    const recipientID = ctx.recipient.id;
    const noticeDigest = ctx.privacy.notice_digest;
    const ceremonyKey = currentCeremonyKey();
    const packageResponse = packageReview.response ? { ...packageReview.response } : undefined;
    const requiresPackagePortal = packageResponse !== undefined;
    if (!token) return;
    accepting = true;
    signError = null;
    try {
      if (!noticeAcknowledged) throw new Error('Acknowledge the current privacy notice before continuing.');
      const res = await fetch(`/sign/${token}/accept`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify(packageResponse ? { package_response: packageResponse } : {})
      });
      if (ceremonyKey !== currentCeremonyKey()) return;
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        if (ceremonyKey !== currentCeremonyKey()) return;
        throw new Error(data.error ?? 'Could not accept the document');
      }
      const data = await res.json();
      if (ceremonyKey !== currentCeremonyKey()) return;
      if (data.completed === true) {
        completed = { terminal: true, links: completionArtifactLinks(data, token, requiresPackagePortal) };
      } else {
        accepted = true;
      }
    } catch (e) {
      if (ceremonyKey === currentCeremonyKey()) {
        signError = (e as Error).message;
      }
    } finally {
      if (ceremonyKey === currentCeremonyKey()) accepting = false;
    }
  }

  async function confirmDecline() {
    if (!ctx || changesRequested || requestingChanges) return;
    const token = $page.params.token;
    const recipientID = ctx.recipient.id;
    const noticeDigest = ctx.privacy.notice_digest;
    if (!token) return;
    declining = true;
    signError = null;
    try {
      if (!noticeAcknowledged) throw new Error('Acknowledge the current privacy notice before continuing.');
      const res = await fetch(`/sign/${token}/decline`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify({ reason: declineReason })
      });
      if (token !== $page.params.token || recipientID !== ctx?.recipient.id) return;
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        if (token !== $page.params.token || recipientID !== ctx?.recipient.id) return;
        throw new Error(data.error ?? `Could not decline the document (${res.status})`);
      }
      declined = true;
      showDeclineModal = false;
    } catch (e) {
      if (token === $page.params.token && recipientID === ctx?.recipient.id) {
        signError = (e as Error).message;
      }
    } finally {
      if (token === $page.params.token && recipientID === ctx?.recipient.id) declining = false;
    }
  }

  function requestChanges() {
    if (requestingChanges) return;
    showChangesModal = true;
  }

  async function confirmRequestChanges() {
    if (!ctx || requestingChanges) return;
    if (!changesMessage.trim()) {
      signError = $t('changes.placeholder');
      return;
    }
    const token = $page.params.token;
    const recipientID = ctx.recipient.id;
    const noticeDigest = ctx.privacy.notice_digest;
    if (!token) return;
    requestingChanges = true;
    try {
      if (!noticeAcknowledged) throw new Error('Acknowledge the current privacy notice before continuing.');
      const res = await fetch(`/sign/${token}/request-changes`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify({ message: changesMessage })
      });
      if (token !== $page.params.token || recipientID !== ctx?.recipient.id) return;
      if (!res.ok) {
        const message = await res.text();
        if (token === $page.params.token && recipientID === ctx?.recipient.id) {
          signError = message;
        }
        return;
      }
      if (token !== $page.params.token || recipientID !== ctx?.recipient.id) return;
      pauseSigningForChanges();
    } catch (e) {
      if (token === $page.params.token && recipientID === ctx?.recipient.id) {
        signError = (e as Error).message;
      }
    } finally {
      if (token === $page.params.token && recipientID === ctx?.recipient.id) requestingChanges = false;
    }
  }

  function fontFamilyFor(name: string): string {
    return `'${name}', cursive`;
  }

</script>

<svelte:head>
  <link rel="stylesheet" href="/fonts/fonts.css" />
</svelte:head>

{#if ctx?.privacy}
  {@const noticeCeremonyKey = currentCeremonyKey()}
  {#key JSON.stringify([ceremonyEpoch, noticeCeremonyKey, ctx.source_kind])}
    {@const noticeEpoch = untrack(() => ceremonyEpoch)}
    <A13Notice
      privacy={ctx.privacy}
      storageKey={a13AcknowledgementKey(ctx)}
	  onAcknowledged={() => { if (noticeEpoch === ceremonyEpoch && noticeCeremonyKey === currentCeremonyKey()) acknowledgeCurrentNotice(); }}
    />
  {/key}
{/if}

<div class="signer-page">
  <header class="signer-bar">
    <div class="brand">
      <FileSignature class="size-4" />
      <span>Hash</span>
    </div>
    <div class="bar-right">
      {#if ctx}
        <div class="meta">
          <span>{ctx.document_name}</span>
          <span class="dot">·</span>
          <span>{$t('sign.for', { name: ctx.recipient.name, role: ctx.recipient.role })}</span>
        </div>
      {/if}
	  <span class="ceremony-language">English legal/signing experience</span>
    </div>
  </header>

  {#if loadError}
    <div class="banner banner-danger">{loadError}</div>
  {:else if !ctx}
    <p class="loading">{$t('common.loading')}</p>
  {:else if declined}
    <div class="state-card">
      <X class="size-10 text-danger mb-3 mx-auto" />
      <h2>{$t('sign.declined.title')}</h2>
      <p>{$t('sign.declined.body')}</p>
    </div>
  {:else if completed}
    <div class="state-card">
      <CheckCircle2 class="size-10 text-success mb-3 mx-auto" />
	  <h2>{ctx.requires_signature ? $t('sign.signed.title') : $t('sign.accepted.completedTitle')}</h2>
      {#if completed.links}
		<p>{ctx.requires_signature ? $t('sign.signed.allParties') : $t('sign.accepted.completedAllParties')}</p>
        <a class="btn btn-primary" href={completed.links.finalPDFURL} download>
		  {ctx.requires_signature ? $t('sign.signed.download') : $t('sign.accepted.download')}
        </a>
        <a class="btn btn-secondary" href={completed.links.auditCertURL} download>
          {$t('sign.completed.downloadAudit')}
        </a>
        {#if completed.links.packagePortalURL}<a class="btn btn-secondary" href={completed.links.packagePortalURL}>Download original contract files</a>{/if}
      {:else if completed.terminal}
        <p>{$t('sign.completed.downloadsUnavailable')}</p>
      {:else}
		<p>{ctx.requires_signature ? $t('sign.signed.recorded') : $t('sign.accepted.completedRecorded')}</p>
      {/if}
    </div>
  {:else if accepted}
    <div class="state-card">
      <CheckCircle2 class="size-10 text-success mb-3 mx-auto" />
      <h2>{$t('sign.accepted.title')}</h2>
      <p>{$t('sign.accepted.body')}</p>
    </div>
  {:else}
    <main class="signer-main">
      {#if ctx.amendment_context}<div class="amendment-context"><SignerAmendmentContext disclosure={ctx.amendment_context} /></div>{/if}
      {#if ctx.pre_sign_context}
        <section class="state-card mb-4" aria-label="Provider pre-signing disclosure">
          <h2>Our company’s part is already signed</h2>
          <p>{ctx.pre_sign_context.provider_name} pre-signed the provider’s part on <time datetime={ctx.pre_sign_context.executed_at}>{ctx.pre_sign_context.executed_at}</time>.</p>
          <p class="whitespace-pre-wrap">{ctx.pre_sign_context.disclosure_text}</p>
          <p>Review the provider-signed agreement below. Your own signature still requires your explicit confirmation.</p>
        </section>
      {/if}
      <article class="document-frame" aria-label="Current document">
        {#if ctx.source_kind === 'pdf'}
          {#if ctx.pdf_observation}
          {#key JSON.stringify([ceremonyEpoch, currentCeremonyKey(), ctx.source_kind])}
          {@const pdfEpoch = untrack(() => ceremonyEpoch)}
          <PdfSignerView
            token={$page.params.token ?? ''}
            noticeDigest={ctx.privacy.notice_digest}
            observation={ctx.pdf_observation}
            signed={!!completed}
            readOnly={changesRequested || requestingChanges || signing || accepting || declining}
            onReadyChange={(ready, scope) => updatePDFReady(ready, scope, pdfEpoch)}
            onFilledChange={(filled, scope) => updatePDFGate(filled, scope, pdfEpoch)}
            onSignatureClick={(scope) => adoptPDF(scope, pdfEpoch)}
          />
          {/key}
          {/if}
        {:else}
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div class="doc-page" onmouseup={onDocMouseUp}>
            {@html documentHTML}
          </div>
        {/if}
        {#if packageCanLoad()}
        {#key JSON.stringify([ceremonyEpoch, currentCeremonyKey()])}
          {@const packageEpoch = untrack(() => ceremonyEpoch)}
          {@const packageScope = untrack(() => ({ token: loadedToken, key: currentCeremonyKey(), documentID: ctx!.document_id,
            recipientID: ctx!.recipient.id, noticeDigest: ctx!.privacy.notice_digest, observation: ctx!.pdf_observation }))}
          <SignerPackageReview scope={packageScope} mainReady={documentDisplayed()}
            disabled={requestingChanges || signing || accepting || declining || commentLoading}
            onChange={next => updatePackageReview(next, packageEpoch)} />
        {/key}
        {/if}
      </article>

      <aside class="signer-actions">
        {#if viewState.error}
          <div class="banner banner-danger" role="alert">
            <p>{viewState.error}</p>
            <button class="btn btn-secondary" disabled={viewState.pending || !documentDisplayed() || !noticeAcknowledged} onclick={() => viewRecorder.retry()}>Retry view confirmation</button>
          </div>
        {/if}
        {#if changesRequested}
          <section class="negotiation-status" role="status" aria-label="Changes requested">
            <h2>{$t('changes.requested.title')}</h2>
            <p>{$t('changes.requested.body')}</p>
            <p>Signing and field changes are paused. Review this version and continue the conversation below.</p>
          </section>
          {#if ctx.source_kind === 'blocks'}
            <p class="anno-hint">{$t('changes.markHint')}</p>
          {/if}
        {:else if ctx.routing_tier === 'AES' || ctx.routing_tier === 'QES'}
          <h3 class="section-eyebrow">{$t('sign.tierUnavailable.title')}</h3>
          <p class="text-xs text-text-muted mb-3">
            {$t('sign.tierUnavailable.body', { tier: ctx.routing_tier })}
          </p>
          <button class="btn btn-secondary w-full" onclick={decline}>{$t('common.decline')}</button>
          <button class="btn btn-secondary w-full" onclick={requestChanges}>{$t('common.requestChanges')}</button>
        {:else if !ctx.requires_signature}
          <h3 class="section-eyebrow">{$t('sign.accept.title')}</h3>
          <p class="text-xs text-text-muted mb-3">{$t('sign.accept.body')}</p>
          <button class="btn btn-primary w-full" disabled={accepting || signing || declining || requestingChanges || !viewerReady() || !packageReady() || !noticeAcknowledged} onclick={accept}>
            <CheckCircle2 class="size-4" /> {accepting ? $t('common.loading') : $t('sign.accept.button')}
          </button>
          <button class="btn btn-secondary w-full" onclick={decline}>{$t('common.decline')}</button>
        {:else}
        {#if ctx.source_kind !== 'pdf'}
          {@const blockCeremonyKey = currentCeremonyKey()}
          {#key JSON.stringify([ceremonyEpoch, blockCeremonyKey, ctx.source_kind])}
          {@const blockEpoch = untrack(() => ceremonyEpoch)}
          <SignerFields
            token={$page.params.token ?? ''}
            noticeDigest={ctx.privacy.notice_digest}
            onChange={(v) => { if (blockEpoch === ceremonyEpoch && blockCeremonyKey === currentCeremonyKey()) fieldsFilled = v; }}
          />
          {/key}
        {:else}
          <p class="text-xs text-text-muted mb-3">{$t('sign.pdf.fillHint')}</p>
        {/if}

        <p class="anno-hint">
          {$t('changes.markHint')}
          {#if annoCount > 0}<span class="anno-count">{annoCount}</span>{/if}
        </p>

        <h3 class="section-eyebrow">{$t('sign.yourName')}</h3>
        <input
          type="text"
          bind:value={typedName}
          placeholder={$t('sign.namePlaceholder')}
          class="name-input"
        />

        <button
          class="btn btn-primary w-full"
          disabled={signing || accepting || declining || requestingChanges || !viewerReady() || !packageReady() || !noticeAcknowledged || !typedName.trim() || !fieldsFilled}
          onclick={adopt}
          title={!fieldsFilled ? $t('sign.fillRequiredTitle') : ''}
        >
          <FileSignature class="size-4" /> {$t('sign.adoptAndSign')}
        </button>
        {#if !fieldsFilled}
          <p class="text-xs text-text-muted mt-2">{$t('sign.saveRequired')}</p>
        {/if}

        <button class="btn btn-secondary w-full" onclick={decline}>{$t('common.decline')}</button>
        <button class="btn btn-secondary w-full" onclick={requestChanges}>{$t('common.requestChanges')}</button>
        {/if}

        {#if !changesRequested}
        <p class="legal-note">
          <ShieldCheck class="size-3 inline" />
		  {ctx.requires_signature ? $t('sign.legalNote') : $t('sign.accept.legalNote')}
        </p>
        {/if}
        {#if signError}
          <p class="error">{signError}</p>
        {/if}

        <div class="comments">
          <h3 class="section-eyebrow">{$t('comments.title')}</h3>
          <nav aria-label="Message history" class="flex gap-2">
            <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment || !olderCommentCursor}
              onclick={() => olderCommentCursor && loadComments(undefined, undefined, { kind: 'before', cursor: olderCommentCursor })}>Older</button>
            <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment || !newerCommentCursor}
              onclick={() => newerCommentCursor && loadComments(undefined, undefined, { kind: 'after', cursor: newerCommentCursor })}>Newer</button>
            <button type="button" class="btn btn-secondary" disabled={postingComment} onclick={() => loadComments()}>Latest</button>
          </nav>
          <p role="status" aria-live="polite">{commentLoading ? 'Loading messages…' : ''}</p>
          {#if commentRefreshError}
            <div role="alert">
              <p class="error">{commentRefreshError}</p>
              <button type="button" class="btn btn-secondary" disabled={commentLoading || postingComment} onclick={() => commentHistory.retry()}>Retry message refresh</button>
            </div>
          {/if}
          {#if comments.length}
            <ul class="comment-list">
              {#each comments as c (c.id)}
                <li class="comment-item {c.author_side === 'signer' ? 'mine' : ''}">
                  <span class="comment-meta">{c.author_name}</span>
                  <span class="comment-body">{c.body}</span>
                </li>
              {/each}
            </ul>
          {/if}
          <textarea
            bind:value={commentBody}
            rows="2"
            placeholder={$t('comments.placeholder')}
            class="comment-input"
          ></textarea>
          <button class="btn btn-secondary w-full" disabled={postingComment || !commentBody.trim()} onclick={sendComment}>
            {$t('comments.send')}
          </button>
        </div>
      </aside>
    </main>
  {/if}
</div>

{#if showAdoptModal && ctx && !changesRequested}
  <div class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <h3 class="modal-title">{$t('adopt.title')}</h3>
      <p class="modal-sub">{$t('adopt.sub')}</p>

      <div class="font-grid">
        {#each ctx.fonts as font (font)}
          <button
            class="font-option"
            class:selected={chosenFont === font}
            onclick={() => (chosenFont = font)}
            type="button"
          >
            <span class="font-preview" style="font-family: {fontFamilyFor(font)};">
              {typedName || ctx.recipient.name}
            </span>
            <span class="font-label">{font}</span>
          </button>
        {/each}
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary" onclick={() => (showAdoptModal = false)}>{$t('common.cancel')}</button>
        <button class="btn btn-primary" disabled={signing || accepting || declining || requestingChanges || !viewerReady() || !packageReady() || !fieldsFilled || !noticeAcknowledged || !typedName.trim()} onclick={confirmSign}>
          {signing ? $t('adopt.signing') : $t('adopt.confirm')}
        </button>
      </div>
      {#if signError}
        <p class="error">{signError}</p>
      {/if}
    </div>
  </div>
{/if}

{#if showDeclineModal && !changesRequested}
  <div class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <h3 class="modal-title">{$t('decline.title')}</h3>
      <p class="modal-sub">{$t('decline.sub')}</p>
      <textarea
        bind:value={declineReason}
        rows="3"
        placeholder={$t('decline.reasonPlaceholder')}
        class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      ></textarea>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick={() => (showDeclineModal = false)}>{$t('common.cancel')}</button>
        <button class="btn btn-primary" disabled={declining} onclick={confirmDecline}>
          {declining ? $t('common.loading') : $t('decline.confirm')}
        </button>
      </div>
      {#if signError}
        <p class="error">{signError}</p>
      {/if}
    </div>
  </div>
{/if}

{#if showChangesModal}
  <div class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <h3 class="modal-title">{$t('changes.title')}</h3>
      <p class="modal-sub">{$t('changes.sub')}</p>
      <textarea
        bind:value={changesMessage}
        rows="4"
        placeholder={$t('changes.placeholder')}
        class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      ></textarea>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick={() => (showChangesModal = false)}>{$t('common.cancel')}</button>
        <button class="btn btn-primary" disabled={requestingChanges} onclick={confirmRequestChanges}>{requestingChanges ? $t('common.loading') : $t('changes.confirm')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAnno}
  <div class="anno-popup" style="top: {annoTop}px; left: {annoLeft}px;">
    <p class="anno-popup-label">{$t('changes.title')}</p>
    <p class="anno-popup-quote">{annoQuote}</p>
    <textarea
      bind:value={annoComment}
      rows="2"
      placeholder={$t('changes.placeholder')}
      class="anno-input"
    ></textarea>
    <input bind:value={annoProposed} placeholder={$t('changes.proposedPlaceholder')} class="anno-input anno-single" />
    <div class="anno-popup-actions">
      <button class="btn btn-secondary" onclick={() => (showAnno = false)}>{$t('common.cancel')}</button>
      <button class="btn btn-primary" disabled={requestingChanges} onclick={submitAnno}>{requestingChanges ? $t('common.loading') : $t('changes.confirm')}</button>
    </div>
    {#if annoError}<p class="error">{annoError}</p>{/if}
  </div>
{/if}

<style>
  .signer-page {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--t-bg);
  }
  .signer-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.25rem;
    background: var(--t-bg-surface);
    border-bottom: 1px solid var(--t-border-light);
    font-size: 13px;
  }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 1.05rem;
  }
  .meta {
    display: flex;
    gap: 0.5rem;
    color: var(--t-text-muted);
    font-size: 12px;
  }
  .dot { opacity: 0.5; }
  .bar-right { display: flex; align-items: center; gap: 1rem; }
	.ceremony-language { color: var(--t-text-muted); font-size: 12px; }
  .loading { padding: 3rem; text-align: center; color: var(--t-text-muted); }
  .signer-main {
    display: grid;
    grid-template-columns: 1fr 280px;
    gap: 1.25rem;
    padding: 1.5rem;
    flex: 1;
  }
  /* The document column sits on a soft gutter, like a Google-Docs canvas. */
  .amendment-context { grid-column: 1 / -1; min-width: 0; }
  .document-frame {
    background: var(--t-bg);
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 2rem 1.5rem;
    min-height: 70vh;
    overflow: auto;
  }
  /* A4 sheet (794px @ 96dpi) centered on the gutter with on-screen margins
     mirroring the printed 1in page margins. The injected document supplies
     its own typography (scoped under .hash-doc); we only frame the page. */
  .doc-page {
    width: 794px;
    max-width: 100%;
    margin: 0 auto;
    background: #ffffff;
    color: #18181b;
    padding: 72px 76px;
    border-radius: 4px;
    box-shadow:
      0 1px 2px rgba(24, 24, 27, 0.06),
      0 10px 30px rgba(24, 24, 27, 0.08);
  }
  .doc-page :global(.hash-doc) {
    max-width: none;
    margin: 0;
  }
  .signer-actions {
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    height: fit-content;
    position: sticky;
    top: 1rem;
  }
  .section-eyebrow {
    font-family: var(--font-mono);
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.2em;
    color: var(--t-text-muted);
    margin: 0;
  }
  .negotiation-status h2 { font-size: 1.1rem; margin: 0 0 0.5rem; }
  .negotiation-status p { font-size: 12px; line-height: 1.5; color: var(--t-text-muted); }
  .name-input {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.375rem;
    background: var(--t-bg-elevated);
    font-size: 0.9rem;
  }
  .legal-note {
    font-size: 11px;
    color: var(--t-text-muted);
    line-height: 1.4;
    margin-top: 0.5rem;
  }
  .error {
    color: var(--t-danger);
    font-size: 12px;
    margin-top: 0.5rem;
  }
  .anno-hint {
    font-size: 11px;
    color: var(--t-text-muted);
    line-height: 1.4;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .anno-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: 9px;
    background: var(--t-accent);
    color: var(--t-accent-foreground, #fff);
    font-size: 10px;
    font-weight: 600;
  }
  .anno-popup {
    position: fixed;
    z-index: 200;
    width: 340px;
    max-width: calc(100vw - 24px);
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.6rem;
    box-shadow: 0 16px 48px rgba(10, 10, 10, 0.28);
    padding: 0.85rem;
  }
  .anno-popup-label {
    font-family: var(--font-mono);
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.18em;
    color: var(--t-text-muted);
    margin: 0 0 0.4rem;
  }
  .anno-popup-quote {
    font-size: 12px;
    color: var(--t-text-primary);
    border-left: 3px solid var(--t-accent);
    padding: 0.2rem 0 0.2rem 0.6rem;
    margin: 0 0 0.5rem;
    max-height: 60px;
    overflow: auto;
  }
  .anno-input {
    width: 100%;
    padding: 0.45rem 0.55rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.4rem;
    background: var(--t-bg-elevated);
    font-size: 0.85rem;
    margin-bottom: 0.45rem;
    box-sizing: border-box;
  }
  .anno-popup-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }
  .comments {
    margin-top: 1rem;
    padding-top: 0.85rem;
    border-top: 1px solid var(--t-border-light);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .comment-list {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    max-height: 220px;
    overflow-y: auto;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .comment-item {
    background: var(--t-bg-elevated);
    border: 1px solid var(--t-border-light);
    border-radius: 0.4rem;
    padding: 0.4rem 0.55rem;
    font-size: 0.8rem;
  }
  .comment-item.mine {
    border-color: var(--t-accent);
  }
  .comment-meta {
    display: block;
    font-size: 0.65rem;
    color: var(--t-text-muted);
    margin-bottom: 0.15rem;
  }
  .comment-body {
    white-space: pre-wrap;
    color: var(--t-text-primary);
  }
  .comment-input {
    width: 100%;
    padding: 0.45rem 0.55rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.4rem;
    background: var(--t-bg-elevated);
    font-size: 0.82rem;
    box-sizing: border-box;
  }
  .state-card {
    margin: 4rem auto;
    max-width: 480px;
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.75rem;
    padding: 2.5rem;
    text-align: center;
  }
  .state-card h2 {
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 1.5rem;
    margin: 0 0 0.5rem;
  }
  .banner {
    margin: 1.5rem;
    padding: 1rem 1.25rem;
    border-radius: 0.5rem;
    border: 1px solid var(--t-border-light);
  }
  .banner-danger {
    color: var(--t-danger);
    border-color: var(--t-danger);
  }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(10, 10, 10, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 1rem;
  }
  .modal {
    background: var(--t-bg-surface);
    border-radius: 1rem;
    padding: 1.5rem;
    max-width: 520px;
    width: 100%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
  }
  .modal-title {
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 1.4rem;
    margin: 0 0 0.25rem;
  }
  .modal-sub {
    color: var(--t-text-muted);
    font-size: 13px;
    margin: 0 0 1rem;
  }
  .font-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
    margin: 1rem 0;
  }
  .font-option {
    background: var(--t-bg-elevated);
    border: 2px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 1rem 0.75rem;
    cursor: pointer;
    text-align: center;
    transition: border-color 150ms ease, background 150ms ease;
  }
  .font-option:hover {
    background: var(--t-bg-hover);
  }
  .font-option.selected {
    border-color: var(--t-accent);
    background: var(--t-bg-surface);
  }
  .font-preview {
    display: block;
    font-size: 1.6rem;
    line-height: 1;
    margin-bottom: 0.5rem;
    color: var(--t-text-primary);
  }
  .font-label {
    display: block;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--t-text-muted);
  }
  .modal-actions {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    margin-top: 1rem;
  }
  @media (max-width: 768px) {
    .signer-main {
      grid-template-columns: 1fr;
    }
    .signer-actions {
      position: static;
    }
  }
</style>
