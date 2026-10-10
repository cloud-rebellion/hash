<script lang="ts">
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { page } from '$app/stores';
  import { sameRecipientDraft, type RecipientDraft } from './senderDraft';
  import {
    listRecipients,
    createRecipient,
    updateRecipient,
    deleteRecipient,
    sendDocument,
    remindDocument,
    voidDocument,
    finalPdfURL,
    auditCertURL,
    SendError,
    type Recipient,
    type SignerLink,
    type LawfulBasis,
    type HTMLDocumentParty,
  } from '$lib/api/client';
  import { LOCALES } from '$lib/i18n';
  import {
    ceremonyModeCopy,
    hasCeremonyParticipant,
    recipientRoleOptions,
  } from './senderMode';
  import {
    Send,
    Bell,
    Ban,
    Plus,
    Trash2,
    Pencil,
    Download,
    FileCheck,
    Copy,
    Users,
    ShieldAlert,
    CreditCard,
    ArrowUpRight,
  } from 'lucide-svelte';

  type Props = {
    documentID: string;
    status: string;
    requiresSignature?: boolean;
    reviewRequired?: boolean;
    revisionBlocked?: boolean;
    intendedParties?: HTMLDocumentParty[];
    recipientIdentityLocked?: boolean;
    sourceCommitment?: string;
    defaultLocale?: string;
    signatureFields?: { role: string; label: string }[];
    onStatusChange?: (next: string) => void;
    onDefaultLocaleChange?: (locale: string) => Promise<void> | void;
    onRecipientsChange?: () => void;
  };

  let {
    documentID,
    status,
    requiresSignature = true,
    reviewRequired = false,
    revisionBlocked = false,
    intendedParties = [],
    recipientIdentityLocked = false,
    sourceCommitment = '',
    defaultLocale = 'en',
    signatureFields = [],
    onStatusChange,
    onDefaultLocaleChange,
    onRecipientsChange,
  }: Props = $props();

  // Distinct roles that have a signature field; each needs a recipient to sign.
  const signerRoles = $derived([
    ...new Set([...intendedParties.map((party) => party.role), ...signatureFields.map((field) => field.role.trim().toLowerCase()).filter(Boolean)]),
  ]);
  const partyConflicts = $derived(intendedPartyConflicts());
  const missingRoles = $derived(
    requiresSignature
      ? signerRoles.filter((role) => !recipients.some((r) => r.role === role))
      : [],
  );
  const modeCopy = $derived(ceremonyModeCopy(requiresSignature));
  const roleOptions = $derived(recipientRoleOptions(signatureFields));

  // Document-level default ceremony language. The sender dictates this before
  // sending; every new recipient inherits it (see openAdd) and the whole
  // ceremony (email + signing page + rendered document) opens in it.
  // This is deliberately an initial value, not a live mirror of the prop:
  // subsequent changes come from the select and are persisted explicitly.
  let docLocale = $state(untrack(() => defaultLocale || 'en'));
  let confirmedDocLocale = $state(untrack(() => defaultLocale || 'en'));
  let savingLocale = $state(false);

  async function changeDocLocale(e: Event) {
    const scope = captureScope();
    if (!scope || !editable || savingLocale || busy || saving) return;
    const next = (e.currentTarget as HTMLSelectElement).value;
    docLocale = next;
    savingLocale = true;
    try {
      const saveLocale = onDefaultLocaleChange;
      if (!saveLocale) throw new Error('Document language cannot be saved here.');
      await saveLocale(next);
      await tick();
      if (!isCurrent(scope)) return;
      if (defaultLocale !== next) throw new Error('The document language was not confirmed. The previous language has been restored.');
      confirmedDocLocale = next;
    } catch (e) {
      if (isCurrent(scope)) {
        docLocale = confirmedDocLocale;
        error = (e as Error).message;
      }
    } finally {
      if (isCurrent(scope)) savingLocale = false;
    }
  }

  let recipients = $state<Recipient[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let recipientRefreshError = $state<string | null>(null);
  let sendErr = $state<SendError | null>(null);

  // Recipient add/edit form.
  let showForm = $state(false);
  let editingId = $state<string | null>(null);
  let fName = $state('');
  let fEmail = $state('');
  let fRole = $state('signer');
  let fLocale = $state('en');
  let saving = $state(false);
  let formBaseline = $state<RecipientDraft | null>(null);
  let formRevision = 0;
  let panelRevision = 0;
  let refreshRevision = 0;
  let observedSourceCommitment = untrack(() => sourceCommitment);
  let disposed = false;
  let initialized = false;
  let boundDocumentID = $state(untrack(() => documentID));
  let documentChanged = $state(false);
  let removingID = $state<string | null>(null);
  let reminderTimer: ReturnType<typeof setTimeout> | null = null;
  let copyTimer: ReturnType<typeof setTimeout> | null = null;
  type PanelScope = { id: string; revision: number };
  function captureScope(): PanelScope | null {
    if (disposed || documentChanged || boundDocumentID !== documentID || $page.params.id !== documentID) return null;
    return { id: documentID, revision: panelRevision };
  }
  function isCurrent(scope: PanelScope): boolean {
    return !disposed && !documentChanged && scope.id === boundDocumentID && scope.id === documentID
      && scope.id === $page.params.id && scope.revision === panelRevision;
  }
  function intendedPartyConflicts(): string[] {
    const issues: string[] = [];
    for (const party of intendedParties) {
      const recipient = recipients.find((candidate) => candidate.id === party.recipient_id);
      if (!recipient) issues.push(`${party.slot === 'provider' ? 'Our company' : 'Customer'} representative is missing.`);
      else if (recipient.role !== party.role || recipient.name !== party.name || recipient.email !== party.email) {
        issues.push(`${party.slot === 'provider' ? 'Our company' : 'Customer'} recipient differs from the printed representative.`);
      }
      if (recipients.some((candidate) => candidate.role === party.role && candidate.id !== party.recipient_id)) issues.push(`More than one recipient occupies the ${party.slot} signing role.`);
    }
    if (intendedParties.length && (intendedParties.length !== 2 || !intendedParties.some((party) => party.slot === 'provider') || !intendedParties.some((party) => party.slot === 'customer'))) issues.push('Both declared signing parties are required.');
    return issues;
  }
  function currentForm(): RecipientDraft {
    return { editingId, name: fName, email: fEmail, role: fRole, locale: fLocale };
  }
  function recipientDraftChanged(): boolean {
    return showForm && formBaseline !== null && !sameRecipientDraft(currentForm(), formBaseline);
  }
  function hasMeaningfulDraft(): boolean {
    return recipientDraftChanged() || lawfulBasis !== '' || docLocale !== confirmedDocLocale;
  }
  function confirmFormReplacement(): boolean {
    return !recipientDraftChanged() || window.confirm('Discard the unsaved recipient changes?');
  }

  // Lifecycle action state.
  let busy = $state<'send' | 'remind' | 'void' | null>(null);
  let links = $state<SignerLink[] | null>(null);
	let lawfulBasis = $state<LawfulBasis | ''>('');
  let remindedFlash = $state<number | null>(null);
  let copiedID = $state<string | null>(null);

  const editable = $derived(status === 'draft');
  const isLive = $derived(status === 'sent' || status === 'in_progress');
  const isCompleted = $derived(status === 'completed');
  const isTerminal = $derived(
    status === 'voided' || status === 'declined' || status === 'expired',
  );
  const hasParticipant = $derived(
    hasCeremonyParticipant(
      requiresSignature,
      recipients.map((recipient) => recipient.role),
      signerRoles,
    ),
  );

  async function refresh() {
    const scope = captureScope();
    if (!scope) return;
    const revision = ++refreshRevision;
    loading = true;
    try {
      const loaded = await listRecipients(scope.id);
      if (!loaded.every((recipient) => recipient.document_id === scope.id)) throw new Error('The server returned recipients for a different document.');
      if (isCurrent(scope) && revision === refreshRevision) {
        recipients = loaded;
        recipientRefreshError = null;
      }
    } catch (e) {
      if (isCurrent(scope) && revision === refreshRevision) recipientRefreshError = (e as Error).message;
    } finally {
      if (isCurrent(scope) && revision === refreshRevision) loading = false;
    }
  }
  function initializePanel(id: string) {
    panelRevision++;
    refreshRevision++;
    formRevision++;
    boundDocumentID = id;
    documentChanged = false;
    recipients = [];
    loading = true;
    error = null;
    recipientRefreshError = null;
    sendErr = null;
    showForm = false;
    editingId = null;
    fName = '';
    fEmail = '';
    fRole = 'signer';
    fLocale = 'en';
    formBaseline = null;
    saving = false;
    savingLocale = false;
    removingID = null;
    busy = null;
    links = null;
    lawfulBasis = '';
    remindedFlash = null;
    copiedID = null;
    confirmedDocLocale = defaultLocale || 'en';
    docLocale = confirmedDocLocale;
    if (reminderTimer) clearTimeout(reminderTimer);
    if (copyTimer) clearTimeout(copyTimer);
    initialized = true;
    observedSourceCommitment = sourceCommitment;
    void refresh();
  }
  $effect(() => {
    const id = documentID;
    untrack(() => {
      if (initialized && id === boundDocumentID) return;
      if (initialized && hasMeaningfulDraft()) {
        panelRevision++;
        documentChanged = true;
        error = 'The document changed. Your recipient and sending draft has been retained; review it before opening the current document.';
        return;
      }
      initializePanel(id);
    });
  });
  $effect(() => {
    const commitment = sourceCommitment;
    untrack(() => refreshSourceRecipients(commitment));
  });
  function refreshSourceRecipients(commitment: string) {
    if (!initialized || !captureScope() || commitment === observedSourceCommitment) return;
    observedSourceCommitment = commitment;
    panelRevision++; refreshRevision++;
    saving = false; savingLocale = false; removingID = null; busy = null;
    if (recipientDraftChanged()) error = 'The printed document changed. Your recipient draft is retained; cancel it and review the current representatives before continuing.';
    else closeForm(true);
    void refresh();
  }
  function discardRetainedDraft() {
    if (!window.confirm('Discard the retained recipient and sending draft and open the current document?')) return;
    initializePanel(documentID);
  }
  beforeNavigate(({ cancel, willUnload, from, to }) => {
    if (!willUnload && to?.url.pathname !== from?.url.pathname && hasMeaningfulDraft()
        && !window.confirm('You have unsaved recipient or sending changes. Leave this document and discard the draft? Changes already being saved may still complete.')) cancel();
  });
  function protectDraft(event: BeforeUnloadEvent) {
    if (!hasMeaningfulDraft()) return;
    event.preventDefault();
    event.returnValue = '';
  }
  onMount(() => {
    window.addEventListener('beforeunload', protectDraft);
    return () => window.removeEventListener('beforeunload', protectDraft);
  });
  onDestroy(() => {
    disposed = true;
    panelRevision++;
    refreshRevision++;
    if (reminderTimer) clearTimeout(reminderTimer);
    if (copyTimer) clearTimeout(copyTimer);
  });

  function openAdd() {
    if (!captureScope() || !editable || recipientIdentityLocked || saving || busy || !confirmFormReplacement()) return;
    editingId = null;
    fName = '';
    fEmail = '';
    const firstSupportedRequiredRole = roleOptions.find((option) =>
      signerRoles.includes(option.value),
    );
    fRole = requiresSignature ? (firstSupportedRequiredRole?.value ?? 'signer') : 'approver';
    fLocale = requiresSignature ? (docLocale || 'en') : 'en';
    showForm = true;
    formRevision++;
    formBaseline = currentForm();
  }

  function openEdit(r: Recipient) {
    if (!captureScope() || !editable || saving || busy || (recipientIdentityLocked && !intendedParties.some((party) => party.recipient_id === r.id))
        || !recipients.some((recipient) => recipient.id === r.id) || !confirmFormReplacement()) return;
    editingId = r.id;
    fName = r.name;
    fEmail = r.email;
    fRole = r.role;
    fLocale = requiresSignature ? (r.locale || 'en') : 'en';
    showForm = true;
    formRevision++;
    formBaseline = currentForm();
  }

  function closeForm(confirmed = false) {
    if (!confirmed && (saving || !confirmFormReplacement())) return;
    showForm = false;
    editingId = null;
    formBaseline = null;
    formRevision++;
  }

  async function submitForm() {
    const scope = captureScope();
    if (!scope || !editable || saving || busy || savingLocale || !showForm) return;
    if (!fName.trim() || !fEmail.trim()) {
      error = 'Name and email are required.';
      return;
    }
    if (recipientIdentityLocked) {
      const party = intendedParties.find((candidate) => candidate.recipient_id === editingId);
      if (!party || fName !== party.name || fEmail !== party.email || fRole !== party.role) {
        error = 'Change the printed representative in document values, then save and review the new PDF. Only email language can change here.';
        return;
      }
    }
    saving = true;
    error = null;
    const submitted = currentForm();
    const revision = formRevision;
    try {
      let saved: Recipient;
      const input = { name: submitted.name.trim(), email: submitted.email.trim(), role: submitted.role, locale: submitted.locale };
      if (submitted.editingId) {
        saved = await updateRecipient(scope.id, submitted.editingId, input);
      } else {
        const nextOrder = recipients.reduce((m, r) => Math.max(m, r.order_index), -1) + 1;
        saved = await createRecipient(scope.id, {
          ...input,
          order_index: nextOrder,
        });
      }
      if (!isCurrent(scope)) return;
      if (saved.document_id !== scope.id || (submitted.editingId && saved.id !== submitted.editingId)) throw new Error('The server did not confirm this recipient. Your draft has been retained.');
      onRecipientsChange?.();
      if (revision === formRevision) {
        if (sameRecipientDraft(currentForm(), submitted)) closeForm(true);
        else {
          editingId = saved.id;
          formBaseline = { ...submitted, editingId: saved.id };
        }
      }
      await refresh();
    } catch (e) {
      if (isCurrent(scope)) error = (e as Error).message;
    } finally {
      if (isCurrent(scope)) saving = false;
    }
  }

  async function remove(r: Recipient) {
    const scope = captureScope();
    if (!scope || !editable || recipientIdentityLocked || saving || busy || removingID || !recipients.some((recipient) => recipient.id === r.id)) return;
    if (!confirm(`Remove ${r.name} <${r.email}> from this document?`)) return;
    error = null;
    removingID = r.id;
    try {
      await deleteRecipient(scope.id, r.id);
      if (!isCurrent(scope)) return;
      onRecipientsChange?.();
      await refresh();
    } catch (e) {
      if (isCurrent(scope)) error = (e as Error).message;
    } finally {
      if (isCurrent(scope)) removingID = null;
    }
  }

  async function send() {
    const scope = captureScope();
    if (!scope || !editable || busy || saving || savingLocale || removingID || reviewRequired || revisionBlocked || loading || recipientRefreshError || partyConflicts.length) return;
    if (recipientDraftChanged()) {
      error = 'Save or cancel the recipient changes before sending this document.';
      return;
    }
    if (!hasParticipant || missingRoles.length) return;
    const basis = lawfulBasis;
    const statusChanged = onStatusChange;
    busy = 'send';
    error = null;
    sendErr = null;
    try {
		if (!basis) {
			error = 'Select and confirm the controller\'s GDPR Article 6 lawful basis before sending.';
			return;
		}
		const res = await sendDocument(scope.id, basis);
      if (!isCurrent(scope)) return;
      links = res.links;
      lawfulBasis = '';
      closeForm(true);
      statusChanged?.(res.status || 'sent');
      await refresh();
    } catch (e) {
      if (!isCurrent(scope)) return;
      if (e instanceof SendError) {
        sendErr = e;
      } else {
        error = (e as Error).message;
      }
    } finally {
      if (isCurrent(scope)) busy = null;
    }
  }

  async function remind() {
    const scope = captureScope();
    if (!scope || !isLive || busy) return;
    busy = 'remind';
    error = null;
    try {
      const res = await remindDocument(scope.id);
      if (!isCurrent(scope)) return;
      remindedFlash = res.reminded;
      if (reminderTimer) clearTimeout(reminderTimer);
      reminderTimer = setTimeout(() => { if (isCurrent(scope)) remindedFlash = null; }, 4000);
      await refresh();
    } catch (e) {
      if (isCurrent(scope)) error = (e as Error).message;
    } finally {
      if (isCurrent(scope)) busy = null;
    }
  }

  async function voidDoc() {
    const scope = captureScope();
    if (!scope || !isLive || busy) return;
    const reason = prompt('Reason for voiding this document (recorded in the audit trail):');
    if (reason === null) return;
    const statusChanged = onStatusChange;
    busy = 'void';
    error = null;
    try {
      await voidDocument(scope.id, reason.trim() || undefined);
      if (!isCurrent(scope)) return;
      links = null;
      statusChanged?.('voided');
      await refresh();
    } catch (e) {
      if (isCurrent(scope)) error = (e as Error).message;
    } finally {
      if (isCurrent(scope)) busy = null;
    }
  }

  async function copyLink(l: SignerLink) {
    const scope = captureScope();
    if (!scope || !links?.some((link) => link.recipient_id === l.recipient_id && link.url === l.url)) return;
    try {
      await navigator.clipboard.writeText(l.url);
      if (!isCurrent(scope)) return;
      copiedID = l.recipient_id;
      if (copyTimer) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => { if (isCurrent(scope)) copiedID = null; }, 2000);
    } catch {
      /* clipboard blocked; the link is still visible to select manually */
    }
  }

  // Per-recipient status pill styling.
  function pill(s: string): string {
    switch (s) {
      case 'signed':
      case 'accepted':
        return 'text-success border-success';
      case 'viewed':
      case 'sent':
        return 'text-info border-info';
      case 'declined':
      case 'bounced':
        return 'text-danger border-danger';
      default:
        return 'text-text-muted border-border-light';
    }
  }

	const lawfulBasisOptions: { value: LawfulBasis; label: string }[] = [
		{ value: 'contract', label: 'Art. 6(1)(b) — contract or requested pre-contractual steps' },
	];

  function ts(value?: string): string {
    return value ? new Date(value).toLocaleString() : '';
  }
</script>

<section class="card p-5 mb-6" aria-label="Recipients and sending">
  {#if documentChanged}
    <div role="alert" class="mb-4 text-danger">
      <p>The current document differs from this retained recipient draft. Sending and recipient changes are blocked.</p>
      <button type="button" class="btn btn-secondary" onclick={discardRetainedDraft}>Discard retained draft and open current document</button>
    </div>
  {/if}
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <Users class="size-4" /> {modeCopy.sectionTitle}
    </h2>
    {#if editable && !recipientIdentityLocked}
      <button class="btn btn-secondary text-xs" onclick={openAdd} disabled={documentChanged || saving || !!busy}>
        <Plus class="size-3" /> Add recipient
      </button>
    {/if}
  </div>

  {#if editable}
    <div class="flex flex-wrap items-center gap-2 mb-4 pb-4 border-b border-border-light">
      <span class="text-xs uppercase tracking-widest text-text-muted font-mono">
        {requiresSignature ? 'Default email language' : 'Ceremony language'}
      </span>
      {#if requiresSignature}
        <select
          bind:value={docLocale}
          onchange={changeDocLocale}
          disabled={documentChanged || savingLocale || !!busy || saving}
          aria-label="Default email language"
          class="px-3 py-1.5 rounded-md border border-border-light bg-bg-elevated text-sm"
        >
          {#each LOCALES as l (l.code)}
            <option value={l.code}>{l.name}</option>
          {/each}
        </select>
      {:else}
        <span class="px-3 py-1.5 rounded-md border border-border-light bg-bg-elevated text-sm">English</span>
      {/if}
      <span class="text-xs text-text-muted">
        {savingLocale ? 'Saving...' : modeCopy.defaultLanguageHelp}
      </span>
    </div>
  {/if}

  <p class="text-sm text-text-secondary mb-4 leading-relaxed">
    {#if editable}
      {modeCopy.editableDescription}
    {:else if isLive}
      {modeCopy.liveDescription}
    {:else if isCompleted}
      {modeCopy.completedDescription}
    {:else}
      This document is {status}. No further sending actions are available.
    {/if}
  </p>
  {#if intendedParties.length}<div class="rounded-md border border-border-light bg-bg-elevated p-4 mb-4 space-y-3 text-sm" aria-label="Required contract parties">
    <p class="font-medium">Both declared parties must sign</p>
    <p>These representatives match the printed contract. Change identity details in document values and review the fresh PDF; this section can change their email language.</p>
    {#each intendedParties as party (party.slot)}<div class="space-y-1 break-words"><p><strong>{party.slot === 'provider' ? 'Our company' : 'Customer'}:</strong> {party.company_name} · {party.company_id}</p><p>{party.name} · {party.email}</p><p class="text-xs text-text-secondary">Declared authority: {party.representative_authority}</p></div>{/each}
    <p class="text-xs text-text-secondary">Identity and authority are declarations, not independent verification. These checks do not establish legal sufficiency.</p>
    {#if partyConflicts.length && !loading}<ul class="list-disc pl-5 text-warning" role="alert">{#each partyConflicts as issue, index (index)}<li>{issue}</li>{/each}</ul>{/if}
  </div>{/if}

  {#if editable && requiresSignature && signerRoles.length > 0}
    <div class="rounded-md border border-border-light bg-bg-elevated p-3 mb-4 text-sm">
      <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-2">Required signature fields</p>
      <ul class="space-y-1">
        {#each signatureFields as f (f.role + f.label)}
          {@const filled = recipients.some((r) => r.role === f.role.trim().toLowerCase())}
          <li class="flex items-center gap-2">
            <span class="inline-block size-1.5 rounded-full {filled ? 'bg-success' : 'bg-warning'}"></span>
            <span>{f.label}</span>
            <span class="text-text-muted text-xs">· role: {f.role}</span>
            {#if !filled}<span class="text-warning text-xs">missing a recipient with this role</span>{/if}
          </li>
        {/each}
      </ul>
    </div>
  {/if}

  {#if error}
    <div role="alert" class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">
      {error}
    </div>
  {/if}
  {#if recipientRefreshError}
    <div role="alert" class="mb-4 text-danger">
      <p>Recipients could not be refreshed. {recipientRefreshError}</p>
      <button type="button" class="btn btn-secondary" disabled={loading || documentChanged} onclick={refresh}>Retry recipient refresh</button>
    </div>
  {/if}

  {#if sendErr}
    {#if sendErr.status === 402}
      <div class="card p-4 mb-4 border-l-4 border-warning">
        <h3 class="font-display font-extralight text-base mb-1 flex items-center gap-2">
          <CreditCard class="size-4" /> Plan limit reached
        </h3>
        <p class="text-sm text-text-secondary mb-3 leading-relaxed">{sendErr.message}</p>
        <a class="btn btn-primary text-xs" href={sendErr.upgradeURL || '/settings/billing'}>
          <ArrowUpRight class="size-3" /> Upgrade plan
        </a>
      </div>
    {:else if sendErr.status === 409 && sendErr.requiredTier}
      <div class="card p-4 mb-4 border-l-4 border-warning">
        <h3 class="font-display font-extralight text-base mb-1 flex items-center gap-2">
          <ShieldAlert class="size-4" /> {requiresSignature ? 'Signature tier unavailable' : 'Ceremony assurance tier unavailable'}
        </h3>
        <p class="text-sm text-text-secondary mb-2 leading-relaxed">
          {#if requiresSignature}
            This document requires <strong>{sendErr.requiredTier}</strong> signing.
            Hash currently supports production signing at SES only, so this send is blocked
            and will not be silently downgraded.
          {:else}
            This document requires <strong>{sendErr.requiredTier}</strong> assurance.
            Hash currently supports production acknowledgement ceremonies at SES only, so this
            send is blocked and will not be silently downgraded.
          {/if}
        </p>
        {#if sendErr.matchedRules && sendErr.matchedRules.length}
          <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-1">
            Triggered by
          </p>
          <ul class="text-sm text-text-secondary list-disc pl-5 mb-3">
            {#each sendErr.matchedRules as rule}
              <li>{rule}</li>
            {/each}
          </ul>
        {/if}
        <a class="btn btn-secondary text-xs" href="/settings/eidas-rules">Review unavailable-tier rules</a>
      </div>
    {:else}
      <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">
        {sendErr.message}
      </div>
    {/if}
  {/if}

  {#if showForm}
    <div class="card p-4 mb-4">
      <h3 class="font-display font-extralight text-base mb-3">
        {editingId ? 'Edit recipient' : 'New recipient'}
      </h3>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Name</span>
          <input
            type="text"
            disabled={recipientIdentityLocked}
            bind:value={fName}
            placeholder="Jane Andersson"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Email</span>
          <input
            type="email"
            disabled={recipientIdentityLocked}
            bind:value={fEmail}
            placeholder="jane@example.com"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Role</span>
          <select
            disabled={recipientIdentityLocked}
            bind:value={fRole}
            class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          >
            {#each roleOptions as o}
              <option value={o.value}>{o.label}</option>
            {/each}
          </select>
        </label>
        <div class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Language</span>
          {#if requiresSignature}
            <select
              bind:value={fLocale}
              class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
            >
              {#each LOCALES as l (l.code)}
                <option value={l.code}>{l.name}</option>
              {/each}
            </select>
          {:else}
            <div class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm">English</div>
          {/if}
          <span class="text-xs text-text-muted">{modeCopy.recipientLanguageHelp}</span>
        </div>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={submitForm} disabled={documentChanged || saving || !!busy || savingLocale}>
          {saving ? 'Saving...' : editingId ? 'Save changes' : 'Add recipient'}
        </button>
        <button class="btn btn-secondary" onclick={() => closeForm()} disabled={saving}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loading && !recipients.length}
    <p class="text-text-muted text-sm">Loading...</p>
  {:else if recipients.length === 0}
    <p class="text-text-muted text-sm mb-4">
      No recipients yet.{#if editable}{' '}{modeCopy.emptyRecipients}{/if}
    </p>
  {:else}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard focus lets users scroll all recipient columns.) -->
    <div class="max-w-full overflow-x-auto mb-4" role="region" aria-label="Recipient details" tabindex="0">
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
          <th class="py-2">Recipient</th>
          <th>Role</th>
          <th>Status</th>
          {#if editable}
            <th class="text-right">Actions</th>
          {/if}
        </tr>
      </thead>
      <tbody class="divide-y divide-border-light">
        {#each recipients as r (r.id)}
          <tr data-recipient-id={r.id}>
            <td class="py-2">
              <div class="font-medium">{r.name}</div>
              <div class="text-xs text-text-muted">{r.email}</div>
            </td>
            <td class="capitalize">{r.role}<span class="text-text-muted normal-case"> · {r.locale}</span></td>
            <td>
              <span
                class="inline-block text-xs px-2 py-0.5 rounded-full border capitalize {pill(r.status)}"
                title={r.status === 'accepted'
                  ? 'Acknowledged'
                  : r.signed_at
                    ? `Signed ${ts(r.signed_at)}`
                  : r.first_viewed_at
                    ? `First viewed ${ts(r.first_viewed_at)}`
                    : r.sent_at
                      ? `Sent ${ts(r.sent_at)}`
                      : ''}
              >
                {r.status}
              </span>
            </td>
            {#if editable}
              <td class="text-right whitespace-nowrap">
                <button class="btn btn-secondary text-xs" aria-label={recipientIdentityLocked ? `Email language for ${r.name}` : `Edit ${r.name}`} disabled={documentChanged || saving || !!busy || (recipientIdentityLocked && !intendedParties.some((party) => party.recipient_id === r.id))} onclick={() => openEdit(r)}>
                  <Pencil class="size-3" />
                </button>
                <button class="btn btn-secondary text-xs" aria-label={`Remove ${r.name}`} disabled={recipientIdentityLocked || documentChanged || saving || !!busy || !!removingID} onclick={() => remove(r)}>
                  <Trash2 class="size-3" />
                </button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {/if}

  <!-- Action bar -->
	{#if editable}
		<div class="mb-4 rounded-md border border-border-light bg-bg-elevated p-3 space-y-2">
			<label class="block text-sm" for="lawful-basis">
				<span class="text-xs uppercase tracking-widest text-text-muted font-mono">{modeCopy.lawfulBasisLabel}</span>
				<select
					id="lawful-basis"
					bind:value={lawfulBasis}
					disabled={documentChanged || !!busy}
					class="mt-1 block w-full px-3 py-2 rounded-md border border-border-light bg-bg text-sm"
					required
				>
					<option value="" disabled>Select the controller-approved basis…</option>
					{#each lawfulBasisOptions as option (option.value)}
						<option value={option.value}>{option.label}</option>
					{/each}
				</select>
			</label>
			<p class="text-xs text-text-muted">
				Your organisation is the controller and must confirm that Art. 6(1)(b) actually applies to this document. Hash currently blocks ceremonies requiring another basis; it does not determine legal effect or choose a basis for you.
			</p>
		</div>
	{/if}
  <div class="flex flex-wrap items-center gap-3 pt-2 border-t border-border-light">
    {#if editable}
      <button class="btn btn-primary" onclick={send} disabled={revisionBlocked || reviewRequired || documentChanged || loading || !!recipientRefreshError || partyConflicts.length > 0 || !!busy || saving || savingLocale || !!removingID || recipientDraftChanged() || !hasParticipant || missingRoles.length > 0 || !lawfulBasis}>
        <Send class="size-4" /> {busy === 'send' ? modeCopy.sendingAction : modeCopy.sendAction}
      </button>
      {#if revisionBlocked}
        <span class="text-xs text-warning">Save or reconcile the document values and wording before sending.</span>
      {:else if reviewRequired}
        <span class="text-xs text-warning">Review the generated PDF above before sending.</span>
      {:else if partyConflicts.length > 0}
        <span class="text-xs text-warning">Resolve the declared party conflicts before sending.</span>
      {:else if !hasParticipant}
        <span class="text-xs text-text-muted">{modeCopy.missingParticipant}</span>
      {:else if missingRoles.length > 0}
        <span class="text-xs text-warning">Add a recipient for: {missingRoles.join(', ')}.</span>
      {/if}
    {:else if isLive}
      <button class="btn btn-secondary" onclick={remind} disabled={documentChanged || !!busy}>
        <Bell class="size-4" /> {busy === 'remind' ? 'Sending...' : 'Send reminder'}
      </button>
      <button class="btn btn-secondary" onclick={voidDoc} disabled={documentChanged || !!busy}>
        <Ban class="size-4" /> {busy === 'void' ? 'Voiding...' : 'Void document'}
      </button>
      {#if remindedFlash !== null}
        <span class="text-xs text-success">
          Reminder sent to {remindedFlash} pending recipient{remindedFlash === 1 ? '' : 's'}.
        </span>
      {/if}
    {:else if isCompleted}
      <a class="btn btn-primary" href={finalPdfURL(documentID)} download>
        <Download class="size-4" /> {modeCopy.completedPDF}
      </a>
      <a class="btn btn-secondary" href={auditCertURL(documentID)} download>
        <FileCheck class="size-4" /> {modeCopy.auditCertificate}
      </a>
    {:else if isTerminal}
      <span class="text-sm text-text-muted capitalize">Document {status}.</span>
    {/if}
  </div>

  {#if links && links.length}
    <div class="card p-4 mt-4 border-l-4 border-warning">
      <h3 class="font-display font-extralight text-base mb-1">{modeCopy.linksTitle}</h3>
      <p class="text-xs text-text-secondary mb-3 leading-relaxed">
        {modeCopy.linksDescription}
      </p>
      <ul class="divide-y divide-border-light">
        {#each links as l (l.recipient_id)}
          <li class="flex items-center gap-2 py-2">
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium">{l.name}</div>
              <code class="font-mono text-xs text-text-muted break-all">{l.url}</code>
            </div>
            <button class="btn btn-secondary text-xs" onclick={() => copyLink(l)}>
              <Copy class="size-3" /> {copiedID === l.recipient_id ? 'Copied' : 'Copy'}
            </button>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</section>
