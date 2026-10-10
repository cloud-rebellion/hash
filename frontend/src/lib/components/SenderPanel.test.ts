import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { sameRecipientDraft } from './senderDraft';

const source = readFileSync(new URL('./SenderPanel.svelte', import.meta.url), 'utf8');
const names = ['captureScope', 'isCurrent', 'currentForm', 'recipientDraftChanged', 'hasMeaningfulDraft', 'confirmFormReplacement',
  'intendedPartyConflicts', 'refreshSourceRecipients', 'changeDocLocale', 'refresh', 'initializePanel', 'openAdd', 'openEdit', 'closeForm', 'submitForm', 'remove', 'send', 'remind', 'voidDoc', 'copyLink'];
function callback(name: string): string {
  let start = source.indexOf(`function ${name}(`);
  if (source.slice(start - 6, start) === 'async ') start -= 6;
  let position = source.indexOf('{', start), depth = 1;
  const opening = position;
  while (depth && ++position < source.length) {
    if (source[position] === '{') depth++;
    if (source[position] === '}') depth--;
  }
  if (start < 0 || opening < 0 || depth) throw new Error(`Production callback missing: ${name}`);
  return source.slice(start, position + 1);
}
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(names.map(callback).join('\n'));
const bind = new Function('env', `with(env) { ${code}; return { ${names.join(',')} }; }`);
function fixture() {
  const calls: any[] = [], prompts: string[] = [];
  const recipientChanges: string[] = [];
  const pending = (kind: string) => (...args: any[]) => new Promise((resolve, reject) => calls.push({ kind, args, resolve, reject }));
  const env: any = {
    documentID: 'A', boundDocumentID: 'A', $page: { params: { id: 'A' } }, panelRevision: 1, refreshRevision: 0, disposed: false,
    documentChanged: false, initialized: true, status: 'draft', editable: true, isLive: false,
    requiresSignature: true, reviewRequired: false, revisionBlocked: false, crmBlocked: false, crmBusy: false, onCRMReviewRequired: undefined, onMutationStateChange: undefined, generatedPlacementRequired: false, generatedPlacementReady: false, signerRoles: [], missingRoles: [], hasParticipant: true,
    intendedParties: [], recipientIdentityLocked: false, sourceCommitment: '', observedSourceCommitment: '',
    roleOptions: [{ value: 'signer' }, { value: 'approver' }],
    docLocale: 'en', confirmedDocLocale: 'en', defaultLocale: 'en', savingLocale: false,
    recipients: [{ id: 'original', document_id: 'A', name: 'Original', email: 'original@example.test', role: 'signer', locale: 'en', order_index: 0 }],
    loading: false, error: null, recipientRefreshError: null, sendErr: null, showForm: false,
    editingId: null, fName: '', fEmail: '', fRole: 'signer', fLocale: 'en', saving: false, formRevision: 0, formBaseline: null,
    removingID: null, busy: null, links: null, lawfulBasis: '', remindedFlash: null, copiedID: null,
    reminderTimer: null, copyTimer: null, sameRecipientDraft, tick: async () => {},
    onStatusChange: (next: string) => calls.push({ kind: 'status', args: [next] }),
    onRecipientsChange: () => recipientChanges.push(env.boundDocumentID),
    listRecipients: pending('list'), createRecipient: pending('create'), updateRecipient: pending('update'),
    deleteRecipient: pending('delete'), sendDocument: pending('send'), remindDocument: pending('remind'), voidDocument: pending('void'),
    navigator: { clipboard: { writeText: pending('clipboard') } },
    window: { confirm: (message: string) => { prompts.push(message); return env.confirmed; } },
    confirm: () => env.confirmed, prompt: () => 'Audit reason', confirmed: false, SendError: class extends Error {},
    setTimeout, clearTimeout
  };
  const actions = bind(env);
  Object.defineProperty(env, 'partyConflicts', { get: () => actions.intendedPartyConflicts() });
  return { env, calls, prompts, recipientChanges, actions };
}
function bindContractParties(state: ReturnType<typeof fixture>) {
  state.env.recipientIdentityLocked = true;
  state.env.intendedParties = ['provider', 'customer'].map((slot) => ({ slot, role: slot, recipient_id: slot,
    name: `${slot} representative`, email: `${slot}@example.test`, company_name: `${slot} company`, company_id: `${slot}-id`, representative_authority: 'Declared director' }));
  state.env.recipients = state.env.intendedParties.map((party: any, index: number) => ({ id: party.recipient_id, document_id: 'A', role: party.role,
    name: party.name, email: party.email, locale: 'en', order_index: index }));
}
test('both declared parties are checked before any signature field exists and missing or drifting identity blocks send', async () => {
  for (const drift of ['missing', 'name', 'email', 'role', 'extra_role']) {
    const state = fixture(); bindContractParties(state); state.env.lawfulBasis = 'contract';
    if (drift === 'missing') state.env.recipients.pop();
    if (drift === 'name') state.env.recipients[1].name = 'Different person';
    if (drift === 'email') state.env.recipients[1].email = 'different@example.test';
    if (drift === 'role') state.env.recipients[1].role = 'signer';
    if (drift === 'extra_role') state.env.recipients.push({ ...state.env.recipients[1], id: 'another' });
    expect(state.env.signatureFields ?? []).toEqual([]); expect(state.actions.intendedPartyConflicts().length).toBeGreaterThan(0);
    await state.actions.send(); expect(state.calls).toEqual([]);
  }
});
test('automatic page dispatch requires actual verified generated locations even with reviewed PDF and matching intended parties', async () => {
  const state = fixture(); bindContractParties(state); state.env.lawfulBasis = 'contract';
  state.env.generatedPlacementRequired = true;
  await state.actions.send(); expect(state.calls).toEqual([]);
  state.env.generatedPlacementReady = true;
  const pending = state.actions.send();
  expect(state.calls[0].kind).toBe('send');
  state.calls[0].resolve({ status: 'sent', links: [] }); await Promise.resolve(); await Promise.resolve();
  const readback = state.calls.find((call) => call.kind === 'list');
  expect(readback).toBeDefined(); readback.resolve(state.env.recipients); await pending;
  expect(state.env.busy).toBeNull();
});
test('bound signer identity cannot be separately added, deleted or rewritten, while email language can be saved', async () => {
  const state = fixture(); bindContractParties(state); const customer = state.env.recipients[1];
  state.actions.openAdd(); expect(state.env.showForm).toBe(false);
  state.env.confirmed = true; await state.actions.remove(customer); expect(state.calls).toEqual([]);
  state.actions.openEdit(customer); state.env.fName = 'Another name'; await state.actions.submitForm(); expect(state.calls).toEqual([]);
  state.env.fName = customer.name; state.env.fLocale = 'sv'; const pending = state.actions.submitForm();
  expect(state.calls[0].args).toEqual(['A', 'customer', { name: customer.name, email: customer.email, role: 'customer', locale: 'sv' }]);
  state.calls[0].resolve({ ...customer, locale: 'sv' }); await Promise.resolve(); await Promise.resolve();
  state.calls[1].resolve(state.env.recipients); await pending;
});
test('fresh source recipient refresh invalidates old reads and keeps unsaved email-language draft for deliberate reconciliation', async () => {
  const state = fixture(); bindContractParties(state); state.actions.openEdit(state.env.recipients[1]); state.env.fLocale = 'sv';
  const old = state.actions.refresh(); state.actions.refreshSourceRecipients('new-source');
  expect(state.env.fLocale).toBe('sv'); expect(state.env.error).toContain('draft is retained');
  state.calls[1].resolve([{ ...state.env.recipients[1], name: 'Fresh printed person' }]); await Promise.resolve(); await Promise.resolve();
  state.calls[0].resolve([{ ...state.env.recipients[1], name: 'Old stale person' }]); await old;
  expect(state.env.recipients[0].name).toBe('Fresh printed person'); expect(state.env.fLocale).toBe('sv');
});
function move(state: ReturnType<typeof fixture>) {
  state.env.documentID = 'B'; state.env.boundDocumentID = 'B'; state.env.$page.params.id = 'B'; state.env.panelRevision++;
  state.env.error = 'Current B error'; state.env.recipientRefreshError = 'Current B refresh';
  state.env.recipients = [{ id: 'B', document_id: 'B' }]; state.env.loading = true; state.env.saving = true; state.env.busy = 'send';
}
test('unsaved, pending or unreconciled HTML revision input blocks sending an older reviewed PDF', async () => {
  const state = fixture(); state.env.lawfulBasis = 'contract'; state.env.revisionBlocked = true;
  await state.actions.send(); expect(state.calls).toHaveLength(0); expect(state.env.lawfulBasis).toBe('contract');
  expect(state.env.busy).toBeNull();
});

test('CRM pending review and external Apply lock block actual Send and competing recipient writes', async () => {
  for (const gate of ['crmBlocked', 'crmBusy']) {
    const state = fixture(); state.env[gate] = true; state.env.lawfulBasis = 'contract';
    await state.actions.send(); expect(state.calls).toEqual([]); expect(state.env.lawfulBasis).toBe('contract');
    if (gate === 'crmBusy') {
      state.actions.openAdd(); state.actions.openEdit(state.env.recipients[0]); await state.actions.remove(state.env.recipients[0]);
      state.env.showForm = true; state.env.fName = 'New'; state.env.fEmail = 'new@example.test'; await state.actions.submitForm();
      await state.actions.changeDocLocale({ currentTarget: { value: 'sv' } }); expect(state.calls).toEqual([]);
    }
  }
});
test('CRM review-required Send response requests fresh review without adopting status or exposing returned links', async () => {
  const state = fixture(); state.env.lawfulBasis = 'contract'; let requested = 0;
  state.env.onCRMReviewRequired = () => requested++;
  const pending = state.actions.send();
  const refusal = new state.env.SendError('CRM values changed; update and review the document before sending'); refusal.status = 409;
  state.calls[0].reject(refusal); await pending;
  expect(requested).toBe(1); expect(state.env.links).toBeNull(); expect(state.env.lawfulBasis).toBe('contract');
  expect(state.calls).toHaveLength(1); expect(state.env.sendErr).toBe(refusal);
});
test('recipient baseline ignores untouched forms but detects changes, cancellation and replacement retain a denied draft', () => {
  const state = fixture(); state.actions.openAdd();
  expect(state.actions.hasMeaningfulDraft()).toBe(false);
  state.env.fName = 'Unsent name';
  expect(state.actions.hasMeaningfulDraft()).toBe(true);
  state.actions.closeForm(); state.actions.openEdit(state.env.recipients[0]);
  expect(state.env.showForm).toBe(true); expect(state.env.fName).toBe('Unsent name'); expect(state.prompts).toHaveLength(2);
  state.env.confirmed = true; state.actions.closeForm(); expect(state.actions.hasMeaningfulDraft()).toBe(false);
  state.actions.openEdit(state.env.recipients[0]); expect(state.actions.hasMeaningfulDraft()).toBe(false);
  state.env.fLocale = 'sv'; expect(state.actions.hasMeaningfulDraft()).toBe(true);
});
test('basis and unconfirmed default language are meaningful drafts without fabricated acknowledgement', () => {
  const state = fixture(); state.env.lawfulBasis = 'contract'; expect(state.actions.hasMeaningfulDraft()).toBe(true);
  state.env.lawfulBasis = ''; state.env.docLocale = 'sv'; expect(state.actions.hasMeaningfulDraft()).toBe(true);
  expect(state.calls).toHaveLength(0);
});
test('old ordered or disposed recipient reads cannot replace current rows or errors', async () => {
  for (const mode of ['route', 'disposed', 'ordered']) {
    const state = fixture(); const old = state.actions.refresh();
    if (mode === 'route') move(state);
    else if (mode === 'disposed') state.env.disposed = true;
    else { const next = state.actions.refresh(); state.calls[1].resolve([{ id: 'fresh', document_id: 'A' }]); await next; }
    const expected = state.env.recipients;
    state.calls[0].resolve([{ id: 'old', document_id: 'A' }]); await old;
    expect(state.env.recipients).toEqual(expected);
    if (mode === 'route') { expect(state.env.error).toBe('Current B error'); expect(state.env.loading).toBe(true); }
  }
});
test('foreign recipient list and failed refresh preserve existing rows with a separate visible error', async () => {
  const state = fixture(); const pending = state.actions.refresh(); state.calls[0].resolve([{ id: 'foreign', document_id: 'B' }]); await pending;
  expect(state.env.recipients[0].id).toBe('original'); expect(state.env.recipientRefreshError).toContain('different document');
  state.env.error = 'Current form error'; const failed = state.actions.refresh(); state.calls[1].reject(new Error('Unavailable')); await failed;
  expect(state.env.recipients[0].id).toBe('original'); expect(state.env.error).toBe('Current form error'); expect(state.env.recipientRefreshError).toBe('Unavailable');
});
test('recipient submit serializes and preserves newer typed input as edits to the acknowledged new recipient', async () => {
  const state = fixture(); state.actions.openAdd(); state.env.fName = 'Submitted'; state.env.fEmail = 'submit@example.test';
  const pending = state.actions.submitForm(); await state.actions.submitForm(); expect(state.calls).toHaveLength(1);
  expect(state.calls[0].args[0]).toBe('A'); state.env.fName = 'Newer name';
  state.calls[0].resolve({ id: 'created', document_id: 'A' });
  await Promise.resolve(); await Promise.resolve();
  state.calls[1].resolve([]); await pending;
  expect(state.recipientChanges).toEqual(['A']);
  expect(state.env.showForm).toBe(true); expect(state.env.fName).toBe('Newer name'); expect(state.env.editingId).toBe('created');
  expect(state.actions.recipientDraftChanged()).toBe(true); expect(state.env.saving).toBe(false);
});
test('late recipient create success or failure cannot close another route form or reset its busy/error state', async () => {
  for (const failed of [false, true]) {
    const state = fixture(); state.actions.openAdd(); state.env.fName = 'Submitted'; state.env.fEmail = 'submit@example.test';
    const pending = state.actions.submitForm(); move(state); state.env.fName = 'B draft';
    if (failed) state.calls[0].reject(new Error('Old failure')); else state.calls[0].resolve({ id: 'created', document_id: 'A' });
    await pending; expect(state.env.fName).toBe('B draft'); expect(state.env.showForm).toBe(true); expect(state.env.saving).toBe(true); expect(state.env.error).toBe('Current B error');
    expect(state.calls).toHaveLength(1);
    expect(state.recipientChanges).toHaveLength(0);
  }
});
test('recipient removal signals committed current changes even when its list refresh fails', async () => {
  for (const outcome of ['committed', 'failed', 'stale']) {
    const state = fixture(); state.env.confirmed = true;
    const pending = state.actions.remove(state.env.recipients[0]);
    expect(state.calls[0].kind).toBe('delete');
    if (outcome === 'stale') move(state);
    if (outcome === 'failed') state.calls[0].reject(new Error('Refused'));
    else state.calls[0].resolve(undefined);
    await Promise.resolve(); await Promise.resolve();
    if (outcome === 'committed') {
      expect(state.recipientChanges).toEqual(['A']);
      expect(state.calls[1].kind).toBe('list');
      state.calls[1].reject(new Error('Refresh unavailable'));
    }
    await pending;
    if (outcome === 'committed') expect(state.env.recipientRefreshError).toBe('Refresh unavailable');
    else expect(state.recipientChanges).toHaveLength(0);
  }
});
test('failed language persistence restores last confirmed locale and late completion is fenced', async () => {
  const state = fixture(); state.env.onDefaultLocaleChange = async () => {};
  await state.actions.changeDocLocale({ currentTarget: { value: 'sv' } });
  expect(state.env.docLocale).toBe('en'); expect(state.env.error).toContain('not confirmed'); expect(state.env.savingLocale).toBe(false);
  state.env.onDefaultLocaleChange = (...args: any[]) => new Promise((resolve) => state.calls.push({ args, resolve }));
  const pending = state.actions.changeDocLocale({ currentTarget: { value: 'sv' } }); move(state); state.env.savingLocale = true; state.env.docLocale = 'de';
  state.calls[0].resolve(); await pending; expect(state.env.docLocale).toBe('de'); expect(state.env.savingLocale).toBe(true);
});
test('late send, reminder and void completions cannot borrow next document callbacks, links or error state', async () => {
  for (const name of ['send', 'remind', 'voidDoc']) {
    const state = fixture(); state.env.lawfulBasis = 'contract'; if (name !== 'send') { state.env.editable = false; state.env.isLive = true; }
    const pending = state.actions[name](); expect(state.calls[0].args[0]).toBe('A'); move(state);
    state.calls[0].resolve({ links: [{ url: 'old-link' }], status: 'sent', reminded: 1 }); await pending;
    expect(state.calls).toHaveLength(1); expect(state.env.links).toBeNull(); expect(state.env.busy).toBe('send'); expect(state.env.error).toBe('Current B error');
  }
});
test('send refuses unsaved recipient edits and all stale URL actions refuse dispatch', async () => {
  const state = fixture(); state.actions.openAdd(); state.env.fName = 'Unsent'; state.env.lawfulBasis = 'contract'; await state.actions.send();
  expect(state.calls).toHaveLength(0); expect(state.env.error).toContain('Save or cancel');
  state.env.$page.params.id = 'B'; await state.actions.submitForm(); await state.actions.send(); await state.actions.refresh();
  expect(state.calls).toHaveLength(0);
});

test('an unreviewed HTML PDF cannot dispatch Send even with complete recipients and lawful basis', async () => {
  const state = fixture();
  state.env.lawfulBasis = 'contract'; state.env.reviewRequired = true;
  await state.actions.send();
  expect(state.calls).toEqual([]);
  expect(state.env.busy).toBeNull();
});
