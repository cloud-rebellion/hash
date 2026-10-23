import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { checkedPackageSendObservation } from '../packageSend';
import { sameRecipientDraft } from './senderDraft';

const source = readFileSync(new URL('./SenderPanel.svelte', import.meta.url), 'utf8');
const names = ['captureScope', 'isCurrent', 'currentForm', 'recipientDraftChanged', 'hasMeaningfulDraft', 'confirmFormReplacement',
  'intendedPartyConflicts', 'refreshSourceRecipients', 'changeDocLocale', 'refresh', 'initializePanel', 'openAdd', 'openEdit', 'closeForm', 'submitForm', 'remove', 'send', 'adoptPackageReview', 'reconcilePackageSelection', 'acceptPackageStatus', 'reconcilePackageSend', 'remind', 'voidDoc', 'copyLink'];
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
    requiresSignature: true, reviewRequired: false, revisionBlocked: false, crmBlocked: false, crmBusy: false, attachmentsBlocked:false, attachmentsMessage:"", packageSend:undefined, packageReviewRequired:false,packageReviewRevision:0,packageReconciliationBusy:false,observedPackageReviewRevision:0,onPackageReviewRequired:(inspect:boolean)=>calls.push({kind:"package-review",args:[inspect]}),packageStatus:{stop:async()=>{},start:()=>{}},pendingPackageAttempt:null,packageUncertain:false,checkingPackage:false,externalMutationBusy:false, onDraftStateChange:undefined, onCRMReviewRequired: undefined, onMutationStateChange: undefined, generatedPlacementRequired: false, generatedPlacementReady: false, signerRoles: [], missingRoles: [], hasParticipant: true,
    intendedParties: [], recipientIdentityLocked: false, sourceCommitment: '', observedSourceCommitment: '',
    preSignMode: 'manual', preSignBusy: false, preSignRecoveryBlocked: false, preSignDraft: false,
    roleOptions: [{ value: 'signer' }, { value: 'approver' }],
    docLocale: 'en', confirmedDocLocale: 'en', defaultLocale: 'en', savingLocale: false,
    recipients: [{ id: 'original', document_id: 'A', name: 'Original', email: 'original@example.test', role: 'signer', locale: 'en', order_index: 0 }],
    loading: false, error: null, recipientRefreshError: null, sendErr: null, showForm: false,
    editingId: null, fName: '', fEmail: '', fRole: 'signer', fLocale: 'en', saving: false, formRevision: 0, formBaseline: null,
    removingID: null, busy: null, links: null, lawfulBasis: '', remindedFlash: null, copiedID: null,
    reminderTimer: null, copyTimer: null, sameRecipientDraft, checkedPackageSendObservation, tick: async () => {},
    onStatusChange: (next: string) => calls.push({ kind: 'status', args: [next] }),
    onRecipientsChange: () => recipientChanges.push(env.boundDocumentID),
    listRecipients: pending('list'), createRecipient: pending('create'), updateRecipient: pending('update'),
    deleteRecipient: pending('delete'), getDocument:pending('document'),inspectPackageSendAttempt:pending('inspect'),sendDocument: pending('send'), remindDocument: pending('remind'), voidDocument: pending('void'),
    navigator: { clipboard: { writeText: pending('clipboard') } },
    window: { confirm: (message: string) => { prompts.push(message); return env.confirmed; } },
    confirm: () => env.confirmed, prompt: () => 'Audit reason', confirmed: false, SendError: class extends Error {},
    setTimeout, clearTimeout
  };
  Object.defineProperty(env,'otherMutationBusy',{get:()=>env.crmBusy || env.externalMutationBusy || env.preSignBusy || env.preSignRecoveryBlocked});
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
test('pre-sign selection and unresolved original request never fall through to ordinary Send', async () => {
  for (const patch of [{ preSignMode: 'presign' }, { preSignRecoveryBlocked: true }, { preSignBusy: true }]) {
    const state = fixture(); bindContractParties(state); state.env.lawfulBasis = 'contract'; Object.assign(state.env, patch);
    await state.actions.send(); expect(state.calls).toEqual([]);
  }
  const state = fixture(); state.env.preSignDraft = true;
  expect(state.actions.hasMeaningfulDraft()).toBe(true);
});
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

test('attachment write barrier refuses recipient save and Send but still permits cancelling the local form',async()=>{const f=fixture();f.actions.openAdd();f.env.fName='Unsaved';f.env.fEmail='local@example.test';expect(f.actions.recipientDraftChanged()).toBe(true);f.env.externalMutationBusy=true;f.env.attachmentsBlocked=true;await f.actions.submitForm();await f.actions.send();expect(f.calls).toHaveLength(0);f.actions.closeForm();expect(f.env.showForm).toBe(true);f.env.confirmed=true;f.actions.closeForm();expect(f.env.showForm).toBe(false);expect(f.calls).toHaveLength(0);});


test('package Send captures the saved selection before props change and retains queued attempt',async()=>{const f=fixture();f.env.lawfulBasis='contract';const selected={expected_updated_at:'2026-10-19T12:03:04.123456Z',package_id:'4e972fb2-ae22-4c84-a52d-93d66507b080',generation:'7'};f.env.packageSend=selected;const pending=f.actions.send();expect(f.calls[0].args[2]).toEqual(selected);f.env.packageSend=undefined;f.calls[0].resolve({status:'sealing',links:[],package_send:{attempt_id:'3190d00e-c777-4a5b-9e90-63b95532a99c',outcome:'active',reconciliation_required:true}});await Promise.resolve();await Promise.resolve();const list=f.calls.find(c=>c.kind==='list');if(list)list.resolve(f.env.recipients);await pending;expect(f.env.pendingPackageAttempt).toBe('3190d00e-c777-4a5b-9e90-63b95532a99c');expect(f.calls.some(c=>c.kind==='status'&&c.args[0]==='sealing')).toBe(true);});
test('network loss on package Send blocks repeat and inspection uses only GET owners',async()=>{const f=fixture();f.env.lawfulBasis='contract';f.env.packageSend={expected_updated_at:'2026-10-19T12:03:04Z',package_id:'4e972fb2-ae22-4c84-a52d-93d66507b080',generation:'7'};const pending=f.actions.send();f.calls[0].reject(new Error('network loss'));await pending;expect(f.env.packageUncertain).toBe(true);await f.actions.send();expect(f.calls.filter(c=>c.kind==='send')).toHaveLength(1);const check=f.actions.reconcilePackageSend();await Promise.resolve();const request=f.calls.find(c=>c.kind==='document');request.resolve({id:'A',status:'sealing'});await Promise.resolve();await Promise.resolve();const list=f.calls.find(c=>c.kind==='list');if(list)list.resolve(f.env.recipients);await check;expect(f.calls.filter(c=>c.kind==='send')).toHaveLength(1);});

test('stale package409 blocks repeated Send until explicit inspected selection adoption',async()=>{
 const f=fixture();f.env.lawfulBasis='contract';f.env.packageSend={expected_updated_at:'2026-10-19T12:03:04Z',package_id:'4e972fb2-ae22-4c84-a52d-93d66507b080',generation:'7'};
 const rejected=f.actions.send();const failure=new f.env.SendError('Review and reconcile the exact document and saved attachment selection');failure.status=409;f.calls[0].reject(failure);await rejected;
 expect(f.env.packageReviewRequired).toBe(true);expect(f.calls.find(c=>c.kind==='package-review').args).toEqual([false]);
 await f.actions.send();expect(f.calls.filter(c=>c.kind==='send')).toHaveLength(1);
 f.env.externalMutationBusy=true; // the attachment's own dirty/readback barrier must not block inspection
 f.actions.reconcilePackageSelection();expect(f.calls.filter(c=>c.kind==='package-review').at(-1).args).toEqual([true]);
 f.env.externalMutationBusy=false;
 f.env.packageSend={...f.env.packageSend,generation:'8',expected_updated_at:'2026-10-19T12:03:05Z'};
 f.actions.adoptPackageReview(1);expect(f.env.packageReviewRequired).toBe(false);
 const sent=f.actions.send();const request=f.calls.filter(c=>c.kind==='send').at(-1);expect(request.args[2].generation).toBe('8');request.resolve({status:'sealing',links:[],package_send:{attempt_id:'3190d00e-c777-4a5b-9e90-63b95532a99c',outcome:'active',reconciliation_required:true}});
 await Promise.resolve();await Promise.resolve();f.calls.find(c=>c.kind==='list').resolve(f.env.recipients);await sent;
});
test('observed sent retires the queued attempt banner while refreshing actual recipients',async()=>{
 const f=fixture();f.env.pendingPackageAttempt='3190d00e-c777-4a5b-9e90-63b95532a99c';const scope=f.actions.captureScope();
 const applied=f.actions.acceptPackageStatus('sent',scope);expect(f.env.pendingPackageAttempt).toBe(null);expect(f.calls[0].args).toEqual(['sent']);f.calls.find(c=>c.kind==='list').resolve(f.env.recipients);await applied;
});
test('package reconciliation still refuses independent mutations and recipient drafts',()=>{
 for(const busy of ['packageReconciliationBusy','crmBusy','saving','savingLocale','removingID','checkingPackage','busy']){
  const f=fixture();f.env.packageReviewRequired=true;f.env.externalMutationBusy=true;f.env[busy]=busy==='removingID'?'recipient':busy==='busy'?'send':true;
  f.actions.reconcilePackageSelection();expect(f.calls).toEqual([]);
 }
});
