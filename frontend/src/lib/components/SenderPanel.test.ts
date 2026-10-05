import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { sameRecipientDraft } from './senderDraft';

const source = readFileSync(new URL('./SenderPanel.svelte', import.meta.url), 'utf8');
const names = ['captureScope', 'isCurrent', 'currentForm', 'recipientDraftChanged', 'hasMeaningfulDraft', 'confirmFormReplacement',
  'changeDocLocale', 'refresh', 'initializePanel', 'openAdd', 'openEdit', 'closeForm', 'submitForm', 'remove', 'send', 'remind', 'voidDoc', 'copyLink'];
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
    requiresSignature: true, signerRoles: [], missingRoles: [], hasParticipant: true,
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
  return { env, calls, prompts, recipientChanges, actions: bind(env) };
}
function move(state: ReturnType<typeof fixture>) {
  state.env.documentID = 'B'; state.env.boundDocumentID = 'B'; state.env.$page.params.id = 'B'; state.env.panelRevision++;
  state.env.error = 'Current B error'; state.env.recipientRefreshError = 'Current B refresh';
  state.env.recipients = [{ id: 'B', document_id: 'B' }]; state.env.loading = true; state.env.saving = true; state.env.busy = 'send';
}
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
