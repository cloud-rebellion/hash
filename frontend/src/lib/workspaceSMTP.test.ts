import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { createWorkspaceSMTPController, smtpDraftProblems, type WorkspaceSMTP, type WorkspaceSMTPPorts, type SMTPSaveInput, type SMTPTestReceipt } from './workspaceSMTP';

const inactive = (mode: WorkspaceSMTP['mode'] = 'unconfigured'): WorkspaceSMTP => ({ schema_version: 1, revision: mode === 'disabled' ? 2 : 0, mode, configured: false, host: '', port: 0, tls_mode: '', sender_name: '', sender_email: '', username_set: false, password_set: false, updated_at: null });
const configured = (revision = 1): WorkspaceSMTP => ({ ...inactive(), revision, mode: 'configured', configured: true, host: 'smtp.example.test', port: 587, tls_mode: 'starttls', sender_name: 'Workspace', sender_email: 'sender@example.test', username_set: true, password_set: true });
const receipt = (status: SMTPTestReceipt['status'] = 'pending'): SMTPTestReceipt => ({ delivery_id: '11111111-1111-4111-8111-111111111111', status, smtp_accepted: status === 'sent', inbox_delivery_confirmed: false });
const failure = (status: number) => Object.assign(new Error('private provider detail must not escape'), { status });
function fixture(overrides: Partial<WorkspaceSMTPPorts> = {}, options = {}) {
  const calls: { saves: SMTPSaveInput[]; tests: number[]; statuses: string[]; disables: number[] } = { saves: [], tests: [], statuses: [], disables: [] };
  const ports: WorkspaceSMTPPorts = { load: async () => configured(), save: async input => { calls.saves.push(input); return { ...configured(input.expected_revision + 1), host: input.host, port: input.port, tls_mode: input.tls_mode, sender_name: input.sender_name, sender_email: input.sender_email, username_set: input.credentials_action === 'keep' || !!input.username, password_set: input.credentials_action === 'keep' || !!input.password }; }, disable: async revision => { calls.disables.push(revision); return { ...inactive('disabled'), revision: revision + 1 }; }, test: async revision => { calls.tests.push(revision); return receipt(); }, status: async id => { calls.statuses.push(id); return receipt('sent'); }, ...overrides };
  const controller = createWorkspaceSMTPController(ports, { pollIntervalMs: 1, pollAttempts: 3, pollWindowMs: 30, ...options });
  return { controller, calls };
}
const flush = () => new Promise(resolve => setTimeout(resolve, 5));
function newServer(controller: ReturnType<typeof createWorkspaceSMTPController>) { controller.edit('host', 'smtp.example.test'); controller.edit('connection', 'starttls'); controller.edit('sender_name', 'Workspace'); controller.edit('sender_email', 'sender@example.test'); }

test('new, legacy and disabled workspaces have no selected server or authentication defaults', async () => {
  for (const mode of ['unconfigured', 'installation_legacy', 'disabled'] as const) {
    const { controller, calls } = fixture({ load: async () => inactive(mode) }); await controller.load();
    expect(get(controller).draft.connection).toBe(''); expect(get(controller).authentication).toBe('');
    expect(await controller.save()).toBe(false); expect(await controller.test()).toBe(false); expect(calls.saves).toEqual([]); controller.dispose();
  }
});
test('same-server keep sends only public fields and preserves endpoint normalization', async () => {
  const { controller, calls } = fixture(); await controller.load(); controller.edit('host', ' SMTP.EXAMPLE.TEST '); controller.edit('sender_name', 'New name');
  expect(await controller.save()).toBe(true); expect(calls.saves).toHaveLength(1);
  expect(calls.saves[0]).toEqual({ expected_revision: 1, host: 'smtp.example.test', port: 587, tls_mode: 'starttls', sender_name: 'New name', sender_email: 'sender@example.test', credentials_action: 'keep' });
  expect(get(controller).metadata?.revision).toBe(2); expect(get(controller).notice).toContain('not been tested'); controller.dispose();
});
test('changing endpoint clears private entries and requires explicit new authentication', async () => {
  const { controller, calls } = fixture(); await controller.load(); controller.authenticate('replace'); controller.credential('username', 'SYNTHETIC-USERNAME'); controller.credential('password', 'SYNTHETIC-PASSWORD');
  expect(JSON.stringify(get(controller))).not.toContain('SYNTHETIC'); const epoch = get(controller).credentialEpoch;
  controller.edit('host', 'other.example.test'); expect(get(controller).usernameEntered).toBe(false); expect(get(controller).credentialEpoch).toBeGreaterThan(epoch);
  expect(await controller.save()).toBe(false); expect(calls.saves).toHaveLength(0);
  controller.authenticate('keep'); expect(controller.problems().authentication).toContain('server changed');
  controller.authenticate('replace'); controller.credential('username', 'new-user'); controller.credential('password', 'new-password');
  expect(await controller.save()).toBe(true); expect(calls.saves[0]).toMatchObject({ credentials_action: 'replace', username: 'new-user', password: 'new-password' }); expect(get(controller).usernameEntered).toBe(false); controller.dispose();
});
test('unauthenticated relay requires explicit choice and transmits an exact blank pair', async () => {
  const { controller, calls } = fixture({ load: async () => inactive() }); await controller.load(); newServer(controller);
  expect(await controller.save()).toBe(false); controller.authenticate('relay'); expect(await controller.save()).toBe(true);
  expect(calls.saves[0]).toMatchObject({ credentials_action: 'replace', username: '', password: '' }); expect(get(controller).metadata?.username_set).toBe(false); controller.dispose();
});
test('required fields, byte limits, controls and incomplete credential pairs refuse without a request', async () => {
  const { controller, calls } = fixture({ load: async () => inactive() }); await controller.load(); newServer(controller); controller.authenticate('replace'); controller.credential('username', 'user');
  expect(await controller.save()).toBe(false); expect(controller.problems().password).toBeDefined();
  controller.credential('password', 'x\n'); expect(await controller.save()).toBe(false);
  const draft = get(controller).draft; expect(smtpDraftProblems({ ...draft, sender_name: 'å'.repeat(101) }, 'relay', null).sender_name).toBeDefined();
  expect(smtpDraftProblems({ ...draft, host: 'https://smtp.example.test:587' }, 'relay', null).host).toBeDefined();
  expect(calls.saves).toEqual([]); controller.dispose();
});
test('cancel wipes credentials, restores metadata and does not submit', async () => {
  const { controller, calls } = fixture(); await controller.load(); controller.authenticate('replace'); controller.credential('password', 'private'); controller.edit('sender_name', 'Draft');
  controller.cancel(); expect(get(controller).dirty).toBe(false); expect(get(controller).passwordEntered).toBe(false); expect(get(controller).draft.sender_name).toBe('Workspace'); expect(calls.saves).toEqual([]); controller.dispose();
});
test('CAS conflict retains public draft and fences writes until an explicit reload', async () => {
  const { controller, calls } = fixture({ save: async () => { throw failure(409); }, load: async () => configured(7) }); await controller.load(); controller.edit('sender_name', 'Draft'); expect(await controller.save()).toBe(false);
  expect(get(controller).conflict).toBe(true); expect(get(controller).draft.sender_name).toBe('Draft'); expect(await controller.load()).toBe(false); expect(await controller.save()).toBe(false); expect(await controller.load(true)).toBe(true); expect(get(controller).conflict).toBe(false); expect(calls.tests).toEqual([]); controller.dispose();
});
test('unbound save response or timeout is uncertain and never retried automatically', async () => {
  for (const save of [async () => configured(99), async () => new Promise<WorkspaceSMTP>(() => {})]) {
    let saves = 0; const { controller } = fixture({ save: async (...args) => { saves++; return save(); } }, { requestTimeoutMs: 5 }); await controller.load(); controller.edit('sender_name', 'Changed');
    expect(await controller.save()).toBe(false); expect(get(controller).outcomeUnknown).toBe(true); expect(await controller.save()).toBe(false); expect(saves).toBe(1); controller.dispose();
  }
});
test('busy and disposed requests cannot double-submit or publish a late response', async () => {
  let complete!: (value: WorkspaceSMTP) => void; let signal!: AbortSignal; let saves = 0;
  const { controller } = fixture({ save: async (_, received) => { saves++; signal = received; return new Promise(resolve => complete = resolve); } }); await controller.load(); controller.edit('sender_name', 'Draft'); const first = controller.save();
  expect(await controller.save()).toBe(false); controller.dispose(); expect(signal.aborted).toBe(true); complete({ ...configured(2), sender_name: 'Draft' }); expect(await first).toBe(false); expect(saves).toBe(1); expect(get(controller).metadata?.revision).toBe(1);
});
test('owner denial hides authorization and does not expose provider error text', async () => {
  const { controller } = fixture({ load: async () => { throw failure(403); } }); expect(await controller.load()).toBe(false); expect(get(controller).authorized).toBe(false); expect(get(controller).error).toContain('owners'); expect(get(controller).error).not.toContain('provider'); expect(await controller.test()).toBe(false); controller.dispose();
});
test('disable needs a separate explicit confirmation and produces no fallback', async () => {
  const { controller, calls } = fixture(); await controller.load(); expect(await controller.disable()).toBe(false); controller.requestDisable(); controller.cancelDisable(); expect(await controller.disable()).toBe(false); controller.requestDisable(); expect(await controller.disable()).toBe(true); expect(calls.disables).toEqual([1]); expect(get(controller).metadata?.mode).toBe('disabled'); expect(await controller.test()).toBe(false); controller.dispose();
});
test('202 is only queued; GET-only monitoring reaches SMTP acceptance without an inbox claim', async () => {
  let status = 0; const { controller, calls } = fixture({ status: async () => { status++; return receipt(status === 1 ? 'retrying' : 'sent'); } }); await controller.load(); expect(await controller.test()).toBe(true);
  expect(get(controller).testReceipt?.smtp_accepted).toBe(false); expect(await controller.test()).toBe(false); await flush(); expect(get(controller).testReceipt?.status).toBe('sent'); expect(get(controller).testReceipt?.smtp_accepted).toBe(true); expect(get(controller).testReceipt?.inbox_delivery_confirmed).toBe(false); expect(calls.tests).toEqual([1]); expect(status).toBe(2); controller.dispose();
});
test('test timeout is not a no-send result and reload does not permit automatic resubmission', async () => {
  let tests = 0; const { controller } = fixture({ test: async () => { tests++; return new Promise(() => {}); } }, { requestTimeoutMs: 5 }); await controller.load(); expect(await controller.test()).toBe(false); expect(get(controller).testUnknown).toBe(true); expect(await controller.load(true)).toBe(true); expect(await controller.test()).toBe(false); expect(tests).toBe(1); controller.dispose();
});
test('monitoring is finite, ignores another receipt and stops on disposal', async () => {
  let reads = 0; const { controller } = fixture({ status: async () => { reads++; return receipt(); } }, { pollAttempts: 2 }); await controller.load(); await controller.test(); await new Promise(resolve => setTimeout(resolve, 8)); expect(reads).toBe(2); expect(get(controller).polling).toBe(false); expect(get(controller).testError).toContain('paused'); expect(await controller.test()).toBe(false); controller.dispose();
  const wrong = fixture({ status: async () => ({ ...receipt('sent'), delivery_id: '22222222-2222-4222-8222-222222222222' }) }); await wrong.controller.load(); await wrong.controller.test(); await flush(); expect(get(wrong.controller).testReceipt?.status).toBe('pending'); expect(get(wrong.controller).testError).toContain('not be confirmed'); wrong.controller.dispose();
});
