import { expect, test } from 'bun:test';
import { CRMConnectionController, checkedCRMConnection, crmConnectionCapacity, crmConnectionPin, crmGeneration, crmOpaqueID, crmToken, type CRMConnectionResponse, type CRMConnectionTransport } from './crmConnection';

const owner = { user_id: '11111111-1111-4111-8111-111111111111', org_id: '22222222-2222-4222-8222-222222222222', role: 'owner' };
const id = '33333333-3333-4333-8333-333333333333';
function response(status: 'candidate' | 'active' | 'revoked' | null, generation = '1'): CRMConnectionResponse {
  return { org_id: owner.org_id, user_id: owner.user_id, available: true, configured: status !== null, requires_reconfiguration: false, origin: 'https://crm.example.test', connection: status === null ? null : {
    id, generation, status, crm_team_id: 'team_CASE-opaque', crm_user_id: 'user_CUID2',
    verified_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:00:00.123456789Z',
  } };
}
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture(initial = response(null)) {
  const calls: { kind: string; input?: unknown; signal: AbortSignal }[] = [];
  let actor = { ...owner }, saved = initial;
  const transport: CRMConnectionTransport = {
    identity: async (signal) => { calls.push({ kind: 'identity', signal }); return actor; },
    read: async (signal) => { calls.push({ kind: 'read', signal }); return saved; },
    configure: async (input, signal) => { calls.push({ kind: 'configure', input, signal }); saved = response('candidate', String(BigInt(input.expected_generation) + 1n)); return saved; },
    enable: async (input, signal) => { calls.push({ kind: 'enable', input, signal }); saved = response('active', String(BigInt(input.expected_generation) + 1n)); return saved; },
    revoke: async (input, signal) => { calls.push({ kind: 'revoke', input, signal }); saved = response('revoked', String(BigInt(input.expected_generation) + 1n)); return saved; },
  };
  const controller = new CRMConnectionController(transport, () => {});
  return { calls, transport, controller, setActor: (next: typeof actor) => { actor = next; }, setSaved: (next: CRMConnectionResponse) => { saved = next; } };
}
test('CRM IDs remain exact opaque strings and generations preserve signed-int64 precision', () => {
  for (const value of ['cuid2team', 'TEAM_case-2', 'a'.repeat(256)]) expect(crmOpaqueID(value)).toBe(true);
  for (const value of ['', ' team', 'team ', 't/eam', 'a'.repeat(257), 'é']) expect(crmOpaqueID(value)).toBe(false);
  for (const value of ['1', '9007199254740993', '9223372036854775807']) expect(crmGeneration(value)).toBe(true);
  for (const value of ['0', '01', '1.0', '+1', '9223372036854775808', 1]) expect(crmGeneration(value)).toBe(false);
  expect(crmGeneration('0', true)).toBe(true);
  expect(crmToken('a'.repeat(64))).toBe(true);
  expect(crmToken('A'.repeat(64))).toBe(false);
  expect(crmToken(` ${'a'.repeat(64)}`)).toBe(false);
});
test('typed descriptor rejects secrets, missing/invalid identity, unsafe origin and numeric generation', () => {
  const valid = response('candidate', '9007199254740993');
  expect(checkedCRMConnection(valid)).toEqual(valid);
  const invalid = [
    { ...valid, token: 'a'.repeat(64) }, { ...valid, connection: null }, { ...valid, configured: false },
    { ...valid, origin: 'https://user:secret@crm.example.test' }, { ...valid, origin: 'https://crm.example.test/path' },
    { ...valid, connection: { ...valid.connection, generation: 9007199254740993 } },
    { ...valid, connection: { ...valid.connection, crm_team_id: ' team' } },
    { ...valid, connection: { ...valid.connection, verified_at: null } },
    { ...valid, connection: { ...valid.connection, generation: '9223372036854775807' } },
    { ...valid, connection: { ...valid.connection, ciphertext: 'hidden' } },
    { ...valid, org_id: '' }, { ...valid, user_id: 'cuid2-not-a-Hash-user' },
  ];
  for (const value of invalid) expect(() => checkedCRMConnection(value)).toThrow();
  const revoked = response('revoked'); revoked.available = false; revoked.origin = '';
  expect(checkedCRMConnection(revoked).connection?.crm_team_id).toBe('team_CASE-opaque');
});
test('saved key stays disabled until the exact returned account is explicitly confirmed', async () => {
  const f = fixture(); await f.controller.refresh();
  await f.controller.configure('a'.repeat(64));
  expect(f.controller.state.response?.connection?.status).toBe('candidate');
  expect(f.calls.filter((call) => call.kind === 'enable')).toHaveLength(0);
  await f.controller.enable(); expect(f.calls.filter((call) => call.kind === 'enable')).toHaveLength(0);
  const pin = crmConnectionPin(f.controller.state.response);
  f.controller.confirmAccount(`${pin}changed`, true); await f.controller.enable();
  expect(f.calls.filter((call) => call.kind === 'enable')).toHaveLength(0);
  f.controller.confirmAccount(pin, true); await f.controller.enable();
  expect(f.calls.find((call) => call.kind === 'enable')?.input).toEqual({ expected_org_id: owner.org_id, expected_user_id: owner.user_id,
    expected_generation: '1', crm_team_id: 'team_CASE-opaque', crm_user_id: 'user_CUID2' });
  expect(f.controller.state.response?.connection?.status).toBe('active');
  expect(f.controller.state.confirmation).toBe('');
});
test('rotation disables the prior account and confirmation is invalidated by a refresh', async () => {
  const f = fixture(response('active', '9007199254740993')); await f.controller.refresh();
  await f.controller.configure('b'.repeat(64));
  expect(f.controller.state.response?.connection?.generation).toBe('9007199254740994');
  expect(f.controller.state.response?.connection?.status).toBe('candidate');
  f.controller.confirmAccount(crmConnectionPin(f.controller.state.response), true);
  await f.controller.refresh(); await f.controller.enable();
  expect(f.calls.filter((call) => call.kind === 'enable')).toHaveLength(0);
});
test('revocation works while provider unavailable, and retains account context without reenabling', async () => {
  const initial = response('active'); initial.available = false;
  const f = fixture(initial); await f.controller.refresh();
  await f.controller.configure('a'.repeat(64)); expect(f.calls.filter((call) => call.kind === 'configure')).toHaveLength(0);
  await f.controller.revoke(crmConnectionPin(f.controller.state.response));
  expect(f.controller.state.response?.connection?.status).toBe('revoked');
  expect(f.controller.state.response?.connection?.crm_user_id).toBe(initial.connection?.crm_user_id);
  expect(f.calls.filter((call) => call.kind === 'revoke')).toHaveLength(1);
});
test('revision limits reserve enable/revoke and terminal counters cannot dispatch another enrollment', async () => {
  expect(crmConnectionCapacity(response('active', '9223372036854775804')).configure).toBe(true);
  const f = fixture(response('candidate', '9223372036854775805')); await f.controller.refresh();
  expect(crmConnectionCapacity(f.controller.state.response)).toEqual({ configure: false, enable: true, revoke: true });
  await f.controller.configure('a'.repeat(64)); expect(f.calls.filter((call) => call.kind === 'configure')).toHaveLength(0);
  f.controller.confirmAccount(crmConnectionPin(f.controller.state.response), true); await f.controller.enable();
  expect(f.controller.state.response?.connection?.generation).toBe('9223372036854775806');
  expect(crmConnectionCapacity(f.controller.state.response)).toEqual({ configure: false, enable: false, revoke: true });
  await f.controller.revoke(crmConnectionPin(f.controller.state.response));
  expect(f.controller.state.response?.connection?.generation).toBe('9223372036854775807');
  expect(crmConnectionCapacity(f.controller.state.response)).toEqual({ configure: false, enable: false, revoke: false });
  await f.controller.configure('b'.repeat(64)); expect(f.calls.filter((call) => call.kind === 'configure')).toHaveLength(0);
  const terminalCandidate = fixture(response('candidate', '9223372036854775806')); await terminalCandidate.controller.refresh();
  terminalCandidate.controller.confirmAccount(crmConnectionPin(terminalCandidate.controller.state.response), true);
  await terminalCandidate.controller.enable(); expect(terminalCandidate.calls.filter((call) => call.kind === 'enable')).toHaveLength(0);
  await terminalCandidate.controller.revoke(crmConnectionPin(terminalCandidate.controller.state.response));
  expect(terminalCandidate.controller.state.response?.connection?.status).toBe('revoked');
});
test('changed operator origin blocks enabling the retained account while permitting replacement or revocation', async () => {
  const stale = response('candidate'); stale.requires_reconfiguration = true;
  const f = fixture(stale); await f.controller.refresh();
  expect(crmConnectionCapacity(f.controller.state.response)).toEqual({ configure: true, enable: false, revoke: true });
  f.controller.confirmAccount(crmConnectionPin(f.controller.state.response), true); await f.controller.enable();
  expect(f.calls.filter((call) => call.kind === 'enable')).toHaveLength(0);
  await f.controller.configure('a'.repeat(64));
  expect(f.controller.state.response?.requires_reconfiguration).toBe(false);
  expect(f.controller.state.response?.connection?.status).toBe('candidate');
  const revoked = fixture(stale); await revoked.controller.refresh(); await revoked.controller.revoke(crmConnectionPin(revoked.controller.state.response));
  expect(revoked.controller.state.response?.connection?.status).toBe('revoked');
});
test('owner role/user/org changes during external work cannot adopt a connection or dispatch another change', async () => {
  for (const changed of [{ ...owner, role: 'sender' }, { ...owner, user_id: '44444444-4444-4444-8444-444444444444' }, { ...owner, org_id: '55555555-5555-4555-8555-555555555555' }]) {
    const f = fixture(); await f.controller.refresh(); const waiting = deferred<unknown>();
    f.transport.configure = async (input, signal) => { f.calls.push({ kind: 'configure', input, signal }); return waiting.promise; };
    const pending = f.controller.configure('a'.repeat(64));
    await Promise.resolve(); await Promise.resolve();
    f.setActor(changed); waiting.resolve(response('candidate')); await pending;
    expect(f.controller.state.owner).toBeNull(); expect(f.controller.state.fresh).toBe(false);
    expect(f.controller.state.response?.connection).toBeNull();
    await f.controller.configure('b'.repeat(64)); expect(f.calls.filter((call) => call.kind === 'configure')).toHaveLength(1);
    await f.controller.refresh(); expect(f.controller.state.owner).toBeNull();
  }
});
test('A to B to A cookie switch cannot adopt another actor response even when both identity probes report A', async () => {
  const b = { ...owner, org_id: '55555555-5555-4555-8555-555555555555', user_id: '44444444-4444-4444-8444-444444444444' };
  const f = fixture(); const waiting = deferred<unknown>();
  f.transport.read = () => waiting.promise;
  const pending = f.controller.refresh(); await Promise.resolve(); await Promise.resolve();
  f.setActor(b); // Cookie B is used by the outstanding connection request.
  const other = { ...response('active'), org_id: b.org_id, user_id: b.user_id };
  f.setActor(owner); // Cookie A is restored before a final identity probe.
  waiting.resolve(other); await pending;
  expect(f.controller.state.owner).toBeNull(); expect(f.controller.state.response).toBeNull();
  expect(f.controller.state.fresh).toBe(false); expect(f.controller.state.needsReadback).toBe(true);
});
test('every mutation carries the original intended actor and rejects a switched response witness', async () => {
  const f = fixture(); await f.controller.refresh(); await f.controller.configure('a'.repeat(64));
  f.controller.confirmAccount(crmConnectionPin(f.controller.state.response), true); await f.controller.enable();
  await f.controller.revoke(crmConnectionPin(f.controller.state.response));
  for (const call of f.calls.filter((call) => ['configure', 'enable', 'revoke'].includes(call.kind))) {
    expect(call.input).toMatchObject({ expected_org_id: owner.org_id, expected_user_id: owner.user_id });
  }
  const switched = fixture(); await switched.controller.refresh(); const waiting = deferred<unknown>(); let intended: unknown;
  switched.transport.configure = async (input) => { intended = input; return waiting.promise; };
  const pending = switched.controller.configure('a'.repeat(64)); await Promise.resolve(); await Promise.resolve();
  expect(intended).toMatchObject({ expected_org_id: owner.org_id, expected_user_id: owner.user_id });
  waiting.resolve({ ...response('candidate'), org_id: '55555555-5555-4555-8555-555555555555', user_id: '44444444-4444-4444-8444-444444444444' });
  await pending;
  expect(switched.controller.state.fresh).toBe(false); expect(switched.controller.state.response?.connection).toBeNull();
  expect(switched.controller.state.needsReadback).toBe(true);
});
test('navigation aborts a captured request and late success cannot overwrite refreshed state', async () => {
  const f = fixture(); await f.controller.refresh(); const waiting = deferred<unknown>(); let captured!: AbortSignal;
  f.transport.configure = async (_input, signal) => { captured = signal; return waiting.promise; };
  const pending = f.controller.configure('a'.repeat(64)); await Promise.resolve(); await Promise.resolve();
  f.controller.interrupt(); expect(captured.aborted).toBe(true);
  f.setSaved(response('revoked', '8')); await f.controller.refresh();
  waiting.resolve(response('candidate')); await pending;
  expect(f.controller.state.response?.connection?.status).toBe('revoked');
  expect(f.controller.state.response?.connection?.generation).toBe('8');
  f.controller.dispose(); await f.controller.refresh();
  expect(f.controller.state.owner).toBeNull();
});
test('uncertain writes and malformed response pins require readback and never echo a key', async () => {
  for (const failure of [new Error(`provider echoed token ${'a'.repeat(64)}`), { status: 409 }, { status: 503 }]) {
    const f = fixture(); await f.controller.refresh();
    let attempts = 0; f.transport.configure = async () => { attempts++; throw failure; };
    await f.controller.configure('a'.repeat(64));
    expect(f.controller.state.needsReadback).toBe(true); expect(f.controller.state.error).not.toContain('a'.repeat(64));
    await f.controller.configure('b'.repeat(64)); expect(attempts).toBe(1);
    f.setSaved(response('candidate')); await f.controller.refresh();
    expect(f.controller.state.needsReadback).toBe(false);
  }
  for (const changed of [response('candidate', '1'), { ...response('candidate', '2'), origin: 'https://other.example.test' },
    { ...response('candidate', '2'), connection: { ...response('candidate', '2').connection!, id: '66666666-6666-4666-8666-666666666666' } }]) {
    const f = fixture(response('active')); await f.controller.refresh(); f.transport.configure = async () => changed;
    await f.controller.configure('a'.repeat(64)); expect(f.controller.state.needsReadback).toBe(true);
    expect(f.controller.state.response?.connection?.status).toBe('active');
  }
});
