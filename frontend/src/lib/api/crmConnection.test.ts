import { expect, test } from 'bun:test';
import { configureCRMConnection, enableCRMConnection, getCRMConnection, revokeCRMConnection } from './crmConnection';
import { APIError } from './client';
const expectedActor = { expected_org_id: '22222222-2222-4222-8222-222222222222', expected_user_id: '11111111-1111-4111-8111-111111111111' };
const descriptor = { org_id: expectedActor.expected_org_id, user_id: expectedActor.expected_user_id, available: true, configured: true, requires_reconfiguration: false, origin: 'https://crm.example.test', connection: {
  id: '33333333-3333-4333-8333-333333333333', generation: '9007199254740993', status: 'candidate',
  crm_team_id: 'team_CUID2', crm_user_id: 'user_CUID2', verified_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:00:00Z',
} };
async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: () => Response) {
  const original = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options?: RequestInit) => { calls.push({ path: String(path), options: options ?? {} }); return respond(); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}
test('connection transport uses exact owner-session routes, decimal strings and captured abort signals', async () => {
  await mocked(async (calls) => {
    const signal = new AbortController().signal;
    await getCRMConnection(signal);
    await configureCRMConnection({ ...expectedActor, expected_generation: '0', token: 'a'.repeat(64) }, signal);
    await enableCRMConnection({ ...expectedActor, expected_generation: '9007199254740993', crm_team_id: 'team_CUID2', crm_user_id: 'user_CUID2' }, signal);
    await revokeCRMConnection({ ...expectedActor, expected_generation: '9007199254740993' }, signal);
    expect(calls.map((call) => [call.path, call.options.method])).toEqual([
      ['/api/v1/settings/crm/connection', 'GET'], ['/api/v1/settings/crm/connection', 'PUT'],
      ['/api/v1/settings/crm/connection/enable', 'POST'], ['/api/v1/settings/crm/connection', 'DELETE'],
    ]);
    for (const call of calls) expect(call.options).toMatchObject({ credentials: 'include', cache: 'no-store', signal });
    expect(JSON.parse(calls[1].options.body as string)).toEqual({ ...expectedActor, expected_generation: '0', token: 'a'.repeat(64) });
    expect(JSON.parse(calls[2].options.body as string)).toEqual({ ...expectedActor, expected_generation: '9007199254740993', crm_team_id: 'team_CUID2', crm_user_id: 'user_CUID2' });
    expect(JSON.parse(calls[3].options.body as string)).toEqual({ ...expectedActor, expected_generation: '9007199254740993' });
    expect(calls.every((call) => !call.path.includes('a'.repeat(64)))).toBe(true);
  }, () => Response.json(descriptor));
});
test('connection transport refuses unbounded/non-JSON/malformed or secret-bearing response data', async () => {
  for (const response of [
    () => new Response('login', { headers: { 'Content-Type': 'text/html' } }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '16385' } }),
    () => Response.json({ ...descriptor, token: 'a'.repeat(64) }),
    () => Response.json({ ...descriptor, connection: { ...descriptor.connection, generation: 2 } }),
    () => new Response('{broken', { headers: { 'Content-Type': 'application/json' } }),
  ]) await mocked(async () => { await expect(getCRMConnection(new AbortController().signal)).rejects.toThrow(); }, response);
  let cancelled = false;
  await mocked(async () => {
    await expect(getCRMConnection(new AbortController().signal)).rejects.toThrow(); expect(cancelled).toBe(true);
  }, () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(16385)); }, cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } }));
});
test('error bodies never surface provider secrets, and invalid IDs/generations/keys never dispatch', async () => {
  await mocked(async (calls) => {
    try { await getCRMConnection(new AbortController().signal); throw new Error('accepted'); }
    catch (error) { expect(error).toBeInstanceOf(APIError); expect((error as APIError).status).toBe(503); expect((error as Error).message).not.toContain('a'.repeat(64)); }
    const before = calls.length, signal = new AbortController().signal;
    await expect(configureCRMConnection({ ...expectedActor, expected_generation: '01', token: 'a'.repeat(64) }, signal)).rejects.toThrow();
    await expect(configureCRMConnection({ ...expectedActor, expected_generation: '0', token: 'A'.repeat(64) }, signal)).rejects.toThrow();
    await expect(enableCRMConnection({ ...expectedActor, expected_generation: '2', crm_team_id: 'team ', crm_user_id: 'user' }, signal)).rejects.toThrow();
    await expect(revokeCRMConnection({ ...expectedActor, expected_generation: '0' }, signal)).rejects.toThrow();
    await expect(configureCRMConnection({ ...expectedActor, expected_org_id: 'opaque-crm-team', expected_generation: '0', token: 'a'.repeat(64) }, signal)).rejects.toThrow();
    expect(calls).toHaveLength(before);
  }, () => Response.json({ error: `token=${'a'.repeat(64)}` }, { status: 503 }));
});
