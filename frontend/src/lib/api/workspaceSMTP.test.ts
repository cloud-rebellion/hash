import { afterEach, expect, test } from 'bun:test';
import { checkedWorkspaceSMTP, checkedSMTPTest, loadWorkspaceSMTP, saveWorkspaceSMTP, disableWorkspaceSMTP, startWorkspaceSMTPTest, readWorkspaceSMTPTest } from './workspaceSMTP';
const original = globalThis.fetch; afterEach(() => { globalThis.fetch = original; });
const saved = { schema_version: 1, revision: 1, mode: 'configured', configured: true, host: 'smtp.example.test', port: 587, tls_mode: 'starttls', sender_name: 'Workspace', sender_email: 'sender@example.test', username_set: true, password_set: true, updated_at: '2026-11-03T10:00:00Z' };
const inactive = { ...saved, revision: 0, mode: 'unconfigured', configured: false, host: '', port: 0, tls_mode: '', sender_name: '', sender_email: '', username_set: false, password_set: false, updated_at: null };
const receipt = { delivery_id: '11111111-1111-4111-8111-111111111111', status: 'pending', smtp_accepted: false, inbox_delivery_confirmed: false };
const signal = () => new AbortController().signal;
function response(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } }); }
function fake(value: unknown, status = 200) { const calls: { url: string; init: RequestInit }[] = []; globalThis.fetch = (async (url, init) => { calls.push({ url: String(url), init: init! }); return response(value, status); }) as typeof fetch; return calls; }
test('strict DTO accepts the four truthful modes and rejects secret or unknown fields', () => {
  expect(checkedWorkspaceSMTP(saved).configured).toBe(true); expect(checkedWorkspaceSMTP(inactive).mode).toBe('unconfigured'); expect(checkedWorkspaceSMTP({ ...inactive, mode: 'installation_legacy' }).mode).toBe('installation_legacy'); expect(checkedWorkspaceSMTP({ ...inactive, revision: 2, mode: 'disabled' }).revision).toBe(2);
  for (const value of [{ ...saved, password: 'never-read' }, { ...saved, username: '' }, { ...saved, ciphertext: '' }, { ...saved, mode: 'unconfigured' }, { ...saved, port: 25 }, { ...saved, tls_mode: 'none' }, { ...saved, password_set: false }, { ...saved, revision: 1.5 }, { ...saved, schema_version: 2 }, { ...saved, updated_at: 'nonsense' }, { ...inactive, host: 'not-empty' }]) expect(() => checkedWorkspaceSMTP(value)).toThrow();
});
test('GET uses a same-origin fixed URL, no-store and included session, without credential hydration', async () => {
  const calls = fake(saved); expect(await loadWorkspaceSMTP(signal())).toEqual(saved); expect(calls[0]).toMatchObject({ url: '/api/v1/workspace-smtp', init: { method: 'GET', credentials: 'include', cache: 'no-store', redirect: 'error' } }); expect(calls[0].init.body).toBeUndefined();
});
test('PUT keep omits credentials entirely; replace and explicit blank relay are closed exact bodies', async () => {
  const keep = { expected_revision: 1, host: saved.host, port: 587 as const, tls_mode: 'starttls' as const, sender_name: saved.sender_name, sender_email: saved.sender_email, credentials_action: 'keep' as const };
  const calls = fake(saved); await saveWorkspaceSMTP(keep, signal()); expect(JSON.parse(calls[0].init.body as string)).toEqual(keep); expect(calls[0].init.method).toBe('PUT'); expect(calls[0].init.redirect).toBe('error');
  for (const pair of [{ username: 'new-user', password: 'new-password' }, { username: '', password: '' }]) { await saveWorkspaceSMTP({ ...keep, credentials_action: 'replace', ...pair }, signal()); expect(JSON.parse(calls.at(-1)!.init.body as string)).toMatchObject(pair); }
  for (const value of [{ ...keep, password: null }, { ...keep, username: '' }, { ...keep, credentials_action: 'replace', username: 'only-user', password: '' }, { ...keep, credentials_action: 'replace', username: 'x'.repeat(257), password: 'x' }]) await expect(saveWorkspaceSMTP(value as any, signal())).rejects.toThrow();
  expect(calls).toHaveLength(3);
});
test('disable and fixed-owner test can send only expected revision, never recipient or content', async () => {
  let calls = fake({ ...inactive, mode: 'disabled', revision: 2 }); await disableWorkspaceSMTP(1, signal()); expect(calls[0].init.method).toBe('DELETE'); expect(JSON.parse(calls[0].init.body as string)).toEqual({ expected_revision: 1 });
  calls = fake(receipt, 202); expect((await startWorkspaceSMTPTest(1, signal())).smtp_accepted).toBe(false); expect(calls[0].url).toBe('/api/v1/workspace-smtp/test'); expect(JSON.parse(calls[0].init.body as string)).toEqual({ expected_revision: 1 });
  calls = fake(receipt); await readWorkspaceSMTPTest(receipt.delivery_id, signal()); expect(calls[0].url).toBe('/api/v1/workspace-smtp/test/' + receipt.delivery_id); expect(calls[0].init.method).toBe('GET');
});
test('receipt schema cannot turn a queued request into inbox or SMTP acceptance', () => {
  for (const bad of [{ ...receipt, smtp_accepted: true }, { ...receipt, inbox_delivery_confirmed: true }, { ...receipt, recipient: 'private' }, { ...receipt, last_error: 'raw' }, { ...receipt, status: 'delivered' }, { ...receipt, delivery_id: '../other' }, { ...receipt, delivery_id: '00000000-0000-0000-0000-000000000000' }]) expect(() => checkedSMTPTest(bad)).toThrow();
  expect(checkedSMTPTest({ ...receipt, status: 'sent', smtp_accepted: true }).inbox_delivery_confirmed).toBe(false); expect(() => checkedSMTPTest(receipt, '22222222-2222-4222-8222-222222222222')).toThrow();
});
test('wrong HTTP status, type, oversized bytes and malformed UTF8 refuse; provider error body is never read', async () => {
  fake(receipt, 200); await expect(startWorkspaceSMTPTest(1, signal())).rejects.toThrow();
  globalThis.fetch = (async () => new Response('private-provider-message', { status: 503 })) as typeof fetch;
  try { await loadWorkspaceSMTP(signal()); throw new Error('expected refusal'); } catch (error: any) { expect(error.status).toBe(503); expect(error.message).not.toContain('private-provider-message'); }
  for (const responseBody of [new Response('x', { headers: { 'content-type': 'text/plain' } }), new Response(' '.repeat(32769), { headers: { 'content-type': 'application/json' } }), new Response(new Uint8Array([255]), { headers: { 'content-type': 'application/json' } })]) { globalThis.fetch = (async () => responseBody) as typeof fetch; await expect(loadWorkspaceSMTP(signal())).rejects.toThrow(); }
});
test('status requests reject an unbound ID and a response for another owner test', async () => {
  const calls = fake(receipt); await expect(readWorkspaceSMTPTest('../secret', signal())).rejects.toThrow(); expect(calls).toHaveLength(0);
  await expect(readWorkspaceSMTPTest('22222222-2222-4222-8222-222222222222', signal())).rejects.toThrow();
});
