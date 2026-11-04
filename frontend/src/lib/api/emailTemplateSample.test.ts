import { afterEach, expect, test } from 'bun:test';
import { startSavedEmailTemplateTest } from './emailTemplateSample';

const originalFetch = globalThis.fetch;
const id = '30303030-3030-4030-8030-303030303030';
const pending = { delivery_id: id, status: 'pending', smtp_accepted: false, inbox_delivery_confirmed: false };
afterEach(() => { globalThis.fetch = originalFetch; });

test('saved-template test binds both observed revisions and cannot select a recipient or body', async () => {
  const controller = new AbortController(); let observed: RequestInit | undefined;
  globalThis.fetch = (async (path, init) => {
    expect(path).toBe('/api/v1/email-templates/email.invite/test'); observed = init;
    return new Response(JSON.stringify(pending), { status: 202, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  expect(await startSavedEmailTemplateTest('email.invite', 7, 3, controller.signal)).toEqual(pending);
  expect(observed).toEqual({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ expected_template_revision: 7, expected_smtp_revision: 3 }) });
});

test('invalid local observations cannot dispatch and a server refusal never exposes its body', async () => {
  let calls = 0;
  globalThis.fetch = (async () => { calls++; return new Response('private transport failure', { status: 409 }); }) as typeof fetch;
  await expect(startSavedEmailTemplateTest('email.invite', -1, 3, new AbortController().signal)).rejects.toThrow('Invalid saved email test observation');
  await expect(startSavedEmailTemplateTest('email.invite', 7, 0, new AbortController().signal)).rejects.toThrow('Invalid saved email test observation');
  expect(calls).toBe(0);
  await expect(startSavedEmailTemplateTest('email.invite', 7, 3, new AbortController().signal)).rejects.toMatchObject({ status: 409, message: 'Saved email test request rejected.' });
  expect(calls).toBe(1);
});

test('queued is distinct from SMTP or inbox receipt and unbounded or mismatched replies are refused', async () => {
  for (const value of [{ ...pending, status: 'sent', smtp_accepted: true }, { ...pending, inbox_delivery_confirmed: true }, { ...pending, delivery_id: 'not-an-id' }]) {
    globalThis.fetch = (async () => new Response(JSON.stringify(value), { status: 202, headers: { 'Content-Type': 'application/json' } })) as typeof fetch;
    await expect(startSavedEmailTemplateTest('email.invite', 7, 3, new AbortController().signal)).rejects.toThrow();
  }
  let cancelled = false;
  globalThis.fetch = (async () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(4097)); }, cancel() { cancelled = true; } }), { status: 202, headers: { 'Content-Type': 'application/json' } })) as typeof fetch;
  await expect(startSavedEmailTemplateTest('email.invite', 7, 3, new AbortController().signal)).rejects.toThrow('exceeded its bound');
  expect(cancelled).toBe(true);
});
