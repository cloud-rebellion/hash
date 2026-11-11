import { expect, test } from 'bun:test';
import { postWithLookupRetry } from './signerLookupRetry';

const refusal = () => new Response('{"error":"signer access is temporarily unavailable"}\n', { status: 503, headers: { 'Retry-After': '1' } });
const run = (responses: Array<() => Response>, over: Partial<Parameters<typeof postWithLookupRetry>[1]> = {}) => {
  let calls = 0;
  const sleeps: number[] = [];
  return postWithLookupRetry(async () => responses[Math.min(calls++, responses.length - 1)](), { delayMs: 250, sleep: async ms => { sleeps.push(ms); }, current: () => true, ...over })
    .then(res => ({ res, calls, sleeps }));
};

test('retries only the exact lookup refusal, at most twice', async () => {
  const ok = await run([refusal, refusal, () => new Response('{}', { status: 200 })]);
  expect([ok.res.status, ok.calls, ok.sleeps]).toEqual([200, 3, [250, 250]]);
  const exhausted = await run([refusal]);
  expect([exhausted.res.status, exhausted.calls]).toEqual([503, 3]);
});

test('never retries other responses, including signing unavailable', async () => {
  for (const make of [
    () => new Response('{"error":"signing is temporarily unavailable"}\n', { status: 503, headers: { 'Retry-After': '1' } }),
    () => new Response('{"error":"signer access is temporarily unavailable"}\n', { status: 503 }),
    () => new Response('{"error":"signer access is temporarily unavailable"}\n', { status: 500, headers: { 'Retry-After': '1' } }),
    () => new Response('not json', { status: 503, headers: { 'Retry-After': '1' } }),
    () => new Response('{}', { status: 409 })
  ]) {
    const r = await run([make]);
    expect(r.calls).toBe(1);
  }
});

test('stops retrying when the ceremony is no longer current', async () => {
  let live = true;
  const r = await run([refusal], { sleep: async () => { live = false; }, current: () => live });
  expect(r.calls).toBe(1);
});

test('a network failure is never retried', async () => {
  let calls = 0;
  await expect(postWithLookupRetry(async () => { calls++; throw new Error('network'); }, { delayMs: 1, sleep: async () => {}, current: () => true })).rejects.toThrow('network');
  expect(calls).toBe(1);
});

test('default delay honours the advertised Retry-After of one second', async () => {
  const sleeps: number[] = [];
  let calls = 0;
  await postWithLookupRetry(async () => (calls++, refusal()), { sleep: async ms => { sleeps.push(ms); } });
  expect(sleeps).toEqual([1000, 1000]);
});
