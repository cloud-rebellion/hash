import { expect, test } from 'bun:test';
import { createSignerViewRecorder, type SignerViewScope, type SignerViewState } from './signerView';

const scope = (): SignerViewScope => ({ epoch: 1, key: 'document-recipient-artifact-notice', kind: 'pdf', token: 'original-token', noticeDigest: 'c'.repeat(64) });
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
const success = () => new Response(JSON.stringify({ ok: true, status: 'viewed' }));
function fixture() {
  const calls: { url: string; options: RequestInit; resolve: (value: Response) => void; reject: (error: Error) => void }[] = [];
  let live: SignerViewScope | null = scope();
  let state: SignerViewState = { pending: false, confirmed: false, error: null };
  const recorder = createSignerViewRecorder({
    fetch: ((url: string, options: RequestInit) => new Promise<Response>((resolve, reject) => calls.push({ url, options, resolve, reject }))) as typeof fetch,
    current: candidate => live !== null && Object.keys(candidate).every(key => candidate[key as keyof SignerViewScope] === live![key as keyof SignerViewScope]),
    changed: next => { state = next; }
  });
  return { calls, recorder, get state() { return state; }, get live() { return live!; }, navigate(next: SignerViewScope | null) { live = next; } };
}

for (const first of ['render', 'notice'] as const) {
  test(`${first} first waits for both prerequisites and records exactly one view`, async () => {
    const f = fixture();
    f.recorder.update({ ...f.live }, first === 'render', first === 'notice');
    expect(f.calls).toHaveLength(0);
    f.recorder.update({ ...f.live }, true, true);
    f.recorder.update({ ...f.live }, true, true);
    expect(f.calls).toHaveLength(1); expect(f.state.pending).toBe(true);
    expect(f.calls[0].url).toBe('/sign/original-token/view');
    expect(f.calls[0].options).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    expect(f.calls[0].options.headers).toEqual({ 'X-Hash-Notice-Digest': 'c'.repeat(64) });
    f.calls[0].resolve(success()); await flush();
    expect(f.state).toEqual({ pending: false, confirmed: true, error: null });
    f.recorder.update({ ...f.live }, true, true); f.recorder.retry();
    expect(f.calls).toHaveLength(1);
  });
}

for (const failure of ['503', 'network', 'malformed', 'invalid-body'] as const) {
  test(`${failure} is visible, never automatically retried, and permits one explicit retry`, async () => {
    const f = fixture(); f.recorder.update(f.live, true, true);
    if (failure === 'network') f.calls[0].reject(new Error('network'));
    else if (failure === '503') f.calls[0].resolve({ ok: false, json: () => new Promise(() => {}) } as Response);
    else f.calls[0].resolve(new Response(failure === 'malformed' ? '{' : JSON.stringify({ ok: false, status: 'viewed' })));
    await flush();
    expect(f.state.pending).toBe(false); expect(f.state.confirmed).toBe(false); expect(f.state.error).toBeTruthy();
    f.recorder.update({ ...f.live }, true, true);
    f.recorder.update({ ...f.live }, false, true); f.recorder.retry();
    expect(f.calls).toHaveLength(1);
    f.recorder.update({ ...f.live }, true, true);
    expect(f.calls).toHaveLength(1);
    f.recorder.retry(); f.recorder.retry(); expect(f.calls).toHaveLength(2);
    f.calls[1].resolve(success()); await flush();
    expect(f.state).toEqual({ pending: false, confirmed: true, error: null });
  });
}

for (const part of ['epoch', 'key', 'kind', 'token', 'noticeDigest'] as const) {
  test(`late ${part} results cannot confirm or overwrite the current ceremony`, async () => {
    const f = fixture(); f.recorder.update(f.live, true, true);
    const next = { ...f.live, [part]: part === 'epoch' ? 2 : part === 'noticeDigest' ? 'd'.repeat(64) : 'changed' };
    f.navigate(next); f.recorder.update(next, true, true);
    expect(f.calls[0].options.signal!.aborted).toBe(true);
    f.calls[0].resolve(success()); await flush();
    expect(f.state).toEqual({ pending: true, confirmed: false, error: null });
    f.calls[1].reject(new Error('new failure')); await flush();
    expect(f.state.pending).toBe(false); expect(f.state.error).toBeTruthy();
  });
}

test('A to B to A navigation rejects a delayed old body and its finally', async () => {
  const f = fixture(); f.recorder.update(f.live, true, true);
  let finish!: (body: unknown) => void;
  f.calls[0].resolve({ ok: true, json: () => new Promise(resolve => { finish = resolve; }) } as Response);
  await flush();
  const next = { ...f.live, epoch: 2, key: 'B', token: 'B' };
  f.navigate(next); f.recorder.update(next, false, false);
  const again = { ...scope(), epoch: 3 };
  f.navigate(again); f.recorder.update(again, true, true);
  expect(f.calls[0].options.signal!.aborted).toBe(true);
  finish({ ok: true, status: 'viewed' }); await flush();
  expect(f.state.pending).toBe(true); expect(f.state.confirmed).toBe(false);
  f.calls[1].resolve(success()); await flush();
  expect(f.state.confirmed).toBe(true);
});

test('losing a prerequisite aborts its ticket; late completion cannot clear explicit retry', async () => {
  const f = fixture(); f.recorder.update(f.live, true, true);
  f.recorder.update(f.live, false, true);
  expect(f.calls[0].options.signal!.aborted).toBe(true); expect(f.state.pending).toBe(false);
  f.recorder.update(f.live, true, true); expect(f.calls).toHaveLength(1);
  f.recorder.retry(); expect(f.calls).toHaveLength(2);
  f.calls[0].reject(new Error('old abort')); await flush();
  expect(f.state.pending).toBe(true); expect(f.state.error).toBeNull();
  f.calls[1].resolve(success()); await flush(); expect(f.state.confirmed).toBe(true);
});

test('invalidation and disposal abort requests and refuse late completion or future dispatch', async () => {
  for (const dispose of [false, true]) {
    const f = fixture(); f.recorder.update(f.live, true, true);
    if (dispose) f.recorder.dispose(); else { f.navigate(null); f.recorder.update(null, false, false); }
    expect(f.calls[0].options.signal!.aborted).toBe(true);
    f.calls[0].resolve(success()); await flush();
    expect(f.state).toEqual({ pending: false, confirmed: false, error: null });
    f.recorder.retry(); if (dispose) f.recorder.update(scope(), true, true);
    expect(f.calls).toHaveLength(1);
  }
});
