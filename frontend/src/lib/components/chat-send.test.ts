import { expect, test } from 'bun:test';
import { chatFixture, messages } from './commentHistory-fixture.test-support';
for (const signer of [false, true]) {
  const who = signer ? 'signer' : 'staff';
  test(`${who} serializes sends, retains a newer draft and refreshes Latest after success`, async () => {
    const f = chatFixture(signer); const pending = f.send(); await f.send(); expect(f.calls).toHaveLength(1);
    if (signer) { expect(f.calls[0].options.headers).toEqual({ digest: 'digest', accepted: true }); expect(JSON.parse(f.calls[0].options.body)).toEqual({ body: 'first' }); }
    else expect(f.calls[0].body).toBe('first');
    f.env.commentBody = 'next draft'; f.calls[0].resolve({ ok: true }); await Promise.resolve(); await Promise.resolve();
    expect(f.calls).toHaveLength(2); expect(f.calls[1].method).toBe('GET');
    if (signer) expect(f.calls[1].url).toBe('/sign/token/comments'); else expect(f.calls[1].selection).toEqual({ kind: 'latest' });
    f.resolvePage(f.calls[1], messages('sent')); await pending;
    expect(f.env.commentBody).toBe('next draft'); expect(f.env.postingComment).toBe(false);
  });
  test(`${who} POST success plus refresh failure retries GET without sending again`, async () => {
    const f = chatFixture(signer); const pending = f.send(); f.calls[0].resolve({ ok: true });
    await Promise.resolve(); await Promise.resolve(); f.env.commentBody = 'next'; f.calls[1].reject(new Error('HTTP 503')); await pending;
    expect(f.env.commentBody).toBe('next'); expect(f.env.error).toBeNull(); expect(f.env.signError).toBeNull();
    expect(f.env.commentRefreshError).toContain('503'); const retry = f.env.commentHistory.retry();
    f.resolvePage(f.calls[2], messages('sent')); await retry;
    expect(f.calls.filter(c => c.method === 'POST')).toHaveLength(1); expect(f.env.commentBody).toBe('next');
  });
  test(`${who} send failure preserves draft and reports an error`, async () => {
    const f = chatFixture(signer); const pending = f.send();
    if (signer) f.calls[0].resolve({ ok: false, status: 503 }); else f.calls[0].reject(new Error('Unavailable'));
    await pending; expect(f.env.commentBody).toBe('first'); expect(f.env.postingComment).toBe(false); expect(f.calls).toHaveLength(1);
    expect(signer ? f.env.signError : f.env.error).toBeTruthy();
  });
  test(`${who} ABA response cannot clear a new draft, new error or newer pending send`, async () => {
    for (const fail of [false, true]) {
      const f = chatFixture(signer); const previous = f.send(); f.reset();
      if (signer) { f.env.noticeAcknowledged = true; f.env.acknowledgedScopeKey = f.actions.currentCeremonyKey(); }
      f.env.commentBody = 'new'; f.env.signError = 'current'; f.env.error = 'current'; const next = f.send();
      f.env.signError = 'current'; f.env.error = 'current';
      if (fail) f.calls[0].reject(new Error('old')); else f.calls[0].resolve({ ok: true }); await previous;
      expect(f.env.postingComment).toBe(true); expect(f.env.commentBody).toBe('new'); expect(f.env.signError).toBe('current'); expect(f.env.error).toBe('current');
      f.calls[1].reject(new Error('new failure')); await next;
    }
  });
}

test('ordinary staff status updates preserve the active chat read and send', async () => {
  for (const send of [false, true]) {
    const f = chatFixture(); await f.seed();
    const pending = send ? f.send() : f.load();
    f.actions.receiveStatus('sent', { id: 'd', routeRevision: 1, documentRevision: 1 });
    expect(f.env.documentRevision).toBe(2); f.env.commentBody = 'new draft';
    if (send) {
      f.calls[0].resolve({}); await Promise.resolve(); await Promise.resolve();
      f.resolvePage(f.calls[1], messages('current'));
    } else f.resolvePage(f.calls[0], messages('current'));
    await pending; expect(f.env.commentLoading).toBe(false); expect(f.env.postingComment).toBe(false);
    expect(f.env.comments[0].id).toBe('current'); expect(f.env.commentBody).toBe('new draft');
  }
});

for (const signer of [false, true]) test(`${signer ? 'signer' : 'staff'} confirmed POST releases send and Latest before a stalled refresh finishes`, async () => {
  const f = chatFixture(signer); const previous = f.send(); f.calls[0].resolve({ ok: true });
  await Promise.resolve(); await Promise.resolve(); expect(f.env.postingComment).toBe(false); expect(f.env.commentLoading).toBe(true);
  f.env.commentBody = 'next draft'; const next = f.send(); expect(f.calls[2].method).toBe('POST');
  f.calls[1].reject(new Error('superseded refresh')); await previous;
  expect(f.env.postingComment).toBe(true); expect(f.env.commentBody).toBe('next draft'); expect(f.env.commentRefreshError).toBeNull();
  f.calls[2].reject(new Error('next failed')); await next; expect(f.env.postingComment).toBe(false);
});
