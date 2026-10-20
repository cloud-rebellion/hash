import { expect, test } from 'bun:test';
import { chatFixture, message, messages } from './commentHistory-fixture.test-support';
for (const signer of [false, true]) {
  const who = signer ? 'signer' : 'staff';
  test(`${who} failed chat refresh retains thread, exact Older retry and current draft`, async () => {
    const f = chatFixture(signer); await f.seed(); f.env.commentBody = 'draft';
    const selection = { kind: 'before', cursor: 'A'.repeat(76) };
    const pending = signer ? f.actions.loadComments('token', undefined, selection) : f.actions.loadComments('d', selection);
    f.calls[0].reject(new Error('Unavailable')); await pending;
    expect(f.env.comments).toEqual([message('retained')]); expect(f.env.commentBody).toBe('draft');
    expect(f.env.commentRefreshError).toContain('could not be refreshed');
    const retry = f.env.commentHistory.retry();
    if (signer) expect(f.calls[1].url).toBe(`/sign/token/comments?before=${selection.cursor}`);
    else expect(f.calls[1].selection).toEqual(selection);
    f.resolvePage(f.calls[1], messages('older')); await retry;
    expect(f.env.comments).toEqual([message('older')]); expect(f.env.commentBody).toBe('draft');
  });
  test(`${who} late read cannot replace a newer read or reset its loading state`, async () => {
    for (const fail of [false, true]) {
      const f = chatFixture(signer); const old = f.load(); const newer = f.load();
      if (fail) f.calls[0].reject(new Error('old')); else f.resolvePage(f.calls[0], messages('old'));
      await old; expect(f.env.commentLoading).toBe(true); expect(f.env.commentRefreshError).toBeNull();
      f.resolvePage(f.calls[1], messages('new')); await newer; expect(f.env.comments).toEqual([message('new')]);
    }
  });
  test(`${who} late GET cannot cross route ABA or disposal`, async () => {
    for (const disposed of [false, true]) {
      const f = chatFixture(signer); await f.seed(); const pending = f.load(); const oldCall = f.calls[0]; f.reset();
      await f.seed('current'); f.env.commentBody = 'current draft';
      if (disposed) { f.env.routeDisposed = true; f.env.disposed = true; f.env.commentHistory.dispose(); }
      f.resolvePage(oldCall, messages('wrong')); await pending;
      expect(f.env.comments).toEqual([message('current')]); expect(f.env.commentBody).toBe('current draft');
    }
  });
}

for (const signer of [false, true]) test(`${signer ? 'signer' : 'staff'} replaces windows over full 105-message bidirectional navigation`, async () => {
  const f = chatFixture(signer); f.env.commentBody = 'draft';
  const all = Array.from({ length: 105 }, (_, i) => message(String(i + 1)));
  const cursor = 'A'.repeat(76);
  for (const [first, last, kind] of [[55, 105, 'latest'], [5, 55, 'before'], [0, 5, 'before'], [5, 55, 'after'], [55, 105, 'latest']] as const) {
    const selection = kind === 'latest' ? { kind } : { kind, cursor };
    const pending = signer ? f.actions.loadComments('token', undefined, selection) : f.actions.loadComments('d', selection);
    f.resolvePage(f.calls[f.calls.length - 1], { comments: all.slice(first, last), older_cursor: first ? cursor : null, newer_cursor: last < 105 ? cursor : null });
    await pending; expect(f.env.comments).toEqual(all.slice(first, last)); expect(f.env.comments.length).toBeLessThanOrEqual(50);
    expect(f.env.commentBody).toBe('draft');
  }
});
