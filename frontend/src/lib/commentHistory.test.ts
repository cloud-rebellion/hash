import { expect, test } from 'bun:test';
import { commentQuery, createCommentHistory, emptyCommentHistory } from './commentHistory';

export function row(id: number) { return { id: `message-${id}`, author_name: 'Author', author_side: 'sender' as const, body: `Text ${id}`, created_at: '2026-10-16T10:00:00.123456Z' }; }
const older = 'A'.repeat(76), newer = 'B'.repeat(76);
function fixture() {
  const calls: any[] = []; let state = emptyCommentHistory(); let current = 1;
  const history = createCommentHistory<number>({ isCurrent: scope => scope === current,
    readPage: (scope, selection, signal) => new Promise((resolve, reject) => calls.push({ scope, selection, signal, resolve, reject })),
    changed: view => { state = view; } });
  return { calls, history, get state() { return state; }, move: (scope: number) => { current = scope; history.reset(); } };
}
function page(start = 1) { return { comments: [row(start)], older_cursor: older, newer_cursor: newer }; }

test('history uses only latest or one opaque direction query', () => {
  expect(commentQuery({ kind: 'latest' })).toBe('');
  expect(commentQuery({ kind: 'before', cursor: older })).toBe(`?before=${older}`);
  expect(commentQuery({ kind: 'after', cursor: newer })).toBe(`?after=${newer}`);
  expect(() => commentQuery({ kind: 'before', cursor: 'bad&limit=100' })).toThrow();
});
test('failed older read preserves the complete window and retries the exact captured selection', async () => {
  const f = fixture(); const first = f.history.load(1); f.calls[0].resolve(page()); await first;
  const prior = f.state; const failed = f.history.load(1, { kind: 'before', cursor: older });
  f.calls[1].reject(new Error('HTTP 503')); await failed;
  expect(f.state.comments).toEqual(prior.comments); expect(f.state.olderCursor).toBe(older); expect(f.state.canRetry).toBe(true);
  const retry = f.history.retry(); expect(f.calls[2].selection).toEqual({ kind: 'before', cursor: older });
  f.calls[2].resolve(page(2)); await retry; expect(f.state.comments).toEqual([row(2)]); expect(f.state.error).toBeNull();
});
test('latest supersedes old success, error and finalization even if transport ignores abort', async () => {
  for (const failure of [false, true]) {
    const f = fixture(); const pending = f.history.load(1, { kind: 'before', cursor: older }); const latest = f.history.load(1);
    expect(f.calls[0].signal.aborted).toBe(true);
    if (failure) f.calls[0].reject(new Error('old')); else f.calls[0].resolve(page(1)); await pending;
    expect(f.state.loading).toBe(true); expect(f.state.error).toBeNull();
    f.calls[1].resolve(page(2)); await latest; expect(f.state.comments).toEqual([row(2)]); expect(f.state.loading).toBe(false);
  }
});
test('malformed, duplicated and oversized responses retain the previous valid window', async () => {
  for (const invalid of [null, {}, { ...page(), older_cursor: undefined }, { ...page(), comments: [row(1), row(1)] },
    { ...page(), comments: Array.from({ length: 51 }, (_, i) => row(i)) }, { ...page(), comments: [{ ...row(1), author_side: 'other' }] }]) {
    const f = fixture(); const initial = f.history.load(1); f.calls[0].resolve(page()); await initial;
    const pending = f.history.load(1); f.calls[1].resolve(invalid); await pending;
    expect(f.state.comments).toEqual([row(1)]); expect(f.state.olderCursor).toBe(older); expect(f.state.error).toContain('Invalid message history');
  }
});
test('route ABA, external cancellation, POST invalidation and disposal reject late results', async () => {
  for (const action of ['aba', 'cancel', 'post', 'dispose']) {
    const f = fixture(); const signal = new AbortController(); const pending = f.history.load(1, undefined, signal.signal);
    if (action === 'aba') { f.move(2); f.move(1); }
    if (action === 'cancel') signal.abort();
    if (action === 'post') f.history.invalidate();
    if (action === 'dispose') f.history.dispose();
    f.calls[0].resolve(page()); await pending;
    expect(f.state.comments).toEqual([]); expect(f.state.loading).toBe(false); expect(f.state.error).toBeNull();
    if (action === 'dispose') { await f.history.load(1); expect(f.calls).toHaveLength(1); }
  }
});
test('whole-window replacement preserves full historical text and microsecond time strings', async () => {
  const f = fixture(); const body = 'Historical text '.repeat(10000); const pending = f.history.load(1);
  f.calls[0].resolve({ comments: [{ ...row(1), body }], older_cursor: null, newer_cursor: null }); await pending;
  expect(f.state.comments[0].body).toBe(body); expect(f.state.comments[0].created_at).toBe(row(1).created_at);
  const next = f.history.load(1); f.calls[1].resolve({ comments: [], older_cursor: null, newer_cursor: null }); await next;
  expect(f.state.comments).toEqual([]);
});
