import type { DocComment } from './api/client';

export type CommentSelection = { kind: 'latest' } | { kind: 'before' | 'after'; cursor: string };
export type CommentPage = { comments: DocComment[]; older_cursor: string | null; newer_cursor: string | null };
export type CommentHistoryView = {
  comments: DocComment[];
  olderCursor: string | null;
  newerCursor: string | null;
  loading: boolean;
  error: string | null;
  canRetry: boolean;
};
export const latestComments: CommentSelection = Object.freeze({ kind: 'latest' });
const cursorPattern = /^[A-Za-z0-9_-]{76}$/;

export function commentQuery(selection: CommentSelection): string {
  if (selection.kind === 'latest') return '';
  if (!cursorPattern.test(selection.cursor)) throw new Error('Invalid message history selection.');
  return `?${selection.kind}=${encodeURIComponent(selection.cursor)}`;
}

export function emptyCommentHistory(): CommentHistoryView {
  return { comments: [], olderCursor: null, newerCursor: null, loading: false, error: null, canRetry: false };
}

function validatePage(raw: unknown): CommentPage {
  if (!raw || typeof raw !== 'object') throw new Error('Invalid message history response.');
  const page = raw as CommentPage;
  if (!Array.isArray(page.comments) || page.comments.length > 50
      || ![page.older_cursor, page.newer_cursor].every(c => c === null || (typeof c === 'string' && cursorPattern.test(c)))) {
    throw new Error('Invalid message history response.');
  }
  const ids = new Set<string>();
  const comments = page.comments.map(c => {
    if (!c || typeof c.id !== 'string' || !c.id || ids.has(c.id)
        || typeof c.author_name !== 'string' || !['sender', 'signer'].includes(c.author_side)
        || typeof c.body !== 'string' || typeof c.created_at !== 'string'
        || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(c.created_at)
        || !Number.isFinite(Date.parse(c.created_at))) throw new Error('Invalid message history response.');
    ids.add(c.id);
    // Preserve full historical text and microsecond timestamps; never sort via Date.
    return { id: c.id, author_name: c.author_name, author_side: c.author_side, body: c.body, created_at: c.created_at };
  });
  return { comments, older_cursor: page.older_cursor, newer_cursor: page.newer_cursor };
}

// GET ownership only. Drafts, POST and privacy acknowledgement belong to the route.
export function createCommentHistory<Scope>(options: {
  readPage: (scope: Scope, selection: CommentSelection, signal: AbortSignal) => Promise<unknown>;
  isCurrent: (scope: Scope) => boolean;
  changed: (view: CommentHistoryView) => void;
}) {
  let view = emptyCommentHistory();
  let generation = 0;
  let disposed = false;
  let active: AbortController | null = null;
  let failed: { scope: Scope; selection: CommentSelection } | null = null;
  function publish(next: CommentHistoryView) { view = next; options.changed(next); }
  function invalidate() {
    generation++;
    active?.abort();
    active = null;
    failed = null;
    publish({ ...view, loading: false, error: null, canRetry: false });
  }
  async function load(scope: Scope, selection: CommentSelection = latestComments, externalSignal?: AbortSignal): Promise<void> {
    if (disposed || externalSignal?.aborted || !options.isCurrent(scope)) return;
    invalidate();
    const ticket = generation;
    const request = new AbortController();
    active = request;
    const captured = Object.freeze({ ...selection });
    const live = () => !disposed && ticket === generation && !request.signal.aborted && options.isCurrent(scope);
    const abort = () => { if (live()) invalidate(); else request.abort(); };
    externalSignal?.addEventListener('abort', abort, { once: true });
    publish({ ...view, loading: true, error: null, canRetry: false });
    try {
      const raw = await options.readPage(scope, captured, request.signal);
      if (!live()) return;
      const page = validatePage(raw);
      publish({ comments: page.comments, olderCursor: page.older_cursor, newerCursor: page.newer_cursor,
        loading: false, error: null, canRetry: false });
    } catch (error) {
      if (!live()) return;
      failed = { scope, selection: captured };
      const message = error instanceof Error ? error.message : 'Request failed.';
      publish({ ...view, loading: false, error: `Messages could not be refreshed. ${message}`, canRetry: true });
    } finally {
      externalSignal?.removeEventListener('abort', abort);
      if (ticket === generation && active === request) active = null;
    }
  }
  return {
    load,
    retry: async () => { const retry = failed; if (retry) await load(retry.scope, retry.selection); },
    invalidate,
    reset: () => { invalidate(); publish(emptyCommentHistory()); },
    dispose: () => { disposed = true; invalidate(); },
  };
}
