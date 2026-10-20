import { signerNoticeHeaders } from './api/signerNotice';

export type SignerViewScope = {
  epoch: number;
  key: string;
  kind: string;
  token: string;
  noticeDigest: string;
};

export type SignerViewState = { pending: boolean; confirmed: boolean; error: string | null };
const emptyState = (): SignerViewState => ({ pending: false, confirmed: false, error: null });
const failureMessage = 'The document is displayed, but its view could not be confirmed with the sender. Please try again.';

// A rendered document and its acknowledged notice are prerequisites, separate
// from filling fields or signing. Only a new ceremony gets an automatic attempt.
export function createSignerViewRecorder(options: {
  fetch: typeof fetch;
  current: (scope: SignerViewScope) => boolean;
  changed: (state: SignerViewState) => void;
}) {
  type Attempt = { controller: AbortController };
  type Owner = {
    scope: SignerViewScope;
    ready: boolean;
    acknowledged: boolean;
    attempted: boolean;
    attempt?: Attempt;
    state: SignerViewState;
  };
  let owner: Owner | undefined;
  let disposed = false;

  function current(active: Owner, attempt?: Attempt): boolean {
    return !disposed && owner === active && options.current(active.scope)
      && (!attempt || active.attempt === attempt && !attempt.controller.signal.aborted);
  }

  function publish(active: Owner) {
    if (current(active)) options.changed({ ...active.state });
  }

  function invalidate() {
    owner?.attempt?.controller.abort();
    owner = undefined;
    options.changed(emptyState());
  }

  async function dispatch(active: Owner) {
    if (!current(active) || !active.ready || !active.acknowledged || active.attempt || active.state.confirmed) return;
    active.attempted = true;
    const attempt: Attempt = { controller: new AbortController() };
    active.attempt = attempt;
    active.state = { pending: true, confirmed: false, error: null };
    publish(active);
    try {
      const response = await options.fetch(`/sign/${encodeURIComponent(active.scope.token)}/view`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: attempt.controller.signal,
        headers: signerNoticeHeaders(active.scope.noticeDigest)
      });
      if (!current(active, attempt)) return;
      if (!response.ok) throw new Error('View confirmation refused');
      const body: unknown = await response.json();
      if (!current(active, attempt)) return;
      if (!body || typeof body !== 'object' || !('ok' in body) || body.ok !== true
        || !('status' in body) || body.status !== 'viewed') throw new Error('Invalid view confirmation');
      active.state.confirmed = true;
    } catch {
      if (current(active, attempt)) active.state.error = failureMessage;
    } finally {
      if (current(active, attempt)) {
        active.attempt = undefined;
        active.state.pending = false;
        publish(active);
      }
    }
  }

  function update(scope: SignerViewScope | null, ready: boolean, acknowledged: boolean) {
    if (disposed) return;
    if (!scope || !scope.key || !scope.token || !scope.noticeDigest || !options.current(scope)) {
      invalidate();
      return;
    }
    if (!owner || Object.keys(scope).some(key => scope[key as keyof SignerViewScope] !== owner!.scope[key as keyof SignerViewScope])) {
      invalidate();
      owner = { scope: { ...scope }, ready, acknowledged, attempted: false, state: emptyState() };
    }
    const active = owner;
    active.ready = ready;
    active.acknowledged = acknowledged;
    if (!ready || !acknowledged) {
      if (active.attempt) {
        active.attempt.controller.abort();
        active.attempt = undefined;
        active.state.pending = false;
        active.state.error = failureMessage;
        publish(active);
      }
      return;
    }
    if (!active.attempted) void dispatch(active);
  }

  return {
    update,
    invalidate,
    retry() {
      if (owner?.state.error && !owner.state.pending) void dispatch(owner);
    },
    dispose() { invalidate(); disposed = true; }
  };
}
