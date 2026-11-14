import { writable } from 'svelte/store';
import { needsSession, STAFF_PREFIXES, routeSurface } from './routeSurface';

// Staff session expiry. Every failed session check in the Go middleware answers
// 401 "unauthorized" (text/plain): missing or expired cookie, bad signature,
// user removed, role invalid, session generation bumped. The cookie is HttpOnly
// and /api/v1/me does not expose its expiry, so the client reacts to the 401 and
// probes /api/v1/me on focus and on a slow timer.
//
// The guard publishes a safe login URL. The root layout's notice returns the
// expired staff session to sign-in in the same tab. Normal browser navigation
// protection still applies to unsaved work; no draft is persisted by this guard.

/** Login URL to offer once the session is known to be over; null while the session is fine. */
export const sessionExpiredLoginUrl = writable<string | null>(null);

/**
 * Accepts only a same-origin staff route. The result is the normalised path, so
 * dot-segments and encoded dots cannot turn into '//host', and the route prefix
 * is matched on a '/' boundary, so backend paths such as /api/ never qualify.
 */
export function safeReturnPath(raw: string | null | undefined): string | null {
  if (!raw || raw.length > 2048 || !raw.startsWith('/') || raw.startsWith('//')) return null;
  if (raw.includes('\\') || /[\u0000-\u001f\u007f]/.test(raw)) return null;
  let url: URL;
  try { url = new URL(raw, 'https://return.invalid'); } catch { return null; }
  if (url.origin !== 'https://return.invalid') return null;
  const out = url.pathname + url.search;
  if (out.startsWith('//') || !STAFF_PREFIXES.some((p) => url.pathname === p || url.pathname.startsWith(p + '/'))) return null;
  if (routeSurface(url.pathname) !== 'staff') return null;
  return out;
}

export function loginUrlFor(pathname: string, search: string): string {
  const next = safeReturnPath(pathname + search);
  return next ? '/login?next=' + encodeURIComponent(next) : '/login';
}

/** Same safe return target, with an informational message on the sign-in screen. */
export function expiredLoginUrlFor(pathname: string, search: string): string {
  const login = loginUrlFor(pathname, search);
  return login + (login.includes('?') ? '&' : '?') + 'expired=1';
}

function staffApiPath(input: RequestInfo | URL, origin: string): string | null {
  let url: URL;
  try {
    url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, origin);
  } catch { return null; }
  if (url.origin !== origin) return null;
  return url.pathname;
}

/** True for staff API calls whose 401 means the session ended. /api/v1/auth/* is the public login surface. */
export function isStaffApiRequest(input: RequestInfo | URL, origin: string): boolean {
  const path = staffApiPath(input, origin);
  return path !== null && path.startsWith('/api/v1/') && !path.startsWith('/api/v1/auth/');
}

export interface SessionExpiryEnv {
  origin: string;
  location: { pathname: string; search: string };
  fetch: typeof fetch;
  setFetch(next: typeof fetch): void;
  /** Present in the browser so dispose can tell whether another guard replaced ours. */
  currentFetch?(): typeof fetch;
  visible(): boolean;
  /** Monotonic milliseconds. A step backwards is tolerated. */
  now(): number;
  listen(event: 'focus' | 'visibilitychange', handler: () => void): () => void;
  setInterval(handler: () => void, ms: number): () => void;
  /** Called with the login URL once the session is confirmed over. */
  notifyExpired(loginUrl: string): void;
  /** Called when /api/v1/me answers 2xx: the session is fine again, so any expired notice must go. */
  notifyRestored(): void;
  /** Called instead of notifyRestored when a different user is signed in than the one whose session expired. */
  reload(): void;
  onExpired?: () => void;
}

const PROBE_MIN_GAP_MS = 15_000;
const PROBE_INTERVAL_MS = 60_000;
const NOTIFY_MIN_GAP_MS = 5_000;
const CONFIRM_TIMEOUT_MS = 5_000;

function gapPassed(last: number | null, now: number, gap: number): boolean {
  return last === null || now < last || now - last >= gap;
}

/** Wraps fetch so a confirmed 401 from a staff API call announces the expired session. Returns a disposer. */
export function installSessionExpiryGuard(env: SessionExpiryEnv): () => void {
  const original = env.fetch;
  let disposed = false;
  let lastNotify: number | null = null;
  let lastProbe: number | null = null;
  let confirming: Promise<{ seq: number; state: 'expired' | 'ok' | 'unknown'; user: string | null }> | null = null;

  // Every /me request is stamped when it is sent. A result is applied only if no
  // newer request has already been applied, so a slow stale response can neither
  // bring the notice back over a valid session nor clear a newer expiry.
  let meSent = 0;
  let meApplied = 0;
  let lastUser: string | null = null;
  let noticeOpen = false;
  let noticeUser: string | null = null;

  let reloadAttempted = false;

  function showNotice(): void {
    noticeOpen = true;
    try { env.onExpired?.(); } catch { /* clearing local state must not block the notice */ }
    env.notifyExpired(loginUrlFor(env.location.pathname, env.location.search));
  }

  function expire(): void {
    if (disposed || !needsSession(env.location.pathname)) return;
    const t = env.now();
    // A short window instead of a permanent latch: a later 401 after the user
    // stayed on the page (for example a cancelled sign-in) announces again.
    if (!gapPassed(lastNotify, t, NOTIFY_MIN_GAP_MS)) return;
    lastNotify = t;
    noticeUser = lastUser;
    showNotice();
  }

  function applyMe(seq: number, state: 'expired' | 'ok', user: string | null): void {
    if (disposed || seq < meApplied) return;
    meApplied = seq;
    if (state === 'expired') { expire(); return; }
    // Fail closed: a 200 whose identity cannot be read proves nothing about who
    // is signed in, so it neither clears an open notice nor changes the known user.
    if (user === null) return;
    const owner = noticeOpen ? noticeUser : lastUser;
    if (owner !== null && user !== owner) {
      // A different account is signed in than the one this page was loaded for,
      // whether or not the notice was open: the page's state belongs to the old
      // user. Reload once per page load. If the reload is cancelled (a beforeunload
      // prompt) or has already been tried, keep the notice up instead of trying again.
      noticeUser = owner;
      if (!noticeOpen) showNotice();
      if (!reloadAttempted) { reloadAttempted = true; env.reload(); }
      return;
    }
    noticeOpen = false;
    lastUser = user;
    lastNotify = null; // a second expiry right after a restore must show again
    env.notifyRestored();
  }

  async function readUser(res: Response): Promise<string | null> {
    try {
      const body: unknown = await res.json();
      const id = (body as { user_id?: unknown } | null)?.user_id;
      return typeof id === 'string' && id !== '' ? id : null;
    } catch { return null; }
  }

  function timeoutSignal(ms: number): AbortSignal | undefined {
    if (typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(ms);
    if (typeof AbortController !== 'function') return undefined;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
  }

  // A request sent with the old cookie can 401 after a fresh sign-in in another
  // tab. Ask /me with the current cookie before declaring the session over. This
  // runs in the background: the caller already has its 401.
  function confirmExpired(): Promise<{ seq: number; state: 'expired' | 'ok' | 'unknown'; user: string | null }> {
    if (confirming) return confirming;
    const seq = ++meSent;
    confirming = new Promise<Response>((resolve) => {
      resolve(original('/api/v1/me', { credentials: 'include', cache: 'no-store', signal: timeoutSignal(CONFIRM_TIMEOUT_MS) }));
    }).then(async (r) => {
      const state = r.status === 401 ? 'expired' as const : r.ok ? 'ok' as const : 'unknown' as const;
      const user = state === 'ok' ? await readUser(r) : null;
      if (state !== 'ok') void r.body?.cancel().catch(() => {});
      return { seq, state, user };
    }, () => ({ seq, state: 'unknown' as const, user: null }))
      .finally(() => { confirming = null; });
    return confirming;
  }

  const guarded = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const watched = !disposed && isStaffApiRequest(input, env.origin);
    const isMe = watched && staffApiPath(input, env.origin) === '/api/v1/me';
    const seq = isMe ? ++meSent : 0;
    const res = await original(input, init);
    if (!watched || disposed) return res;
    try {
      if (isMe && res.ok) {
        // Awaited so the restore has landed before the caller sees the response.
        applyMe(seq, 'ok', await readUser(res.clone()));
      } else if (res.status === 401 && needsSession(env.location.pathname)) {
        if (isMe) applyMe(seq, 'expired', null);
        else if (gapPassed(lastNotify, env.now(), NOTIFY_MIN_GAP_MS)) {
          void confirmExpired().then((c) => {
            if (c.state !== 'unknown') applyMe(c.seq, c.state, c.user);
          }).catch(() => {});
        }
      }
    } catch { /* the caller must always get its response */ }
    return res;
  }) as typeof fetch;
  env.setFetch(guarded);

  function probe(): void {
    if (disposed || !env.visible() || !needsSession(env.location.pathname)) return;
    const t = env.now();
    if (!gapPassed(lastProbe, t, PROBE_MIN_GAP_MS)) return;
    lastProbe = t;
    guarded('/api/v1/me', { credentials: 'include', cache: 'no-store' }).catch(() => { /* offline: try again later */ });
  }

  const stops = [
    env.listen('focus', probe),
    env.listen('visibilitychange', probe),
    env.setInterval(probe, PROBE_INTERVAL_MS)
  ];
  return () => {
    disposed = true;
    stops.forEach((s) => s());
    if (!env.currentFetch || env.currentFetch() === guarded) env.setFetch(original);
  };
}

export function browserSessionExpiryEnv(onExpired?: () => void): SessionExpiryEnv {
  return {
    origin: window.location.origin,
    location: window.location,
    fetch: window.fetch.bind(window),
    setFetch: (next) => { window.fetch = next; },
    currentFetch: () => window.fetch,
    visible: () => document.visibilityState === 'visible',
    now: () => performance.now(),
    listen: (event, handler) => {
      const target: EventTarget = event === 'focus' ? window : document;
      target.addEventListener(event, handler);
      return () => target.removeEventListener(event, handler);
    },
    setInterval: (handler, ms) => { const id = window.setInterval(handler, ms); return () => window.clearInterval(id); },
    notifyExpired: (url) => sessionExpiredLoginUrl.set(url),
    notifyRestored: () => sessionExpiredLoginUrl.set(null),
    reload: () => window.location.reload(),
    onExpired
  };
}
