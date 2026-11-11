import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { installSessionExpiryGuard, isStaffApiRequest, loginUrlFor, safeReturnPath, sessionExpiredLoginUrl, type SessionExpiryEnv } from './sessionExpiry';
import { needsSession } from './routeSurface';

function harness(pathname: string, respond: (url: string) => Promise<Response> | Response, search = '') {
  const notified: string[] = [];
  let restored = 0;
  let reloaded = 0;
  const handlers: Record<string, () => void> = {};
  let tick: () => void = () => {};
  let clock = 1_000_000;
  let visible = true;
  let cleared = 0;
  const calls: string[] = [];
  const location = { pathname, search };
  const original = (async (input: RequestInfo | URL) => { calls.push(String(input)); return respond(String(input)); }) as typeof fetch;
  let current: typeof fetch = original;
  const env: SessionExpiryEnv = {
    origin: 'https://hash.test', location, fetch: original, setFetch: (f) => { current = f; }, currentFetch: () => current,
    visible: () => visible, now: () => clock,
    listen: (e, h) => { handlers[e] = h; return () => { delete handlers[e]; }; },
    setInterval: (h) => { tick = h; return () => {}; },
    notifyExpired: (u) => { notified.push(u); }, notifyRestored: () => { restored++; }, reload: () => { reloaded++; }, onExpired: () => { cleared++; }
  };
  const stop = installSessionExpiryGuard(env);
  return {
    notified, handlers, calls, stop, location, original, env, get cleared() { return cleared; }, get restored() { return restored; }, get reloaded() { return reloaded; }, get fetch() { return current; },
    tick: () => tick(), advance: (ms: number) => { clock += ms; }, hide: () => { visible = false; }
  };
}
const settle = () => new Promise<void>((r) => setTimeout(r, 5));
const unauthorized = () => new Response('unauthorized', { status: 401 });
const statusOf = (status: number) => () => new Response('x', { status });

test('a confirmed 401 from a staff API call clears state and announces the login url with a return path', async () => {
  const h = harness('/documents/abc', unauthorized, '?tab=2');
  await h.fetch('/api/v1/documents/abc'); await settle();
  await h.fetch('/api/v1/templates'); await settle();
  expect(h.notified).toEqual(['/login?next=' + encodeURIComponent('/documents/abc?tab=2')]);
  expect(h.cleared).toBe(1);
});

test('the guard never navigates and the browser env publishes the url to the store', () => {
  expect(get(sessionExpiredLoginUrl)).toBeNull();
  sessionExpiredLoginUrl.set('/login?next=%2Fdashboard');
  expect(get(sessionExpiredLoginUrl)).toBe('/login?next=%2Fdashboard');
  sessionExpiredLoginUrl.set(null);
});

test('403, 503 and 200 do not announce', async () => {
  for (const status of [200, 403, 503]) {
    const h = harness('/documents', statusOf(status));
    await h.fetch('/api/v1/documents');
    expect(h.notified).toEqual([]);
  }
});

test('login attempts, cross-origin and non-API 401s do not announce', async () => {
  const h = harness('/documents', unauthorized);
  await h.fetch('/api/v1/auth/login', { method: 'POST' });
  await h.fetch('https://other.test/api/v1/me');
  await h.fetch('/api/verify');
  expect(h.notified).toEqual([]);
});

test('public signer, notice, login, legal, verify and unknown pages never announce', async () => {
  for (const path of ['/sign/abc', '/completed/tok', '/notice/x', '/login', '/legal/terms', '/', '/verify', '/verify/', '/nowhere']) {
    const h = harness(path, unauthorized);
    await h.fetch('/api/v1/me'); h.handlers.focus!(); await settle();
    expect(h.notified).toEqual([]);
  }
});

test('an idle tab is probed on focus and announced on 401', async () => {
  const h = harness('/dashboard', unauthorized);
  h.handlers.focus!(); await settle();
  expect(h.calls).toEqual(['/api/v1/me']);
  expect(h.notified).toEqual(['/login?next=' + encodeURIComponent('/dashboard')]);
});

test('probe is throttled and skipped while hidden', () => {
  const h = harness('/dashboard', statusOf(200));
  h.handlers.visibilitychange!(); h.handlers.focus!();
  expect(h.calls.length).toBe(1);
  h.advance(60_000); h.hide(); h.tick();
  expect(h.calls.length).toBe(1);
});

test('isStaffApiRequest', () => {
  expect(isStaffApiRequest('/api/v1/me', 'https://hash.test')).toBe(true);
  expect(isStaffApiRequest(new Request('https://hash.test/api/v1/x'), 'https://hash.test')).toBe(true);
  expect(isStaffApiRequest('/api/v1/auth/login', 'https://hash.test')).toBe(false);
  expect(isStaffApiRequest('//evil.test/api/v1/me', 'https://hash.test')).toBe(false);
});

test.each([
  '/..//evil.test', '/./..//evil.test', '/a/..//evil.test', '/%2e%2e//evil.test', '/%2E%2E//evil.test',
  '/.//evil.test', '/%2e//evil.test', '/.%2e//evil.test', '/..///evil.test', '/../..//evil.test/x?y=1', '/..//evil.test x',
  '/documents/..//evil.test', '/documents/%2e%2e/%2e%2e//evil.test', '/dashboard/../..//evil.test'
])('safeReturnPath(%p) never yields an off-origin or scheme-relative target', (raw) => {
  const out = safeReturnPath(raw);
  expect(out).toBeNull();
});

test('safeReturnPath accepts only staff route prefixes on a slash boundary', () => {
  for (const ok of ['/dashboard', '/documents/1?x=y', '/templates/html/new', '/settings/members', '/help', '/documents/']) {
    const out = safeReturnPath(ok);
    expect(out).toBe(ok);
    expect(out!.startsWith('//')).toBe(false);
  }
  for (const bad of [
    null, '', 'documents', 'https://evil.test', '//evil.test', '/\\evil.test', '/\\/evil.test', 'javascript:alert(1)', '/x\n/y',
    '/login', '/sign/tok', '/verify', '/verify-email', '/dashboardx', '/documents-old', '/api/v1/documents', '/a/cr', '/mcp', '/api/automation/v1/x',
    '/dashboard/../api/v1/me', '/documents/%2e%2e/api/v1/me', '/documents%2F..%2F..%2Fapi', '/%64ashboard/%2e%2e/%61pi/v1/me', '/'
  ]) expect(safeReturnPath(bad as string | null)).toBeNull();
  expect(safeReturnPath('/' + 'a'.repeat(2048))).toBeNull();
  expect(loginUrlFor('/login', '')).toBe('/login');
  expect(loginUrlFor('/verify', '')).toBe('/login');
});

test('the public /verify page is not a session page and an anonymous visitor is not told to sign in', async () => {
  expect(needsSession('/verify')).toBe(false);
  expect(needsSession('/verify-email')).toBe(false);
  const h = harness('/verify', unauthorized);
  await h.fetch('/api/v1/me'); h.handlers.focus!(); await settle();
  expect(h.notified).toEqual([]);
});

test('a later 401 after the first notice announces again once the short window has passed', async () => {
  const h = harness('/documents/42', unauthorized);
  await h.fetch('/api/v1/documents/42'); await settle();
  expect(h.notified.length).toBe(1);
  h.location.pathname = '/templates'; h.advance(60_000);
  await h.fetch('/api/v1/templates'); h.tick(); await settle();
  expect(h.notified.length).toBe(2);
});

test('a burst of 401s inside the window announces once', async () => {
  const h = harness('/documents', unauthorized);
  await Promise.all([h.fetch('/api/v1/a'), h.fetch('/api/v1/b'), h.fetch('/api/v1/c')]); await settle();
  expect(h.notified.length).toBe(1);
  expect(h.calls.filter((c) => c === '/api/v1/me').length).toBe(1);
});

test('a stale 401 is confirmed against /api/v1/me before announcing', async () => {
  const h = harness('/documents/7', (u) => u.endsWith('/api/v1/me') ? meOk() : unauthorized());
  await h.fetch('/api/v1/documents/7/upload', { method: 'POST' }); await settle();
  expect(h.notified).toEqual([]);
});

test('the probe survives the wall clock moving backwards', async () => {
  const h = harness('/dashboard', statusOf(200));
  h.handlers.focus!();
  h.advance(-3_600_000); h.advance(60_000); h.tick();
  expect(h.calls.length).toBe(2);
});

test('percent-encoded aliases of exempt routes are exempt', () => {
  for (const p of ['/%6Cogin', '/%73ign/tok', '/%6Cegal/terms', '/%76erify']) expect(needsSession(p)).toBe(false);
});

test('a probe still in flight when the guard is disposed does not announce', async () => {
  let release!: () => void; const gate = new Promise<void>((r) => { release = r; });
  const h = harness('/dashboard', async () => { await gate; return unauthorized(); });
  h.handlers.focus!(); h.stop(); release(); await settle(); await new Promise((r) => setTimeout(r, 1));
  expect(h.notified).toEqual([]);
});

test('dispose restores the original fetch only when this guard is still the installed one', () => {
  const a = harness('/dashboard', statusOf(200));
  expect(a.fetch).not.toBe(a.original);
  a.stop();
  expect(a.fetch).toBe(a.original);
  const b = harness('/dashboard', statusOf(200));
  const replacement = (async () => new Response('x')) as typeof fetch;
  b.env.setFetch(replacement);
  b.stop();
  expect(b.fetch).toBe(replacement);
});

test('A1: a 2xx from /api/v1/me clears the notice, from the probe, from focus and from the confirm check', async () => {
  const h = harness('/settings/email', () => meOk());
  h.handlers.focus!(); await settle();
  expect(h.restored).toBe(1);
  h.advance(60_000); h.handlers.visibilitychange!(); await settle();
  expect(h.restored).toBe(2);
  const stale = harness('/documents/7', (u) => u.endsWith('/api/v1/me') ? meOk() : unauthorized());
  await stale.fetch('/api/v1/documents/7/upload', { method: 'POST' }); await settle();
  expect(stale.notified).toEqual([]);
  expect(stale.restored).toBe(1);
});

test('A1: a failed or 5xx /me does not clear the notice', async () => {
  const h = harness('/dashboard', statusOf(503));
  h.handlers.focus!(); await settle();
  expect(h.restored).toBe(0);
  expect(h.notified).toEqual([]);
});

test('B1: the caller gets its 401 at once even when the /me confirmation stalls, and the confirm carries a timeout signal', async () => {
  const h = harness('/documents/9', (u) => u.endsWith('/api/v1/me') ? new Promise<Response>(() => {}) : unauthorized());
  const res = await Promise.race([h.fetch('/api/v1/documents/9'), new Promise<string>((r) => setTimeout(() => r('held'), 200))]);
  expect(res).toBeInstanceOf(Response);
  expect((res as Response).status).toBe(401);
  expect(h.notified).toEqual([]);
});

test('B1: the confirm fetch is given an abort signal', async () => {
  const seen: Array<AbortSignal | null | undefined> = [];
  const notified: string[] = [];
  let current: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/api/v1/me')) { seen.push(init?.signal); return new Response('x', { status: 401 }); }
    return new Response('x', { status: 401 });
  }) as typeof fetch;
  const env: SessionExpiryEnv = {
    origin: 'https://hash.test', location: { pathname: '/dashboard', search: '' }, fetch: current, setFetch: (f) => { current = f; },
    visible: () => true, now: () => 1_000_000, listen: () => () => {}, setInterval: () => () => {},
    notifyExpired: (u) => { notified.push(u); }, notifyRestored: () => {}, reload: () => {}
  };
  installSessionExpiryGuard(env);
  await current('/api/v1/documents'); await settle();
  expect(seen.length).toBe(1);
  expect(seen[0]).toBeInstanceOf(AbortSignal);
  expect(notified.length).toBe(1);
});

test('L6: 401s inside the notify window do not each cost a /me round trip', async () => {
  const h = harness('/documents', unauthorized);
  await h.fetch('/api/v1/a'); await settle();
  const before = h.calls.filter((c) => c === '/api/v1/me').length;
  for (let i = 0; i < 5; i++) await h.fetch('/api/v1/b' + i);
  await settle();
  expect(h.calls.filter((c) => c === '/api/v1/me').length).toBe(before);
});

test('N1: without AbortSignal.timeout the caller still gets its 401 and the notice still appears', async () => {
  const real = AbortSignal.timeout;
  (AbortSignal as unknown as { timeout?: unknown }).timeout = undefined;
  try {
    const h = harness('/documents/abc', unauthorized);
    const res = await h.fetch('/api/v1/documents/abc');
    expect(res.status).toBe(401);
    await settle();
    expect(h.notified).toEqual(['/login?next=' + encodeURIComponent('/documents/abc')]);
  } finally { (AbortSignal as unknown as { timeout?: unknown }).timeout = real; }
});

function deferredMe() {
  const waiting: Array<(r: Response) => void> = [];
  const respond = (u: string) => u.endsWith('/api/v1/me') ? new Promise<Response>((r) => { waiting.push(r); }) : unauthorized();
  return { respond, waiting };
}
const meOk = (user = 'user-a') => new Response(JSON.stringify({ user_id: user }), { status: 200 });

test('N4: a slow stale 401 cannot bring the notice back after a newer 200', async () => {
  const d = deferredMe();
  const h = harness('/documents/1', d.respond);
  const stale = h.fetch('/api/v1/me');
  const fresh = h.fetch('/api/v1/me');
  d.waiting[1]!(meOk()); await fresh; await settle();
  expect(h.restored).toBe(1);
  d.waiting[0]!(new Response('unauthorized', { status: 401 })); await stale; await settle();
  expect(h.notified).toEqual([]);
});

test('N4: a slow stale 200 cannot clear a newer expiry', async () => {
  const d = deferredMe();
  const h = harness('/documents/1', d.respond);
  const stale = h.fetch('/api/v1/me');
  const fresh = h.fetch('/api/v1/me');
  d.waiting[1]!(new Response('unauthorized', { status: 401 })); await fresh; await settle();
  expect(h.notified.length).toBe(1);
  d.waiting[0]!(meOk()); await stale; await settle();
  expect(h.restored).toBe(0);
});

test('N5: an expiry right after a restore, inside the dedupe window, is shown again', async () => {
  let answer: () => Response = () => new Response('unauthorized', { status: 401 });
  const h = harness('/documents/1', () => answer());
  await h.fetch('/api/v1/me'); await settle();
  expect(h.notified.length).toBe(1);
  answer = () => meOk(); h.advance(1_000);
  await h.fetch('/api/v1/me'); await settle();
  expect(h.restored).toBe(1);
  answer = () => new Response('unauthorized', { status: 401 }); h.advance(1_000);
  await h.fetch('/api/v1/documents/1'); await settle();
  expect(h.notified.length).toBe(2);
});

test('N2: a different user on the restoring /me reloads instead of clearing the notice', async () => {
  let answer: () => Response = () => meOk('user-a');
  const h = harness('/documents/1', () => answer());
  await h.fetch('/api/v1/me'); await settle();
  answer = () => new Response('unauthorized', { status: 401 }); h.advance(10_000);
  await h.fetch('/api/v1/me'); await settle();
  expect(h.notified.length).toBe(1);
  answer = () => meOk('user-b'); h.advance(10_000);
  await h.fetch('/api/v1/me'); await settle();
  expect(h.reloaded).toBe(1);
  expect(h.restored).toBe(1); // only the first, before the expiry
});

test('N2: the same user on the restoring /me clears the notice without a reload', async () => {
  let answer: () => Response = () => meOk('user-a');
  const h = harness('/documents/1', () => answer());
  await h.fetch('/api/v1/me'); await settle();
  answer = () => new Response('unauthorized', { status: 401 }); h.advance(10_000);
  await h.fetch('/api/v1/me'); await settle();
  answer = () => meOk('user-a'); h.advance(10_000);
  await h.fetch('/api/v1/me'); await settle();
  expect(h.reloaded).toBe(0);
  expect(h.restored).toBe(2);
});

test('N14: the restore has landed by the time the /me response reaches the caller', async () => {
  let answer: () => Response = () => new Response('unauthorized', { status: 401 });
  const h = harness('/documents/1', () => answer());
  await h.fetch('/api/v1/me'); await settle();
  expect(h.notified.length).toBe(1);
  answer = () => meOk();
  await h.fetch('/api/v1/me');
  expect(h.restored).toBe(1); // no settle: "Check again" reads the store right after its await
});

test('N12: a different user on any /me 200 reloads even when no notice was open', async () => {
  let user = 'user-a';
  const h = harness('/documents/1', () => meOk(user));
  await h.fetch('/api/v1/me');
  expect(h.reloaded).toBe(0);
  user = 'user-b'; h.advance(60_000);
  await h.fetch('/api/v1/me');
  expect(h.reloaded).toBe(1);
  expect(h.notified.length).toBe(1); // the notice is up in case the reload is cancelled
});

test('N13: an unreadable /me 200 neither clears the notice nor replaces the known user', async () => {
  let answer: () => Response = () => meOk('user-a');
  const h = harness('/documents/1', () => answer());
  await h.fetch('/api/v1/me');
  answer = () => new Response('unauthorized', { status: 401 }); h.advance(10_000);
  await h.fetch('/api/v1/me');
  expect(h.notified.length).toBe(1);
  const restoredBefore = h.restored;
  for (const body of ['not json', '{"user_id":', '{"user_id":7}', '{"user_id":""}', '']) {
    answer = () => new Response(body, { status: 200 }); h.advance(10_000);
    await h.fetch('/api/v1/me');
  }
  expect(h.restored).toBe(restoredBefore);
  expect(h.reloaded).toBe(0);
  answer = () => meOk('user-b'); h.advance(10_000);
  await h.fetch('/api/v1/me');
  expect(h.reloaded).toBe(1); // still compared against user-a
});

test('N15: reload is attempted once per page load; later different-user results keep the notice', async () => {
  let user = 'user-a';
  const h = harness('/documents/1', () => meOk(user));
  await h.fetch('/api/v1/me');
  user = 'user-b';
  for (let i = 0; i < 4; i++) { h.advance(20_000); await h.fetch('/api/v1/me'); h.handlers.focus!(); await settle(); }
  expect(h.reloaded).toBe(1);
  expect(h.restored).toBe(1); // only the first, before the switch
  expect(h.notified.length).toBe(1);
});
