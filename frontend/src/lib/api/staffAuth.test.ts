import { expect, test } from 'bun:test';
import { getStaffAuthStatus, loginWithPassword, registerWorkspace, verifyStaffEmail, forgotStaffPassword, resetStaffPassword, staffAuthErrorMessage } from './staffAuth';

async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: (path: string) => Response | Promise<Response>) {
  const saved = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options: RequestInit = {}) => { calls.push({ path: String(path), options }); return respond(String(path)); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = saved; }
}

test('native account transport uses fixed JSON POSTs, HttpOnly-cookie credentials and exact success statuses', async () => {
  const signal = new AbortController().signal, token = 'PRIVATE_TOKEN_'.repeat(4), password = ' unchanged password ';
  await mocked(async calls => {
    expect(await getStaffAuthStatus(signal)).toEqual({ password_enabled: true, oidc_enabled: false });
    await loginWithPassword('owner@example.test', password, signal);
    await registerWorkspace('owner@example.test', 'Owner', 'Company', password, signal);
    await verifyStaffEmail(token, password, signal);
    await forgotStaffPassword('owner@example.test', signal);
    await resetStaffPassword(token, password, signal);
    expect(calls.map(c => [c.path, c.options.method])).toEqual([
      ['/api/v1/auth/status', 'GET'], ['/api/v1/auth/login', 'POST'], ['/api/v1/auth/register', 'POST'],
      ['/api/v1/auth/verify-email', 'POST'], ['/api/v1/auth/forgot-password', 'POST'], ['/api/v1/auth/reset-password', 'POST']
    ]);
    expect(calls.every(c => c.options.credentials === 'include' && c.options.cache === 'no-store' && c.options.redirect === 'error' && c.options.signal === signal && !c.path.includes(token) && !c.path.includes(password))).toBe(true);
    expect(calls.slice(1).map(c => JSON.parse(c.options.body as string))).toEqual([
      { email: 'owner@example.test', password }, { email: 'owner@example.test', name: 'Owner', company_name: 'Company', password },
      { token, password }, { email: 'owner@example.test' }, { token, password }
    ]);
  }, path => path.endsWith('/status') ? Response.json({ password_enabled: true, oidc_enabled: false }) : Response.json({}, { status: path.endsWith('/register') || path.endsWith('/forgot-password') ? 202 : 200 }));
});

test('account refusal and network errors never read or expose private upstream bodies', async () => {
  for (const status of [200, 202, 401, 403, 429, 500]) {
    await mocked(async () => {
      if (status === 200) { await loginWithPassword('a@example.test', 'x', new AbortController().signal); return; }
      let refused = false;
      try { await loginWithPassword('a@example.test', 'x', new AbortController().signal); }
      catch (error) { refused = true; expect(staffAuthErrorMessage(error)).not.toContain('PRIVATE'); }
      expect(refused).toBe(true);
    }, () => new Response('PRIVATE token=password', { status }));
  }
  await mocked(async () => {
    await expect(loginWithPassword('a@example.test', 'x', new AbortController().signal)).rejects.toThrow('Hash could not complete');
  }, () => { throw new Error('PRIVATE network URL'); });
  const aborted = new AbortController(); aborted.abort();
  await mocked(async calls => {
    await expect(verifyStaffEmail('x'.repeat(43), 'original password', aborted.signal)).rejects.toThrow(); expect(calls).toHaveLength(0);
  }, () => Response.json({}));
});

test('SSO appears available only from the exact bounded typed status response', async () => {
  for (const response of [
    () => Response.json({ password_enabled: true, oidc_enabled: 'true' }),
    () => Response.json({ password_enabled: true, oidc_enabled: true, private_token: 'PRIVATE' }),
    () => Response.json({ password_enabled: false, oidc_enabled: true }),
    () => new Response('<html>PRIVATE</html>', { headers: { 'Content-Type': 'text/html' } }),
    () => new Response('{broken', { headers: { 'Content-Type': 'application/json' } }),
    () => new Response(' '.repeat(1025), { headers: { 'Content-Type': 'application/json' } })
  ]) await mocked(async () => { await expect(getStaffAuthStatus(new AbortController().signal)).rejects.toThrow(); }, response);
  await mocked(async () => { expect((await getStaffAuthStatus(new AbortController().signal)).oidc_enabled).toBe(true); }, () => Response.json({ password_enabled: true, oidc_enabled: true }));
});
