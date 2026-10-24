import { test, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';

const mailboxURL = process.env.HASH_MAILHOG_URL || 'http://127.0.0.1:8025';
const acceptedInvitation = 'Invitation request accepted. Eligible accounts receive a password setup email.';

function requireCheck(ok: boolean, message: string): asserts ok {
  if (!ok) throw new Error(message);
}

async function postByButton(page: Page, path: string, button: string, status: number): Promise<void> {
  const completed = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST');
  await page.getByRole('button', { name: button, exact: true }).click();
  const response = await completed;
  requireCheck(response.status() === status, 'Unexpected native account response status');
}

async function atPath(page: Page, path: string): Promise<void> {
  await page.waitForURL(url => url.pathname === path && url.hash === '');
}

// Let Chromium apply and clear real session cookies. The test runner's HTTP
// adapter is not part of the application authentication journey.
async function sessionStatus(page: Page, origin: string): Promise<number> {
  return page.evaluate(async url => {
    const response = await fetch(url, { credentials: 'include', cache: 'no-store', redirect: 'error' });
    await response.body?.cancel();
    return response.status;
  }, origin + '/api/v1/me');
}

async function identity(page: Page, origin: string): Promise<{ org_id: string; role: string }> {
  const value = await page.evaluate(async url => {
    const response = await fetch(url, { credentials: 'include', cache: 'no-store', redirect: 'error' });
    if (response.status !== 200) {
      await response.body?.cancel();
      return { status: response.status, org_id: '', role: '' };
    }
    const identity = await response.json();
    return { status: response.status, org_id: typeof identity?.org_id === 'string' ? identity.org_id : '', role: typeof identity?.role === 'string' ? identity.role : '' };
  }, origin + '/api/v1/me');
  requireCheck(value.status === 200, 'Authenticated account read was refused');
  requireCheck(value.org_id !== '' && value.role !== '', 'Account identity response is incomplete');
  return { org_id: value.org_id, role: value.role };
}

async function hasSessionCookie(context: BrowserContext, origin: string): Promise<void> {
  const cookies = await context.cookies(origin);
  requireCheck(cookies.some(cookie => cookie.name === 'hash_session' && cookie.httpOnly && cookie.secure && cookie.sameSite === 'Strict' && cookie.expires > Date.now() / 1000), 'Browser did not retain the normal secure HttpOnly session cookie');
}

async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await postByButton(page, '/api/v1/auth/login', 'Sign in', 200);
  await atPath(page, '/dashboard');
}

type MailLink = { href: string; token: string };

function mailDiagnostics() {
  return { polls: 0, messagesScanned: 0, recipientMatches: 0, textParts: 0, eightBit: 0, sevenBit: 0, quotedPrintable: 0, base64: 0, otherEncoding: 0, parseRefusals: 0, urlCandidates: 0, pathCandidates: 0, validLinks: 0 };
}
type MailDiagnostics = ReturnType<typeof mailDiagnostics>;
class MailboxTimeout extends Error {
  constructor(readonly diagnostics: MailDiagnostics) { super('Account email link was not found before the mailbox deadline'); }
}

function mimeHeader(headers: unknown, name: string): string {
  if (!headers || typeof headers !== 'object') return '';
  const found = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  const value = found?.[1];
  return typeof value === 'string' ? value : Array.isArray(value) && typeof value[0] === 'string' ? value[0] : '';
}

function splitMime(raw: string): { type: string; encoding: string; body: string } | null {
  const wire = raw.replace(/\r\n/g, '\n'), at = wire.indexOf('\n\n');
  if (at < 0 || at > 16384) return null;
  const headers = wire.slice(0, at).replace(/\n[ \t]+/g, ' ');
  return { type: /^content-type:[ \t]*([^\n]*)/im.exec(headers)?.[1] ?? 'text/plain',
    encoding: /^content-transfer-encoding:[ \t]*([^\n]*)/im.exec(headers)?.[1] ?? '7bit', body: wire.slice(at + 2) };
}

// Parse Hash's bounded multipart/alternative wire, not a concatenation of raw
// and already-parsed views. 8bit parts preserve literal '=ab' token prefixes;
// only a part declaring quoted-printable is decoded, exactly once.
function authMailTexts(item: any, diagnostics: MailDiagnostics): string[] {
  const raw = typeof item.Raw?.Data === 'string' ? item.Raw.Data : '';
  let message = raw ? splitMime(raw) : null;
  if (!message && typeof item.Content?.Body === 'string') {
    message = { type: mimeHeader(item.Content.Headers, 'content-type') || 'text/plain',
      encoding: mimeHeader(item.Content.Headers, 'content-transfer-encoding') || '7bit', body: item.Content.Body };
  }
  if (!message || message.body.length > (256 << 10)) { diagnostics.parseRefusals++; return []; }
  let parts = [message];
  if (/^multipart\/alternative(?:\s*;|$)/i.test(message.type)) {
    const boundary = /;\s*boundary=(?:"([^"\r\n]{1,128})"|([^;\s]{1,128}))/i.exec(message.type);
    if (!boundary) { diagnostics.parseRefusals++; return []; }
    const marker = '--' + (boundary[1] ?? boundary[2]);
    const sections = message.body.replace(/\r\n/g, '\n').split(marker).slice(1);
    if (!sections.length || sections.length > 9) { diagnostics.parseRefusals++; return []; }
    parts = [];
    for (const section of sections) {
      if (section.startsWith('--')) break;
      const part = splitMime(section.replace(/^\n/, ''));
      if (part) parts.push(part); else diagnostics.parseRefusals++;
    }
  }
  const texts: string[] = [];
  for (const part of parts) {
    if (!/^text\/plain(?:\s*;|$)/i.test(part.type)) continue;
    diagnostics.textParts++;
    const encoding = part.encoding.trim().toLowerCase();
    if (encoding === '8bit') { diagnostics.eightBit++; texts.push(part.body); }
    else if (encoding === '7bit' || encoding === '') { diagnostics.sevenBit++; texts.push(part.body); }
    else if (encoding === 'quoted-printable') {
      diagnostics.quotedPrintable++;
      texts.push(part.body.replace(/=\r?\n/g, '').replace(/=([0-9a-f]{2})/gi, (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16))));
    } else if (encoding === 'base64') { diagnostics.base64++; texts.push(Buffer.from(part.body, 'base64').toString('utf8')); }
    else diagnostics.otherEncoding++;
  }
  return texts;
}

// Read the same task-owned MailHog receiver as the existing email suite. Match
// the unique envelope recipient, never a global mail count or a DB-decrypted
// outbox row. The worker must actually deliver this message before we proceed.
async function mailboxLink(request: APIRequestContext, recipient: string, origin: string, path: string): Promise<MailLink> {
  const mailbox = new URL(mailboxURL);
  requireCheck(['http:', 'https:'].includes(mailbox.protocol) && !mailbox.username && !mailbox.password && !mailbox.search && !mailbox.hash && (mailbox.pathname === '/' || mailbox.pathname === ''), 'MailHog must be an explicit receiver origin');
  const deadline = Date.now() + 30_000;
  const diagnostics = mailDiagnostics();
  while (Date.now() < deadline) {
    diagnostics.polls++;
    const response = await request.get(mailbox.origin + '/api/v2/messages?limit=100', { timeout: 5_000, maxRedirects: 0 });
    requireCheck(response.status() === 200, 'MailHog receiver was unavailable');
    const declared = response.headers()['content-length'];
    requireCheck(declared === undefined || (/^[0-9]+$/.test(declared) && Number(declared) <= (4 << 20)), 'MailHog response exceeded the bounded fixture size');
    const raw = await response.body();
    requireCheck(raw.byteLength <= (4 << 20), 'MailHog response exceeded the bounded fixture size');
    const payload = JSON.parse(raw.toString('utf8'));
    requireCheck(payload && Array.isArray(payload.items) && payload.items.length <= 100, 'MailHog response has no bounded message list');
    diagnostics.messagesScanned += payload.items.length;
    for (const item of payload.items) {
      const recipients = [
        ...(Array.isArray(item.Raw?.To) ? item.Raw.To.filter((value: unknown) => typeof value === 'string') : []),
        ...(Array.isArray(item.To) ? item.To.filter((value: any) => typeof value?.Mailbox === 'string' && typeof value?.Domain === 'string').map((value: any) => value.Mailbox + '@' + value.Domain) : [])
      ];
      if (!recipients.includes(recipient)) continue;
      diagnostics.recipientMatches++;
      const links = new Map<string, MailLink>();
      for (const text of authMailTexts(item, diagnostics)) for (const word of text.match(/https?:\/\/[^\s"'<>]+/g) ?? []) {
        diagnostics.urlCandidates++;
        let url: URL;
        try { url = new URL(word); } catch { continue; }
        if (url.origin !== origin || url.pathname !== path || url.search || url.username || url.password) continue;
        diagnostics.pathCandidates++;
        const fragment = new URLSearchParams(url.hash.slice(1)), token = fragment.get('token');
        if ([...fragment.keys()].length !== 1 || !token || !/^[A-Za-z0-9_-]{16,512}$/.test(token)) continue;
        links.set(url.href, { href: url.href, token });
        diagnostics.validLinks++;
      }
      requireCheck(links.size <= 1, 'Auth email contains conflicting account links');
      if (links.size === 1) return [...links.values()][0];
    }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new MailboxTimeout(diagnostics);
}

async function noStoredSecrets(page: Page, secrets: string[]): Promise<void> {
  const privateState = await page.evaluate(values => {
    for (const storage of [localStorage, sessionStorage]) {
      for (let index = 0; index < storage.length; index++) {
        const value = storage.getItem(storage.key(index)!) ?? '';
        if (values.some(secret => secret && value.includes(secret))) return true;
      }
    }
    return document.cookie.includes('hash_session=');
  }, secrets);
  requireCheck(!privateState, 'Account credentials escaped ephemeral fields or HttpOnly storage');
}

// Traces include request bodies and navigations; these real test credentials
// and mailbox links must never enter CI artifacts, even on failure/retry.
test.use({ trace: 'off', screenshot: 'off', video: 'off' });

test.describe('native staff account browser journey', () => {
  test.describe.configure({ retries: 0 });

  test('mail parser preserves 8bit hex-prefix tokens and decodes quoted-printable only once', () => {
    const token = 'ab' + 'x'.repeat(41), url = 'https://localhost/reset-password#token=' + token;
    const wire = (encoding: string, body: string) => ({ Raw: { Data: 'Content-Type: multipart/alternative; boundary="hash-test"\r\n\r\n--hash-test\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: ' + encoding + '\r\n\r\n' + body + '\r\n--hash-test--\r\n' },
      Content: { Body: 'PRIVATE parsed duplicate must not be concatenated' } });
    const plain = mailDiagnostics(), encoded = mailDiagnostics();
    requireCheck(authMailTexts(wire('8bit', url), plain).join('').trim() === url && plain.eightBit === 1 && plain.quotedPrintable === 0, '8bit MIME token prefix was decoded as an escape');
    requireCheck(authMailTexts(wire('quoted-printable', url.replace('token=', 'token=3D')), encoded).join('').trim() === url && encoded.quotedPrintable === 1, 'Quoted-printable token was decoded more than once');
  });

  test('registration, original-password proof, login/logout, recovery and owner invitation', async ({ browser, request, baseURL }, testInfo) => {
    test.setTimeout(90_000);
    let stage = 'origin preflight';
    const contexts: BrowserContext[] = [];
    const id = randomUUID();
    const ownerEmail = `native-owner-${id}@example.test`, viewerEmail = `native-viewer-${id}@example.test`;
    const originalPassword = 'Original native passphrase ' + id, resetPassword = 'Recovered native passphrase ' + id, viewerPassword = 'Recipient chosen passphrase ' + id;
    let privacyViolation = false, authRequests = 0, verifyPosts = 0;
    try {
      requireCheck(typeof baseURL === 'string', 'An explicit Hash browser origin is required');
      const base = new URL(baseURL);
      requireCheck(!base.username && !base.password && !base.search && !base.hash && (base.pathname === '/' || base.pathname === ''), 'Hash browser origin must not contain credentials or additional URL components');
      const localHTTP = base.protocol === 'http:' && base.hostname === 'localhost';
      requireCheck(base.protocol === 'https:' || localHTTP, 'Native auth requires HTTPS, or exact localhost development with actual secure-cookie acceptance');
      const origin = base.origin;
      if (localHTTP) {
        const health = await request.get(origin + '/health');
        requireCheck(health.status() === 200 && health.headers()['x-hash-environment'] === 'development', 'HTTP localhost qualification requires the actual development profile');
      }

      const freshContext = async () => {
        const context = await browser.newContext({ baseURL: origin });
        contexts.push(context);
        context.on('request', sent => {
          try {
            const url = new URL(sent.url());
            if (url.origin !== origin || url.hash || url.searchParams.has('token')) privacyViolation = true;
            if (url.pathname.startsWith('/api/v1/auth/')) authRequests++;
            if (sent.method() === 'POST' && url.pathname === '/api/v1/auth/verify-email') verifyPosts++;
          } catch { privacyViolation = true; }
        });
        await context.route('**/*', async route => {
          if (new URL(route.request().url()).origin !== origin) { privacyViolation = true; await route.abort(); }
          else await route.continue();
        });
        return context;
      };

      const owner = await freshContext(), page = await owner.newPage();
      stage = 'register through the real form';
      await page.goto('/register');
      await page.getByLabel('Your name', { exact: true }).fill('Synthetic Owner');
      await page.getByLabel('Company name', { exact: true }).fill('Synthetic native workspace');
      await page.getByLabel('Email', { exact: true }).fill(ownerEmail);
      await page.getByLabel('New password', { exact: true }).fill(originalPassword);
      await page.getByLabel('Confirm password', { exact: true }).fill(originalPassword);
      await postByButton(page, '/api/v1/auth/register', 'Create workspace', 202);
      await page.getByRole('status').waitFor();
      requireCheck(await sessionStatus(page, origin) === 401, 'Registration activated an unverified account');

      stage = 'unverified login refusal';
      await page.goto('/login');
      await page.getByLabel('Email', { exact: true }).fill(ownerEmail);
      await page.getByLabel('Password', { exact: true }).fill(originalPassword);
      await postByButton(page, '/api/v1/auth/login', 'Sign in', 401);
      await page.getByRole('alert').waitFor();

      stage = 'worker-delivered registration mailbox proof';
      const verification = await mailboxLink(request, ownerEmail, origin, '/verify-email');
      await page.goto(verification.href);
      await page.waitForFunction(() => window.location.hash === '');
      await page.getByRole('button', { name: 'Verify email', exact: true }).waitFor();
      requireCheck(verifyPosts === 0, 'Opening the verification link submitted without original-password proof');
      await page.getByLabel('Password', { exact: true }).fill('Incorrect password ' + id);
      await postByButton(page, '/api/v1/auth/verify-email', 'Verify email', 400);
      await page.getByRole('alert').waitFor();
      requireCheck(await sessionStatus(page, origin) === 401, 'Wrong verification password activated the account');
      await page.getByLabel('Password', { exact: true }).fill(originalPassword);
      await postByButton(page, '/api/v1/auth/verify-email', 'Verify email', 200);
      await atPath(page, '/dashboard');
      const firstIdentity = await identity(page, origin);
      requireCheck(firstIdentity.role === 'owner', 'Verified workspace did not belong to its new owner');
      await hasSessionCookie(owner, origin);
      await noStoredSecrets(page, [originalPassword, verification.token]);

      stage = 'real logout and password login';
      await page.getByRole('button', { name: 'Sign out everywhere', exact: true }).click();
      await atPath(page, '/');
      requireCheck(await sessionStatus(page, origin) === 401, 'Logout left the browser session active');
      await login(page, ownerEmail, originalPassword);
      await hasSessionCookie(owner, origin);
      const second = await freshContext(), secondPage = await second.newPage();
      await login(secondPage, ownerEmail, originalPassword);
      requireCheck((await identity(secondPage, origin)).org_id === firstIdentity.org_id, 'Password login forked the original workspace');

      stage = 'worker-delivered password recovery';
      const recovery = await freshContext(), recoveryPage = await recovery.newPage();
      await recoveryPage.goto('/forgot-password');
      await recoveryPage.getByLabel('Email', { exact: true }).fill(ownerEmail);
      await postByButton(recoveryPage, '/api/v1/auth/forgot-password', 'Send reset instructions', 202);
      await recoveryPage.getByRole('status').waitFor();
      const reset = await mailboxLink(request, ownerEmail, origin, '/reset-password');
      await recoveryPage.goto(reset.href);
      await recoveryPage.waitForFunction(() => window.location.hash === '');
      await recoveryPage.getByLabel('New password', { exact: true }).fill(resetPassword);
      await recoveryPage.getByLabel('Confirm password', { exact: true }).fill(resetPassword);
      await postByButton(recoveryPage, '/api/v1/auth/reset-password', 'Save new password', 200);
      await atPath(recoveryPage, '/login');
      requireCheck(await sessionStatus(page, origin) === 401 && await sessionStatus(secondPage, origin) === 401, 'Password reset retained a prior browser session');
      requireCheck(await sessionStatus(recoveryPage, origin) === 401, 'Password reset signed in before explicit login');
      await recoveryPage.getByLabel('Email', { exact: true }).fill(ownerEmail);
      await recoveryPage.getByLabel('Password', { exact: true }).fill(originalPassword);
      await postByButton(recoveryPage, '/api/v1/auth/login', 'Sign in', 401);
      await recoveryPage.getByRole('alert').waitFor();
      await recoveryPage.getByLabel('Password', { exact: true }).fill(resetPassword);
      await postByButton(recoveryPage, '/api/v1/auth/login', 'Sign in', 200);
      await atPath(recoveryPage, '/dashboard');
      requireCheck((await identity(recoveryPage, origin)).org_id === firstIdentity.org_id, 'Password recovery changed the workspace');
      await hasSessionCookie(recovery, origin);
      await noStoredSecrets(recoveryPage, [originalPassword, resetPassword, reset.token]);

      stage = 'owner invitation through Members';
      await recoveryPage.goto('/settings/members');
      await recoveryPage.getByRole('heading', { name: 'Invite a member', exact: true }).waitFor();
      await recoveryPage.getByLabel('Name', { exact: true }).fill('Synthetic Viewer');
      await recoveryPage.getByLabel('Email', { exact: true }).fill(viewerEmail);
      requireCheck(await recoveryPage.getByLabel('Role', { exact: true }).inputValue() === 'sender', 'Invitation role did not default to sender');
      await recoveryPage.getByLabel('Role', { exact: true }).selectOption('viewer');
      await postByButton(recoveryPage, '/api/v1/members', 'Send invitation', 202);
      await recoveryPage.getByRole('status').filter({ hasText: acceptedInvitation }).waitFor();

      stage = 'recipient-chosen invitation password and login';
      const setup = await mailboxLink(request, viewerEmail, origin, '/reset-password');
      const viewer = await freshContext(), viewerPage = await viewer.newPage();
      await viewerPage.goto(setup.href);
      await viewerPage.waitForFunction(() => window.location.hash === '');
      await viewerPage.getByLabel('New password', { exact: true }).fill(viewerPassword);
      await viewerPage.getByLabel('Confirm password', { exact: true }).fill(viewerPassword);
      await postByButton(viewerPage, '/api/v1/auth/reset-password', 'Save new password', 200);
      await atPath(viewerPage, '/login');
      await viewerPage.getByLabel('Email', { exact: true }).fill(viewerEmail);
      await viewerPage.getByLabel('Password', { exact: true }).fill(viewerPassword);
      await postByButton(viewerPage, '/api/v1/auth/login', 'Sign in', 200);
      await atPath(viewerPage, '/dashboard');
      const viewerIdentity = await identity(viewerPage, origin);
      requireCheck(viewerIdentity.org_id === firstIdentity.org_id && viewerIdentity.role === 'viewer', 'Invitation changed tenant membership or selected role');
      await hasSessionCookie(viewer, origin);
      await noStoredSecrets(viewerPage, [viewerPassword, setup.token]);

      stage = 'viewer owner-action refusal';
      await viewerPage.goto('/settings/members');
      await viewerPage.getByRole('heading', { name: 'Members & roles', exact: true }).waitFor();
      requireCheck(await viewerPage.getByRole('button', { name: 'Send invitation', exact: true }).count() === 0, 'Viewer received an owner invitation control');
      const forbidden = await viewerPage.evaluate(async ({ url, email }) => {
        const response = await fetch(url, { method: 'POST', mode: 'cors', credentials: 'include', cache: 'no-store', redirect: 'error',
          headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, name: 'Forbidden', role: 'owner' }) });
        await response.body?.cancel();
        return response.status;
      }, { url: origin + '/api/v1/members', email: `native-forbidden-${id}@example.test` });
      requireCheck(forbidden === 403, 'Viewer could invoke the owner invitation API');
      requireCheck(!privacyViolation && authRequests <= 20, 'Auth wire privacy or the existing request budget was exceeded');

      stage = 'sanitized qualification receipt';
      await testInfo.attach('native-staff-auth-qualification', {
        contentType: 'application/json',
        body: Buffer.from(JSON.stringify({ schema: 'hash-native-staff-browser-v1', verified: true, development_localhost_http: localHTTP,
          checks: ['registration_pending', 'original_password_proof', 'secure_httponly_strict_cookie', 'password_login', 'logout_revocation', 'worker_mailbox_links', 'reset_revokes_prior_sessions', 'recipient_chosen_setup_password', 'same_org_viewer', 'viewer_owner_api_403', 'ephemeral_credentials'], native_auth_requests: authRequests }))
      });
    } catch (failure) {
      // Browser call logs can contain entered passwords or fragment links.
      // Replace the original exception; do not attach it or preserve a cause.
      const kind = failure instanceof TypeError ? 'TypeError' : failure instanceof SyntaxError ? 'SyntaxError' : 'Error';
      const stack = failure instanceof Error && typeof failure.stack === 'string' ? failure.stack : '';
      const source = /^\s*at\s+[^\r\n]*[\\/]staff-auth\.spec\.ts:(\d{1,5}):(\d{1,5})\)?\s*$/m.exec(stack);
      const location = source ? `staff-auth.spec.ts:${source[1]}:${source[2]}` : 'staff-auth.spec.ts:unknown';
      const mailboxCounts = failure instanceof MailboxTimeout ? ' mailbox_counts=' + JSON.stringify(failure.diagnostics) : '';
      throw new Error('Native staff browser qualification failed at: ' + stage + ' [' + kind + ' ' + location + ']' + mailboxCounts);
    } finally {
      await Promise.allSettled(contexts.map(context => context.close()));
    }
  });
});
