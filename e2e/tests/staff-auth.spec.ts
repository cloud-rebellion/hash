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


// Native owner sales acceptance with the ordinary measured free plan.
// Reuse real browser sessions, local SMTP and the existing signer ceremony.

async function salesJSON504(page: Page, origin: string, path: string, method = 'GET', body?: unknown, expected = 200): Promise<any> {
  const response = await page.evaluate(async ({ url, method, body, expected }) => {
    const result = await fetch(url, { method, mode: 'cors', credentials: 'include', cache: 'no-store', redirect: 'error',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (result.status !== expected) { await result.body?.cancel(); return { status: result.status, value: null }; }
    return { status: result.status, value: await result.json() };
  }, { url: origin + path, method, body, expected });
  requireCheck(response.status === expected, 'Ordinary sales API request was refused with status ' + response.status);
  return response.value;
}

async function salesPDF504(page: Page, url: string, session: boolean): Promise<{ status: number; valid: boolean; bytes: number; sha256: string }> {
  return page.evaluate(async ({ url, session }) => {
    const response = await fetch(url, { credentials: session ? 'include' : 'omit', cache: 'no-store', redirect: 'error' });
    if (response.status !== 200) { await response.body?.cancel(); return { status: response.status, valid: false, bytes: 0, sha256: '' }; }
    const reader = response.body?.getReader();
    if (!reader) return { status: 200, valid: false, bytes: 0, sha256: '' };
    const chunks: Uint8Array[] = []; let length = 0;
    try {
      while (true) {
        const part = await reader.read(); if (part.done) break;
        length += part.value.byteLength;
        if (length > (16 << 20)) return { status: 200, valid: false, bytes: length, sha256: '' };
        chunks.push(part.value);
      }
    } finally { await reader.cancel(); reader.releaseLock(); }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const valid = (response.headers.get('Content-Type') ?? '').includes('application/pdf') && length > 100 && new TextDecoder().decode(bytes.subarray(0, 5)) === '%PDF-';
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return { status: 200, valid, bytes: length, sha256: Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('') };
  }, { url, session });
}

// Require the actual unique message recipient AND this contract's unique name.
// Link values stay in memory. An invitation returned by Send is insufficient:
// only the existing worker's delivered MailHog message can supply a ceremony.
async function salesMailLink504(request: APIRequestContext, recipient: string, origin: string, contractName: string, path: RegExp): Promise<string> {
  const mailbox = new URL(mailboxURL), deadline = Date.now() + 30_000;
  requireCheck(['http:', 'https:'].includes(mailbox.protocol) && !mailbox.username && !mailbox.password && !mailbox.search && !mailbox.hash && mailbox.pathname === '/', 'Explicit MailHog origin required');
  const expectedOrigin = new URL(origin);
  const diagnostics = { ...mailDiagnostics(), urlParseRejects: 0, originRejects: 0, schemeRejects: 0, hostnameRejects: 0, portRejects: 0,
    queryRejects: 0, hashRejects: 0, pathPatternRejects: 0, signShape43: 0, signShapeOther: 0,
    completedShape43: 0, otherPathShape: 0, htmlEntityCandidates: 0, trailingDelimiterCandidates: 0, percentEncodedPathCandidates: 0 };
  while (Date.now() < deadline) {
    diagnostics.polls++;
    const response = await request.get(mailbox.origin + '/api/v2/messages?limit=100', { timeout: 5_000, maxRedirects: 0 });
    requireCheck(response.status() === 200, 'Sales MailHog receiver unavailable');
    const bytes = await response.body();
    requireCheck(bytes.byteLength <= (4 << 20), 'Sales mailbox exceeded its bounded fixture size');
    const payload = JSON.parse(bytes.toString('utf8'));
    requireCheck(Array.isArray(payload.items) && payload.items.length <= 100, 'Sales mailbox message list is invalid');
    diagnostics.messagesScanned += payload.items.length;
    for (const item of payload.items) {
      const recipients = [
        ...(Array.isArray(item.Raw?.To) ? item.Raw.To.filter((value: unknown) => typeof value === 'string') : []),
        ...(Array.isArray(item.To) ? item.To.filter((value: any) => typeof value?.Mailbox === 'string' && typeof value?.Domain === 'string').map((value: any) => value.Mailbox + '@' + value.Domain) : [])
      ];
      if (!recipients.includes(recipient)) continue;
      diagnostics.recipientMatches++;
      const found = new Set<string>();
      for (const text of authMailTexts(item, diagnostics)) {
        if (!text.includes(contractName)) continue;
        for (const word of text.match(/https?:\/\/[^\s"'<>]+/g) ?? []) {
          diagnostics.urlCandidates++;
          let candidate: URL; try { candidate = new URL(word); } catch { diagnostics.urlParseRejects++; continue; }
          if (word.includes('&#') || word.includes('&amp;')) diagnostics.htmlEntityCandidates++;
          if (/[)\],.;]$/.test(word)) diagnostics.trailingDelimiterCandidates++;
          if (candidate.pathname.includes('%')) diagnostics.percentEncodedPathCandidates++;
          if (/^\/sign\/[A-Za-z0-9_-]{43}$/.test(candidate.pathname)) diagnostics.signShape43++;
          else if (candidate.pathname.startsWith('/sign/')) diagnostics.signShapeOther++;
          else if (/^\/completed\/[A-Za-z0-9_-]{43}$/.test(candidate.pathname)) diagnostics.completedShape43++;
          else diagnostics.otherPathShape++;
          if (candidate.origin !== origin) {
            diagnostics.originRejects++;
            if (candidate.protocol !== expectedOrigin.protocol) diagnostics.schemeRejects++;
            if (candidate.hostname !== expectedOrigin.hostname) diagnostics.hostnameRejects++;
            if (candidate.port !== expectedOrigin.port) diagnostics.portRejects++;
            continue;
          }
          if (candidate.search) { diagnostics.queryRejects++; continue; }
          if (candidate.hash) { diagnostics.hashRejects++; continue; }
          if (!path.test(candidate.pathname)) { diagnostics.pathPatternRejects++; continue; }
          diagnostics.pathCandidates++; found.add(candidate.href);
        }
      }
      requireCheck(found.size <= 1, 'Conflicting sales links appeared in one message');
      if (found.size === 1) return [...found][0];
    }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new MailboxTimeout(diagnostics);
}

// Same ceremony as signing.spec.ts: real Article13 acknowledgement, typed-name
// adoption and explicit confirmation. No sign endpoint is invoked by the test.
async function salesSign504(page: Page, link: string, typedName: string): Promise<void> {
  await page.goto(link);
  const notice = page.getByRole('dialog', { name: 'Before you respond: how we handle your data', exact: true });
  await notice.waitFor({ state: 'visible' });
  requireCheck((await notice.innerText()).includes('fixed 7-year evidence-retention policy'), 'Signer disclosure was not visible');
  await notice.getByRole('button', { name: 'I understand, continue', exact: true }).click();
  await notice.waitFor({ state: 'hidden' });
  requireCheck(await page.getByPlaceholder('Type your full name').inputValue() === typedName, 'Signer identity was not prefilled');
  await page.getByRole('button', { name: 'Adopt and sign', exact: true }).click();
  await page.getByRole('heading', { name: 'Adopt your signature', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Sign with this signature', exact: true }).click();
  await page.getByRole('heading', { name: 'Signed', exact: true }).waitFor({ timeout: 45_000 });
}

test.describe('native staff sales journey', () => {
  test.describe.configure({ retries: 0 });
  // The containing file's existing top-level trace/screenshot/video-off policy
  // applies. This is intentionally a third test with a fresh native account.
  test('native owner creates and sends two-party contract; both parties sign and receive final evidence', async ({ browser, request, baseURL }, testInfo) => {
    test.setTimeout(180_000);
    const contexts: BrowserContext[] = [];
    let stage = 'sales origin preflight';
    let privacyViolation = false;
    const id = randomUUID(), ownerEmail = `sales-owner-${id}@example.test`, ownerPassword = 'Native sales passphrase ' + id;
    const contractName = 'Synthetic two-party contract ' + id;
    const parties = [
      { role: 'signer', name: 'Synthetic Customer', email: `sales-customer-${id}@example.test` },
      { role: 'approver', name: 'Synthetic Provider', email: `sales-provider-${id}@example.test` }
    ];
    try {
      requireCheck(typeof baseURL === 'string', 'Explicit Hash origin required');
      const base = new URL(baseURL), origin = base.origin, localhostHTTP = base.protocol === 'http:' && base.hostname === 'localhost';
      requireCheck(!base.username && !base.password && !base.search && !base.hash && base.pathname === '/' && (base.protocol === 'https:' || localhostHTTP), 'Sales qualification requires HTTPS or exact localhost development');
      const health = await request.get(origin + '/health');
      requireCheck(health.status() === 200 && (!localhostHTTP || health.headers()['x-hash-environment'] === 'development'), 'Ordinary Hash dependencies/profile are not ready');
      const fresh = async () => {
        const context = await browser.newContext({ baseURL: origin }); contexts.push(context);
        await context.route('**/*', async route => {
          if (new URL(route.request().url()).origin !== origin) { privacyViolation = true; await route.abort(); }
          else await route.continue();
        });
        return context;
      };
      const owner = await fresh(), page = await owner.newPage();
      stage = 'native owner registration and delivered mailbox proof';
      await page.goto('/register');
      await page.getByLabel('Your name', { exact: true }).fill('Synthetic Sales Owner');
      await page.getByLabel('Company name', { exact: true }).fill('Synthetic Sales Company');
      await page.getByLabel('Email', { exact: true }).fill(ownerEmail);
      await page.getByLabel('New password', { exact: true }).fill(ownerPassword);
      await page.getByLabel('Confirm password', { exact: true }).fill(ownerPassword);
      await postByButton(page, '/api/v1/auth/register', 'Create workspace', 202);
      const verification = await mailboxLink(request, ownerEmail, origin, '/verify-email');
      await page.goto(verification.href); await page.waitForFunction(() => location.hash === '');
      await page.getByLabel('Password', { exact: true }).fill(ownerPassword);
      await postByButton(page, '/api/v1/auth/verify-email', 'Verify email', 200);
      await atPath(page, '/dashboard'); await hasSessionCookie(owner, origin);
      const account = await identity(page, origin);
      requireCheck(account.role === 'owner', 'Native sales account is not an owner');

      stage = 'ordinary free-plan entitlement and measured catalog preconditions';
      const subscription = await salesJSON504(page, origin, '/api/v1/billing/subscription');
      requireCheck(subscription.billing_enabled === true && subscription.plan?.slug === 'free' && subscription.plan.document_quota_monthly >= 1 && subscription.plan.recipient_quota_monthly >= 2 && subscription.plan.features?.evidence_bundle === false, 'Ordinary measured free entitlement is required; do not upgrade or bypass it for this proof');

      stage = 'cookie-authenticated contract creation';
      const document = await salesJSON504(page, origin, '/api/v1/documents', 'POST', {
        name: contractName, source_kind: 'blocks', variables_json: {}, blocks_json: { version: 1, blocks: [
          { id: 'title', type: 'heading', attrs: { level: 1 }, text: 'Synthetic services agreement' },
          { id: 'terms', type: 'paragraph', text: 'Synthetic Customer and Synthetic Provider agree to the described test services. Both parties must sign this exact contract.' },
          { id: 'customer-signature', type: 'signature_field', attrs: { recipient_role: 'signer', label: 'Customer signature' } },
          { id: 'provider-signature', type: 'signature_field', attrs: { recipient_role: 'approver', label: 'Provider signature' } }
        ] }
      }, 201);
      requireCheck(/^[a-f0-9-]{36}$/i.test(document.id) && document.org_id === account.org_id && document.status === 'draft' && document.source_kind === 'blocks' && document.requires_signature !== false, 'Created contract lost native tenant/draft/signature identity');
      const path = '/api/v1/documents/' + document.id;
      const recipients: any[] = [];
      for (const party of parties) {
        const recipient = await salesJSON504(page, origin, path + '/recipients', 'POST', { ...party, order_index: 0, locale: 'en' }, 201);
        requireCheck(recipient.document_id === document.id && recipient.role === party.role && recipient.email === party.email, 'Persisted signing party differs from the declared party'); recipients.push(recipient);
      }

      stage = 'ordinary send and two actually delivered invitations';
      const sent = await salesJSON504(page, origin, path + '/send', 'POST', { lawful_basis: 'contract' });
      requireCheck(sent.status === 'sent' && Array.isArray(sent.links) && sent.links.length === 2, 'Send did not activate both required parties');
      const sendShape = { ...mailDiagnostics(), sentURLParseRejects: 0, sentOriginRejects: 0, sentQueryRejects: 0, sentHashRejects: 0, sentPathRejects: 0, sentRecipientRejects: 0 };
      for (const link of sent.links) {
        let candidate: URL;
        try { candidate = new URL(link.url); } catch { sendShape.sentURLParseRejects++; continue; }
        if (candidate.origin !== origin) sendShape.sentOriginRejects++;
        if (candidate.search) sendShape.sentQueryRejects++;
        if (candidate.hash) sendShape.sentHashRejects++;
        if (!/^\/sign\/[A-Za-z0-9_-]{43}$/.test(candidate.pathname)) sendShape.sentPathRejects++;
        if (!parties.some(party => party.email === link.email && party.role === link.role)) sendShape.sentRecipientRejects++;
      }
      if (sendShape.sentURLParseRejects || sendShape.sentOriginRejects || sendShape.sentQueryRejects || sendShape.sentHashRejects || sendShape.sentPathRejects || sendShape.sentRecipientRejects) throw new MailboxTimeout(sendShape);
      const invitationPaths: string[] = [];
      for (const party of parties) invitationPaths.push(await salesMailLink504(request, party.email, origin, contractName, /^\/sign\/[A-Za-z0-9_-]+$/));
      requireCheck(invitationPaths[0] !== invitationPaths[1], 'Required parties shared a ceremony credential');
      const customer = await fresh(), customerPage = await customer.newPage();
      const provider = await fresh(), providerPage = await provider.newPage();

      stage = 'first actual browser signature cannot finalize the agreement';
      await salesSign504(customerPage, invitationPaths[0], parties[0].name);
      await customerPage.getByText('Your signature is recorded. The document will finalise once all parties have signed.', { exact: true }).waitFor();
      requireCheck((await salesJSON504(page, origin, path)).status === 'in_progress', 'Contract finalized before the other required party signed');
      requireCheck((await salesPDF504(page, origin + path + '/final-pdf', true)).status === 404, 'A final contract was available after only one signature');

      stage = 'second actual browser signature and final artifacts';
      await salesSign504(providerPage, invitationPaths[1], parties[1].name);
      const finalLink = providerPage.getByRole('link', { name: 'Download signed PDF', exact: true });
      const certificateLink = providerPage.getByRole('link', { name: 'Download audit certificate', exact: true });
      await finalLink.waitFor({ timeout: 45_000 }); await certificateLink.waitFor();
      const finalHref = await finalLink.getAttribute('href'), certificateHref = await certificateLink.getAttribute('href');
      requireCheck(typeof finalHref === 'string' && /^\/sign\/[A-Za-z0-9_-]+\/final-pdf$/.test(finalHref) && typeof certificateHref === 'string' && /^\/sign\/[A-Za-z0-9_-]+\/audit-cert$/.test(certificateHref), 'Fresh bounded artifact links are missing');
      const completed = await salesJSON504(page, origin, path);
      const finalRecipients = await salesJSON504(page, origin, path + '/recipients');
      requireCheck(completed.status === 'completed' && completed.org_id === account.org_id && finalRecipients.recipients?.length === 2 && recipients.every(party => finalRecipients.recipients.some((row: any) => row.id === party.id && row.status === 'signed' && typeof row.signed_at === 'string')), 'Completed document does not retain both actual signatures');
      const ownerPDF = await salesPDF504(page, origin + path + '/final-pdf', true), ownerCertificate = await salesPDF504(page, origin + path + '/audit-cert', true);
      const partyPDF = await salesPDF504(providerPage, origin + finalHref, false), partyCertificate = await salesPDF504(providerPage, origin + certificateHref, false);
      requireCheck(ownerPDF.valid && ownerCertificate.valid && partyPDF.valid && partyCertificate.valid && ownerPDF.sha256 === partyPDF.sha256 && ownerCertificate.sha256 === partyCertificate.sha256, 'Sender and recipient final contract/evidence artifacts differ');
      for (let index = 0; index < invitationPaths.length; index++) requireCheck((await salesPDF504(index ? providerPage : customerPage, invitationPaths[index] + '/final-pdf', false)).status === 404, 'An original mutation credential still downloads completed artifacts');

      stage = 'two-party signing evidence and real completion email';
      const timeline = await salesJSON504(page, origin, path + '/timeline?group=false&emails=false&limit=200');
      const signed = timeline.entries?.filter((entry: any) => entry.kind === 'document.signed') ?? [];
      requireCheck(signed.length === 2 && recipients.every(party => signed.some((entry: any) => entry.recipient_id === party.id)) && timeline.entries.some((entry: any) => entry.kind === 'document.sent') && timeline.entries.some((entry: any) => entry.kind === 'document.completed'), 'Timeline lacks the two distinct signatures and completion');
      await salesMailLink504(request, ownerEmail, origin, contractName, new RegExp('^/api/v1/documents/' + document.id + '/final-pdf$'));
      for (const party of parties) await salesMailLink504(request, party.email, origin, contractName, /^\/completed\/[A-Za-z0-9_-]+$/);
      await noStoredSecrets(page, [ownerPassword, verification.token]);
      requireCheck(!privacyViolation, 'Sales browser attempted external network disclosure');
      await testInfo.attach('native-sales-qualification', { contentType: 'application/json', body: Buffer.from(JSON.stringify({
        schema: 'hash-native-sales-browser-v1', verified: true, plan: 'free', required_parties: 2, actual_browser_signatures: 2,
        final_pdf_bytes: ownerPDF.bytes, final_pdf_sha256: ownerPDF.sha256, certificate_pdf_bytes: ownerCertificate.bytes,
        certificate_pdf_sha256: ownerCertificate.sha256, real_local_completion_mail_recipients: 3,
        qualification: 'cookie-authenticated REST authoring plus actual browser ceremonies and local SMTP; no independent cryptographic verification or production-provider acceptance'
      })) });
    } catch (failure) {
      const counts = failure instanceof MailboxTimeout ? ' mailbox_counts=' + JSON.stringify(failure.diagnostics) : '';
      throw new Error('Native sales qualification failed at: ' + stage + counts);
    } finally { await Promise.allSettled(contexts.map(context => context.close())); }
  });
});
