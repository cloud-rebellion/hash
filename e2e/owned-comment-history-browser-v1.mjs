import { chromium, expect } from '@playwright/test';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== '00000000-0000-0000-0000-000000000000';
const fail = message => { throw new Error(message); };
export async function ownedChatResponseJSONV1(response, expectedStatus, kind) {
  if (!['identity', 'comment-post', 'history', 'view'].includes(kind)) fail('invalid response class');
  if (response.status() !== expectedStatus) fail(`native ${kind} status ${response.status()}`);
  return response.json();
}
export function validateOwnedChatHandoffV1(value) {
  if (!value || typeof value !== 'object' || !value.packet) fail('invalid chat handoff');
  const p = value.packet; let base;
  try { base = new URL(p.base); } catch { fail('invalid chat origin'); }
  if (base.protocol !== 'https:' || base.hostname !== '127.0.0.1' || !base.port || base.origin !== p.base || base.pathname !== '/' || base.search || base.hash || base.username || base.password) fail('invalid chat origin');
  if (![p.documentID, p.orgID, p.ownerID, p.recipientID].every(uuid) || new Set([p.documentID, p.orgID, p.ownerID, p.recipientID]).size !== 4) fail('invalid chat identities');
  if (typeof p.token !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(p.token)) fail('invalid chat credential');
  const c = p.cookie;
  if (!c || c.name !== 'hash_session' || typeof c.value !== 'string' || c.value.length < 32 || c.value.length > 8192 || /[\s;\x00-\x1f]/.test(c.value) || c.httpOnly !== true || c.secure !== true || c.sameSite !== 'Strict' || !Number.isSafeInteger(c.expires) || c.expires <= Date.now() / 1000) fail('invalid owned cookie');
  if (!/^sha256:[0-9a-f]{64}$/.test(p.rendererImageID) || p.rendererVersion !== '8.36.0-hash.5') fail('invalid renderer provenance input');
  if (!Array.isArray(p.comments) || p.comments.length !== 105) fail('exact native seed required');
  const ids = new Set();
  p.comments.forEach((r, i) => { if (!r || !uuid(r.id) || ids.has(r.id) || r.body !== `Owned seeded comment ${String(i + 1).padStart(3, '0')} ÅÄÖ`) fail('invalid native seeded rows'); ids.add(r.id); });
  for (const p of [value.donePath, value.artifacts]) if (typeof p !== 'string' || !path.isAbsolute(p) || path.normalize(p) !== p || p === path.parse(p).root) fail('invalid private output path');
  if (value.donePath === value.artifacts) fail('output paths collide');
  return value;
}

async function readBootstrap() {
  let size = 0; const chunks = [];
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 65536) fail('private handoff exceeds bound'); chunks.push(chunk); }
  return validateOwnedChatHandoffV1(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}
export async function runOwnedChatBrowserV1(bootstrap) {
  validateOwnedChatHandoffV1(bootstrap);
  const { packet: p, donePath, artifacts } = bootstrap;
  try { await fs.lstat(donePath); fail('completion already exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  await fs.mkdir(artifacts, { recursive: true, mode: 0o700 });
  await fs.chmod(artifacts, 0o700);
  const deadline = Date.now() + 145000;
  const remaining = (cap = 20000) => { const n = Math.min(cap, deadline - Date.now()); if (n <= 0) fail('browser deadline'); return n; };
  const consoleFacts = [];
  const errors = [], observations = [], posted = [], allRows = [...p.comments];
  let currentPostGate = null;
  let browser, verified = false, closed = false, foreignRequests = 0, failure = null, timedOut = false;
  const timer = setTimeout(() => { timedOut = true; void browser?.close().catch(() => {}); }, 145000);
  const redact = value => String(value).replaceAll(p.token, '[recipient]').replaceAll(p.cookie.value, '[session]').replace(/\/sign\/[^\s/?"']+/g, '/sign/[recipient]');
  try {
    browser = await chromium.launch({ headless: true, timeout: remaining(30000) });
    for (const role of ['staff', 'signer']) {
      const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1200 }, locale: 'en-US' });
      context.setDefaultTimeout(remaining());
      await context.addInitScript(() => { window.__ownedChatCSP = []; window.addEventListener('securitypolicyviolation', e => window.__ownedChatCSP.push(e.violatedDirective)); });
      if (role === 'staff') {
        await context.addCookies([{ ...p.cookie, url: p.base + '/' }]);
        const cookies = await context.cookies(p.base);
        if (!cookies.some(c => c.name === p.cookie.name && c.value === p.cookie.value && c.httpOnly && c.secure && c.sameSite === 'Strict')) fail('owned browser cookie differs');
        const identity = await context.request.get(p.base + '/api/v1/me', { timeout: remaining() }); const me = await ownedChatResponseJSONV1(identity, 200, 'identity');
        if (identity.status() !== 200 || me.user_id !== p.ownerID || me.org_id !== p.orgID || me.role !== 'owner') fail('actual owned membership differs');
      }
      const page = await context.newPage();
      const commentsPath = role === 'staff' ? `/api/v1/documents/${p.documentID}/comments` : `/sign/${p.token}/comments`;
      const faults = []; let olderFault = false, latestFault = false, postCount = 0, postGate = null;
      const responseMatches = r => new URL(r.url()).origin === p.base && new URL(r.url()).pathname === commentsPath && r.request().method() === 'GET';
      const nextResponse = () => { const response = page.waitForResponse(responseMatches, { timeout: remaining() }); response.catch(() => {}); return response; };
      const viewMatches = request => { const url = new URL(request.url()); return role === 'signer' && url.origin === p.base && url.pathname === `/sign/${p.token}/view` && !url.search && request.method() === 'POST'; };
      let viewPosts = 0;
      page.on('request', request => { if (viewMatches(request)) viewPosts++; });
      const viewResponse = role === 'signer' ? page.waitForResponse(response => viewMatches(response.request()), { timeout: remaining(145000) }) : null;
      viewResponse?.catch(() => {});
      page.on('pageerror', () => errors.push(role + ':pageerror'));
      page.on('console', m => {
        if (m.type() !== 'error') return;
        const location = m.location();
        const expected = faults.find(f => !f.console && location.url === f.url && /503/.test(m.text()));
        if (consoleFacts.length < 64) consoleFacts.push({ role, expected: !!expected, location: redact(location.url).slice(0, 512), text: redact(m.text()).slice(0, 2048) });
        if (expected) expected.console = true; else errors.push(role + ':unexpected-console-error');
      });
      await context.route('**/*', async route => {
       try {
        const request = route.request(), u = new URL(request.url());
        if (['http:', 'https:'].includes(u.protocol) && u.origin !== p.base) { foreignRequests++; await route.abort(); return; }
        if (u.pathname === commentsPath && request.method() === 'GET' && ((olderFault && u.searchParams.has('before')) || (latestFault && !u.search))) {
          if (u.searchParams.has('before')) olderFault = false; else latestFault = false;
          faults.push({ url: request.url(), console: false });
          await route.fulfill({ status: 503, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' }, body: '{"error":"Owned injected history failure"}' }); return;
        }
        if (u.pathname === commentsPath && request.method() === 'POST') {
          postCount++;
          if (!postGate || postCount !== 1) { errors.push(role + ':unexpected-post'); await route.abort(); return; }
          const response = await route.fetch({ timeout: remaining(), maxRedirects: 0, maxRetries: 0 });
          const row = await ownedChatResponseJSONV1(response, 201, 'comment-post');
          if (response.status() !== 201 || !uuid(row.id) || row.body !== `Owned browser ${role} message ÅÄÖ`) fail('actual native POST contract differs');
          postGate.resolve({ row: { id: row.id, body: row.body } });
          await postGate.release;
          latestFault = true;
          await route.fulfill({ response }); return;
        }
        await route.continue();
       } catch {
         errors.push(role + ':route-handler-failed'); postGate?.reject(new Error('native POST dispatch failed'));
         try { await route.abort(); } catch {}
       }
      });
      const initial = nextResponse(); initial.catch(() => {});
      await page.goto(p.base + (role === 'staff' ? `/documents/${p.documentID}` : `/sign/${p.token}`), { waitUntil: 'domcontentloaded', timeout: remaining() });
      if (role === 'signer') {
        const notice = page.getByRole('dialog', { name: 'Before you respond: how we handle your data' });
        await expect(notice).toBeVisible({ timeout: remaining() });
        await notice.getByRole('button', { name: 'I understand, continue' }).click();
        await expect(notice).toBeHidden({ timeout: remaining() });
      } else if ((await page.evaluate(() => document.cookie)).includes(p.cookie.name + '=')) fail('session exposed to script');
      const section = role === 'staff' ? page.locator('section').filter({ has: page.getByRole('heading', { name: 'Kommentarer', exact: true }) }) : page.locator('.comments');
      const bodies = role === 'staff' ? section.locator('ul li p.whitespace-pre-wrap') : section.locator('ul li .comment-body');
      const nav = section.getByRole('navigation', { name: 'Message history' });
      const draft = section.locator('textarea');
      await expect(nav).toBeVisible({ timeout: remaining() });
      const draftText = `Unsent ${role} draft ÅÄÖ`;
      async function verifyWindow(response, expected) {
        const body = await ownedChatResponseJSONV1(response, 200, 'history');
        if (response.status() !== 200 || !response.headers()['cache-control']?.includes('no-store') || !Array.isArray(body.comments) || JSON.stringify(body.comments.map(r => ({ id: r.id, body: r.body }))) !== JSON.stringify(expected)) fail('actual native history window differs');
        await expect(bodies).toHaveText(expected.map(r => r.body), { timeout: remaining() });
        await expect(draft).toHaveValue(draftText, { timeout: remaining() });
        return body;
      }
      await draft.fill(draftText);
      let window = await verifyWindow(await initial, allRows.slice(-50));
      async function select(name, expected) {
        const pending = nextResponse();
        await nav.getByRole('button', { name, exact: true }).click();
        return verifyWindow(await pending, expected);
      }
      window = await select('Older', allRows.slice(-100, -50));
      const oldestEnd = allRows.length - 100;
      window = await select('Older', allRows.slice(0, oldestEnd));
      await expect(nav.getByRole('button', { name: 'Older', exact: true })).toBeDisabled();
      window = await select('Newer', allRows.slice(oldestEnd, oldestEnd + 50));
      window = await select('Newer', allRows.slice(-50));
      await expect(nav.getByRole('button', { name: 'Newer', exact: true })).toBeDisabled();
      olderFault = true;
      const failed = nextResponse();
      await nav.getByRole('button', { name: 'Older', exact: true }).click();
      const failedResponse = await failed; if (failedResponse.status() !== 503) fail('owned older fault not exercised');
      const exactFailedURL = failedResponse.url();
      await expect(section.getByRole('alert')).toContainText('could not be refreshed', { timeout: remaining() });
      await expect(bodies).toHaveText(allRows.slice(-50).map(r => r.body)); await expect(draft).toHaveValue(draftText);
      const retry = nextResponse();
      await section.getByRole('button', { name: 'Retry message refresh', exact: true }).click();
      const retried = await retry; if (retried.url() !== exactFailedURL) fail('retry selection changed');
      await verifyWindow(retried, allRows.slice(-100, -50));
      await select('Latest', allRows.slice(-50));
      await page.screenshot({ path: path.join(artifacts, role + '-history.png'), fullPage: true, timeout: remaining() });
      let resolvePost, rejectPost, releasePost;
      const dispatched = new Promise((resolve, reject) => { resolvePost = resolve; rejectPost = reject; });
      dispatched.catch(() => {});
      const release = new Promise(resolve => { releasePost = resolve; });
      postGate = { resolve: resolvePost, reject: rejectPost, release, unblock: releasePost };
      currentPostGate = postGate;
      await draft.fill(`Owned browser ${role} message ÅÄÖ`);
      await section.getByRole('button', { name: role === 'staff' ? 'Skicka kommentar' : 'Send comment', exact: true }).click();
      let postTimer; let outcome;
      try { outcome = await Promise.race([dispatched, new Promise((_, reject) => { postTimer = setTimeout(() => reject(new Error('native POST did not reach its held response')), remaining()); })]); }
      finally { clearTimeout(postTimer); }
      const { row } = outcome;
      await draft.fill(draftText);
      const latestFailed = nextResponse();
      releasePost(); const latestResponse = await latestFailed;
      if (latestResponse.status() !== 503 || new URL(latestResponse.url()).search) fail('owned Latest fault not exercised');
      await expect(section.getByRole('alert')).toContainText('could not be refreshed', { timeout: remaining() });
      await expect(draft).toHaveValue(draftText); await expect(bodies).toHaveText(allRows.slice(-50).map(r => r.body));
      const refreshed = nextResponse();
      await section.getByRole('button', { name: 'Retry message refresh', exact: true }).click();
      allRows.push(row); await verifyWindow(await refreshed, allRows.slice(-50));
      await expect.poll(() => faults.filter(f => f.console).length, { timeout: remaining(1000) }).toBe(2);
      if (postCount !== 1 || faults.length !== 2 || faults.some(f => !f.console)) fail('exact POST/fault console accounting differs');
      const csp = await page.evaluate(() => window.__ownedChatCSP);
      if (csp.length) fail('actual CSP violation');
      if (role === 'signer') {
        await expect(page.locator('.pdf-signer')).toHaveAttribute('data-pdf-ready', 'true', { timeout: remaining() });
        await expect(page.locator('.pdf-signer canvas').first()).toBeVisible({ timeout: remaining() });
        const rendered = await page.locator('.pdf-signer').evaluate(element => ({
          pages: Number(element.getAttribute('data-pdf-page-count')),
          canvases: [...element.querySelectorAll('canvas')].map(canvas => ({ width: canvas.width, height: canvas.height }))
        }));
        if (!Number.isInteger(rendered.pages) || rendered.pages < 1 || rendered.canvases.length !== rendered.pages
          || rendered.canvases.some(canvas => canvas.width < 1 || canvas.height < 1)) fail('complete rendered PDF pages required');
        const view = await ownedChatResponseJSONV1(await viewResponse, 200, 'view');
        if (view.ok !== true || view.status !== 'viewed' || viewPosts !== 1) fail('exact native rendered view confirmation differs');
      }
      await page.screenshot({ path: path.join(artifacts, role + '-retry.png'), fullPage: true, timeout: remaining() });
      posted.push(row);
      observations.push({ role, initial_count: allRows.length - 1, verified_windows: 5, exact_failed_older_retry: true, native_posts: postCount, followup_get_retry_only: true, newer_draft_preserved: true, expected_503_console_errors: faults.length, current_rows: allRows.length, native_view_posts: viewPosts, view_confirmed: role === 'signer' });
      await context.close();
    }
    if (errors.length || foreignRequests || timedOut) fail('browser security or runtime gate failed');
    await browser.close(); closed = true; verified = true;
  } catch (e) { failure = redact(e.message); }
  finally {
    currentPostGate?.unblock();
    if (browser && !closed) { try { await browser.close(); closed = true; } catch { errors.push('browser-close-failed'); } }
    clearTimeout(timer);
    verified = verified && closed && !timedOut && errors.length === 0 && foreignRequests === 0;
    await fs.writeFile(path.join(artifacts, 'browser-receipt.json'), JSON.stringify({ result: verified ? 'pass' : 'fail', failure, observations, browser_errors: errors, console_facts: consoleFacts, foreign_request_attempts: foreignRequests, browser_close_returned: closed, timed_out: timedOut, renderer_version: p.rendererVersion, renderer_image_id_supplied_by_root: p.rendererImageID }, null, 2), { mode: 0o600, flag: 'wx' });
    await fs.writeFile(donePath, JSON.stringify({ exit_code: verified ? 0 : 1, verified, posted }), { mode: 0o600, flag: 'wx' });
  }
  if (!verified) fail('owned chat browser rejected journey');
  return { result: 'pass', portals: 2, native_browser_posts: posted.length };
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { console.log(JSON.stringify(await runOwnedChatBrowserV1(await readBootstrap()))); }
  catch { console.error('owned chat browser qualification failed'); process.exitCode = 1; }
}
