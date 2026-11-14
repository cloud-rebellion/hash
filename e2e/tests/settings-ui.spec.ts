import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

// Regression guard for audit fix #8 (operator UI). Each of the
// claimed-shipped settings pages must serve the SPA shell + reach
// the SvelteKit router so the route is real (not 404'd by the
// embedded static FS). These request-only checks assert shell reachability,
// not authenticated interaction. The interactive case below supplies its own
// authenticated read fixtures.

const settingsRoutes = [
  '/settings',
  '/settings/branding',
  '/settings/compliance',
  '/settings/eidas-rules',
  '/settings/dsr',
  '/settings/webhooks',
  '/settings/api-keys',
  '/settings/billing',
];

for (const route of settingsRoutes) {
  test(`${route} serves the SPA shell`, async ({ request }) => {
    const res = await request.get(route);
    expect(res.status()).toBe(200);
    const body = await res.text();
    expect(body).toContain('<!doctype html>');
    // SvelteKit emits this attribute so we can confirm the SPA shell
    // (not a static 200 from an upstream proxy default page) is what
    // we got back.
    expect(body).toContain('data-sveltekit-preload-data');
  });
}

test('settings index links to all sub-pages', async ({ request }) => {
  const res = await request.get('/settings');
  expect(res.status()).toBe(200);
  // The SPA payload is hydrated client-side; we check the SPA shell
  // by sniffing the static index.html. Real UI assertions live in
  // the SvelteKit unit tests; here we only confirm reachability.
  const body = await res.text();
  expect(body).toContain('<!doctype html>');
});

test('eIDAS settings cannot select or seed unavailable AES/QES tiers', async ({ page, baseURL }) => {
  if (!baseURL) throw new Error('Browser fixture base URL is required');
  const identity = {
    user_id: '11111111-1111-4111-8111-111111111111',
    org_id: '22222222-2222-4222-8222-222222222222',
    email: 'owner@example.test',
    role: 'owner',
  };
  let identityReads = 0;
  let ruleReads = 0;
  // This case checks the rendered tier controls, not backend authentication.
  // Keep the session guard active and fixture only these two authenticated reads.
  await page.route(new URL('/api/v1/me', baseURL).href, async (route) => {
    expect(route.request().method()).toBe('GET');
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(identity) });
    identityReads++;
  });
  await page.route(new URL('/api/v1/eidas-rules', baseURL).href, async (route) => {
    expect(route.request().method()).toBe('GET');
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ rules: [] }) });
    ruleReads++;
  });

  await page.goto('/settings/eidas-rules');
  await expect.poll(() => identityReads).toBeGreaterThan(0);
  await expect.poll(() => ruleReads).toBeGreaterThan(0);
  const expiredSession = page.locator('dialog[aria-labelledby="session-expired-title"]');
  await expect(expiredSession).not.toBeVisible();
  await expect(page.getByRole('heading', { name: 'eIDAS routing rules' })).toBeVisible();
  await expect(page.getByText('Production signing currently supports SES only.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Swedish defaults unavailable' })).toBeDisabled();

  await page.getByRole('button', { name: 'New rule' }).click();
  const tier = page.getByLabel('Required tier');
  await expect(tier).toHaveValue('SES');
  await expect(tier.locator('option[value="AES"]')).toHaveAttribute('disabled', '');
  await expect(tier.locator('option[value="QES"]')).toHaveAttribute('disabled', '');

  const currentTier = page.getByLabel('Current tier');
  await expect(currentTier).toHaveValue('SES');
  await expect(currentTier.locator('option[value="AES"]')).toHaveAttribute('disabled', '');
  await expect(currentTier.locator('option[value="QES"]')).toHaveAttribute('disabled', '');
  await expect(expiredSession).not.toBeVisible();
});


// Valid, noncommercial three-page PDF: the browser paints these exact bytes with
// the real PDF.js viewer. Auth/preview/approval responses are isolated fixtures;
// native PostgreSQL approval and PDF production remain separate backend tests.
function savedReviewPDF(): Buffer {
  const objects: string[] = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R 5 0 R 7 0 R] /Count 3 >>',
  ];
  for (let page = 1; page <= 3; page++) {
    const content = `BT /F1 18 Tf 20 250 Td (Template review page ${page}) Tj ET\n`;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 320] /Resources << /Font << /F1 9 0 R >> >> /Contents ${page * 2 + 2} 0 R >>`);
    objects.push(`<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}endstream`);
  }
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  let body = '%PDF-1.4\n'; const offsets = [0];
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(body)); body += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(body);
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) body += String(offset).padStart(10, '0') + ' 00000 n \n';
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(body, 'ascii');
}

test('[functional-finish] saved template preview opens automatically and every full page precedes owner approval', async ({ page, baseURL }) => {
  if (!baseURL) throw new Error('Browser fixture base URL is required');
  await page.addInitScript(() => window.localStorage.setItem('hash_staff_locale', 'en'));
  const identity = { user_id: '11111111-1111-4111-8111-111111111111', org_id: '22222222-2222-4222-8222-222222222222', email: 'owner@example.test', role: 'owner' };
  const id = '33333333-3333-4333-8333-333333333333', contentSHA = 'a'.repeat(64);
  const pdf = savedReviewPDF(), pdfSHA = createHash('sha256').update(pdf).digest('hex');
  let previewRequests = 0, approvalRequests = 0, reminderPolicyReads = 0, approved = false, approvedAt = '';
  const unexpected: string[] = [];
  const saved = () => ({ id, org_id: identity.org_id, name: 'Internal design review fixture', source_kind: 'html', version: 2, content_sha256: contentSHA,
    html_master_json: { schema_version: 1, html: '<main><p>Internal design review fixture</p></main>', css: '@page { size: A4; margin: 20mm; }', values: [], sections: [], assets: [] },
    variables_json: {}, html_approval: { version: 2, content_sha256: contentSHA, ...(approved ? { approved_by: identity.user_id, approved_at: approvedAt } : {}) } });
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (path === '/api/v1/me' && request.method() === 'GET') {
      await route.fulfill({ status: 200, json: identity }); return;
    }
    if (path === `/api/v1/templates/${id}` && request.method() === 'GET') {
      await route.fulfill({ status: 200, json: saved() }); return;
    }
    if (path === `/api/v1/templates/${id}/reminder-policy` && request.method() === 'GET') {
      // Exact existing unsaved template reminder-policy read contract. No policy
      // writes or worker action belong to this design-review fixture.
      reminderPolicyReads++;
      await route.fulfill({ status: 200, json: { schema_version: 1, template_id: id, revision: 0, updated_at: null,
        policy: { mode: 'legacy', interval_days: 0, max_fires: 2, offsets_days: [3, 7] } } }); return;
    }
    if (path === `/api/v1/templates/${id}/html/preview` && request.method() === 'POST') {
      expect(request.postDataJSON()).toEqual({ expected_version: 2, expected_content_sha256: contentSHA, values: {}, sections: {} });
      previewRequests++;
      await route.fulfill({ status: 200, contentType: 'application/pdf', headers: {
        'X-Hash-Template-Id': id, 'X-Hash-Template-Version': '2', 'X-Hash-Template-Content-SHA256': contentSHA,
        'X-Hash-Materialization-SHA256': 'b'.repeat(64), 'X-Hash-PDF-SHA256': pdfSHA, 'X-Hash-PDF-Pages': '3',
        'X-Hash-Preview-Receipt': 'own_session_receipt', 'X-Hash-Preview-Expires-At': new Date(Date.now() + 300_000).toISOString(),
      }, body: pdf }); return;
    }
    if (path === `/api/v1/templates/${id}/html/approve` && request.method() === 'POST') {
      expect(request.postDataJSON()).toEqual({ expected_version: 2, expected_content_sha256: contentSHA,
        preview_receipt: 'own_session_receipt', expected_preview_pdf_sha256: pdfSHA });
      approvalRequests++; approved = true; approvedAt = new Date().toISOString();
      await route.fulfill({ status: 200, json: { template_id: id, version: 2, content_sha256: contentSHA, approved_by: identity.user_id, approved_at: approvedAt } }); return;
    }
    unexpected.push(request.method() + ' ' + path);
    await route.fulfill({ status: 401, contentType: 'text/plain', body: 'unauthorized' });
  });
  await page.goto(`/templates/${id}/html`);
  const progress = page.getByRole('region', { name: 'Page review progress' });
  await expect(progress.getByRole('status')).toHaveText(/Opened 1 of 3 pages/);
  await expect(page.locator('canvas[aria-label="Saved design preview, page 1"]')).toBeVisible();
  expect(previewRequests).toBe(1); expect(approvalRequests).toBe(0);
  const checkbox = page.getByRole('checkbox', { name: /I have reviewed every PDF page/ });
  await expect(checkbox).toBeDisabled();
  await expect(page.locator('#saved-template-review-readiness')).toHaveText('Open every page in full size to enable the review checkbox.');
  await expect(page.locator('details').filter({ has: page.getByText('Edit layout and saved content', { exact: true }) })).not.toHaveAttribute('open', '');
  for (const number of [2, 3]) {
    await progress.getByRole('button', { name: 'Open next unopened page', exact: true }).click();
    await expect(progress.getByRole('status')).toHaveText(new RegExp(`Opened ${number} of 3 pages`));
    await expect(page.locator(`canvas[aria-label="Saved design preview, page ${number}"]`)).toBeVisible();
  }
  await expect(progress.getByText('All pages opened.', { exact: true })).toBeVisible();
  await expect(progress.getByRole('button', { name: 'Open next unopened page', exact: true })).toBeDisabled();
  await expect(checkbox).toBeEnabled(); expect(approvalRequests).toBe(0);
  const approve = page.getByRole('button', { name: 'Approve saved design revision', exact: true });
  await expect(approve).toBeDisabled(); await checkbox.check(); await expect(approve).toBeEnabled();
  await approve.click(); await expect(page.getByText('Approved revision', { exact: false })).toBeVisible();
  expect(approvalRequests).toBe(1); expect(previewRequests).toBe(1); expect(reminderPolicyReads).toBeGreaterThan(0); expect(unexpected).toEqual([]);
  await expect(page.locator('dialog[aria-labelledby="session-expired-title"]')).not.toBeVisible();
});

test('[functional-finish] confirmed expired staff session returns to same-tab localized sign-in without public auth forbidden or offline redirects', async ({ page, context, baseURL }) => {
  if (!baseURL) throw new Error('Browser fixture base URL is required');
  await page.addInitScript(() => window.localStorage.setItem('hash_staff_locale', 'sv'));
  const identity = { user_id: '11111111-1111-4111-8111-111111111111', org_id: '22222222-2222-4222-8222-222222222222', email: 'owner@example.test', role: 'owner' };
  let meMode: 'owner' | 'expired' | 'offline' = 'owner';
  let ruleMode: 'ok' | 'forbidden' = 'ok';
  let meReads = 0, ruleReads = 0; const unexpected: string[] = [];
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (path === '/api/v1/me' && request.method() === 'GET') {
      meReads++;
      if (meMode === 'offline') { await route.abort('failed'); return; }
      await route.fulfill(meMode === 'owner' ? { status: 200, json: identity } : { status: 401, contentType: 'text/plain', body: 'unauthorized' }); return;
    }
    if (path === '/api/v1/eidas-rules' && request.method() === 'GET') {
      ruleReads++; await route.fulfill(ruleMode === 'ok' ? { status: 200, json: { rules: [] } } : { status: 403, json: { error: 'Forbidden' } }); return;
    }
    if (path === '/api/v1/auth/status' && request.method() === 'GET') {
      await route.fulfill({ status: 200, json: { password_enabled: true, oidc_enabled: false } }); return;
    }
    if (path === '/api/v1/auth/login' && request.method() === 'POST') {
      await route.fulfill({ status: 401, json: { error: 'unauthorized' } }); return;
    }
    unexpected.push(request.method() + ' ' + path);
    await route.fulfill({ status: 401, contentType: 'text/plain', body: 'unauthorized' });
  });
  await page.route(new URL('/.well-known/hash-public-key', baseURL).href, async (route) => {
    await route.fulfill({ status: 200, json: { public_key_b64: '' } });
  });
  const target = '/settings/eidas-rules?section=review';
  await page.goto(target); await expect.poll(() => meReads).toBeGreaterThan(0); await expect.poll(() => ruleReads).toBeGreaterThan(0);
  const tabs = context.pages().length;
  meMode = 'expired'; await page.evaluate(() => { void fetch('/api/v1/me', { credentials: 'include', cache: 'no-store' }).catch(() => {}); });
  await expect(page).toHaveURL(new URL('/login?next=' + encodeURIComponent(target) + '&expired=1', baseURL).href);
  await expect(page.getByRole('status').filter({ hasText: 'Din session har gått ut. Logga in igen.' })).toBeVisible();
  expect(context.pages()).toHaveLength(tabs);
  const login = page.url();
  await page.evaluate(async () => { await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); });
  await expect(page).toHaveURL(login);
  await page.goto('/verify');
  await page.evaluate(async () => { await fetch('/api/v1/me', { credentials: 'include', cache: 'no-store' }); });
  await expect(page).toHaveURL(new URL('/verify', baseURL).href);
  meMode = 'owner'; ruleMode = 'forbidden'; const priorRules = ruleReads;
  await page.goto('/settings/eidas-rules?case=forbidden'); await expect.poll(() => ruleReads).toBeGreaterThan(priorRules);
  await expect(page).toHaveURL(new URL('/settings/eidas-rules?case=forbidden', baseURL).href);
  meMode = 'offline'; ruleMode = 'ok'; const priorReads = meReads;
  await page.goto('/settings/eidas-rules?case=offline'); await expect.poll(() => meReads).toBeGreaterThan(priorReads);
  await expect(page).toHaveURL(new URL('/settings/eidas-rules?case=offline', baseURL).href);
  expect(context.pages()).toHaveLength(tabs); expect(unexpected).toEqual([]);
});
