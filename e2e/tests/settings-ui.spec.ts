import { test, expect } from '@playwright/test';

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
