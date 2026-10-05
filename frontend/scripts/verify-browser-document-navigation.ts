// Real Go HTTPS/PostgreSQL routes; actual responses are delayed and one GET fails for fault acceptance.
import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';

const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; cookieName: string; cookie: string; documentAID: string; documentBID: string;
  documentAName: string; documentBName: string; changeAID: string; changeBID: string;
  documentAText?: string; documentBText?: string; commentAText?: string; commentBText?: string;
  changeAMessage?: string; changeBMessage?: string; newCommentBText?: string;
};
for (const id of [fixture.documentAID, fixture.documentBID, fixture.changeAID, fixture.changeBID]) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) throw new Error('Fixture UUID required');
}
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base)) throw new Error('Isolated HTTPS fixture required');
const browser = await chromium.launch({ headless: true });
const errors: string[] = [];
const mutations: Array<{ method: string; path: string }> = [];
let stage = 'initialization';
let page: any;
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}
const metadataHeld = gate();
const metadataRelease = gate();
const commentsHeld = gate();
const commentsRelease = gate();
const changesHeld = gate();
const changesRelease = gate();
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addCookies([{ name: fixture.cookieName, value: fixture.cookie, url: fixture.base,
    httpOnly: true, secure: true, sameSite: 'Lax' }]);
  const meResponse = await context.request.get(`${fixture.base}/api/v1/me`);
  const me = await meResponse.json();
  for (const id of [fixture.documentAID, fixture.documentBID]) {
    const response = await context.request.get(`${fixture.base}/api/v1/documents/${id}`);
    const document = await response.json();
    if (!meResponse.ok() || !response.ok() || document.sender_id !== me.user_id
        || document.status !== 'changes_requested' || document.source_kind !== 'blocks') {
      throw new Error('Two paused blocks documents belonging to the current sender required');
    }
  }
  const apiA = `/api/v1/documents/${fixture.documentAID}`;
  const apiB = `/api/v1/documents/${fixture.documentBID}`;
  let firstMetadata = true;
  let holdAReads = false;
  let failBRefresh = false;
  let injectedFailures = 0;
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', (error: Error) => errors.push(error.message));
  page.on('request', (request: any) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/api/v1/documents/') && !['GET', 'HEAD'].includes(request.method())) {
      mutations.push({ method: request.method(), path });
    }
  });
  await page.route('**/api/v1/documents/**', async (route: any) => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === 'GET' && path === apiA && firstMetadata) {
      firstMetadata = false;
      const response = await route.fetch();
      metadataHeld.release();
      await metadataRelease.promise;
      await route.fulfill({ response });
    } else if (route.request().method() === 'GET' && holdAReads && path === `${apiA}/comments`) {
      const response = await route.fetch();
      commentsHeld.release();
      await commentsRelease.promise;
      await route.fulfill({ response });
    } else if (route.request().method() === 'GET' && holdAReads && path === `${apiA}/change-requests`) {
      const response = await route.fetch();
      changesHeld.release();
      await changesRelease.promise;
      await route.fulfill({ response });
    } else if (route.request().method() === 'GET' && failBRefresh && path === `${apiB}/change-requests`) {
      failBRefresh = false;
      injectedFailures++;
      await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'Isolated refresh failure' }) });
    } else await route.continue();
  });

  async function navigateDocument(id: string, suffix = '') {
    // SvelteKit intercepts this ordinary internal link, preserving the page instance.
    await page.evaluate((href: string) => {
      document.getElementById('navigation-fixture-link')?.remove();
      const link = document.createElement('a');
      link.id = 'navigation-fixture-link';
      link.href = href;
      link.textContent = 'Open fixture document';
      document.body.append(link);
    }, `/documents/${id}${suffix}`);
    await page.locator('#navigation-fixture-link').click();
    if (suffix) {
      await page.waitForURL((url: URL) => url.pathname === `/documents/${id}` && `${url.search}${url.hash}` === suffix);
    }
  }
  async function settleRenderedResponse(response: any) {
    await response.finished();
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  }
  async function assertB() {
    await page.getByRole('heading', { name: fixture.documentBName, exact: true }).waitFor();
    await page.locator(`[data-change-request-id="${fixture.changeBID}"]`).waitFor();
    if (fixture.commentBText) await page.getByText(fixture.commentBText, { exact: true }).waitFor();
    if (await page.getByRole('heading', { name: fixture.documentAName, exact: true }).count()
        || await page.locator(`[data-change-request-id="${fixture.changeAID}"]`).count()
        || (fixture.commentAText && await page.getByText(fixture.commentAText, { exact: true }).count())) {
      throw new Error('Previous document state appeared on the current route');
    }
    if (!await page.evaluate(() => (window as any).__hashNavigationMarker === 'same-page')) {
      throw new Error('Acceptance used a full reload instead of same-component navigation');
    }
    const previewSource = await page.getByTitle('preview', { exact: true }).getAttribute('src');
    if (previewSource !== `${apiB}/preview`) throw new Error('Current route rendered the previous document preview');
    if (fixture.documentBText) {
      await page.frameLocator('iframe[title="preview"]').getByText(fixture.documentBText, { exact: false }).waitFor();
    }
  }

  stage = 'late initial document response';
  await page.goto(`${fixture.base}/documents/${fixture.documentAID}`, { waitUntil: 'domcontentloaded' });
  await metadataHeld.promise;
  await page.evaluate(() => { (window as any).__hashNavigationMarker = 'same-page'; });
  await navigateDocument(fixture.documentBID);
  await assertB();
  const oldMetadataReceipt = page.waitForResponse((response: any) => new URL(response.url()).pathname === apiA
    && response.request().method() === 'GET');
  metadataRelease.release();
  await settleRenderedResponse(await oldMetadataReceipt);
  await assertB();

  stage = 'unsent draft navigation confirmation';
  holdAReads = true;
  await navigateDocument(fixture.documentAID);
  await page.getByRole('heading', { name: fixture.documentAName, exact: true }).waitFor();
  await Promise.all([commentsHeld.promise, changesHeld.promise]);
  const unsent = 'Retain this A draft when I cancel navigation.';
  await page.getByPlaceholder('Skriv en kommentar…').fill(unsent);
  await navigateDocument(fixture.documentAID, '?review=terms#conversation');
  const sameDocumentURL = new URL(page.url());
  if (sameDocumentURL.search !== '?review=terms' || sameDocumentURL.hash !== '#conversation') {
    throw new Error('Same-document query/hash navigation did not complete');
  }
  if (await page.getByPlaceholder('Skriv en kommentar…').inputValue() !== unsent) {
    throw new Error('Same-document query/hash navigation reset the unsent chat draft');
  }
  const cancelled = page.waitForEvent('dialog');
  const cancelNavigation = navigateDocument(fixture.documentBID);
  await (await cancelled).dismiss();
  await cancelNavigation;
  if (new URL(page.url()).pathname !== `/documents/${fixture.documentAID}`
      || await page.getByPlaceholder('Skriv en kommentar…').inputValue() !== unsent) {
    throw new Error('Cancelled navigation discarded the unsent current-document draft');
  }
  const confirmed = page.waitForEvent('dialog');
  const confirmNavigation = navigateDocument(fixture.documentBID);
  await (await confirmed).accept();
  await confirmNavigation;
  await assertB();
  if (await page.getByPlaceholder('Skriv en kommentar…').inputValue() !== '') {
    throw new Error('Confirmed navigation carried the previous document draft into another conversation');
  }

  stage = 'late previous proposal and conversation responses';
  const oldReplies = [
    page.waitForResponse((response: any) => new URL(response.url()).pathname === `${apiA}/comments`),
    page.waitForResponse((response: any) => new URL(response.url()).pathname === `${apiA}/change-requests`)
  ];
  commentsRelease.release();
  changesRelease.release();
  for (const response of await Promise.all(oldReplies)) await settleRenderedResponse(response);
  await assertB();

  stage = 'failed proposal refresh retains list and retries';
  failBRefresh = true;
  await page.getByRole('button', { name: 'Refresh change requests', exact: true }).click();
  const failure = page.getByRole('alert').filter({ hasText: 'Change requests could not be refreshed.' });
  await failure.waitFor();
  await page.locator(`[data-change-request-id="${fixture.changeBID}"]`).waitFor();
  if (fixture.changeBMessage) await page.getByText(fixture.changeBMessage, { exact: true }).waitFor();
  await failure.getByRole('button', { name: 'Retry change request refresh', exact: true }).click();
  await failure.waitFor({ state: 'hidden' });
  await assertB();

  stage = 'current document conversation and proposal actions';
  const newComment = fixture.newCommentBText ?? 'Current B negotiation reply';
  await page.getByPlaceholder('Skriv en kommentar…').fill(newComment);
  const commentReceipt = page.waitForResponse((response: any) => new URL(response.url()).pathname === `${apiB}/comments`
    && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Skicka kommentar', exact: true }).click();
  if ((await commentReceipt).status() !== 201) throw new Error('Current document comment did not commit');
  await page.getByText(newComment, { exact: true }).waitFor();
  const denyPath = `${apiB}/change-requests/${fixture.changeBID}/deny`;
  const denied = page.waitForResponse((response: any) => new URL(response.url()).pathname === denyPath);
  await page.locator(`[data-change-request-id="${fixture.changeBID}"]`).getByRole('button', { name: 'Neka', exact: true }).click();
  if ((await denied).status() !== 200) throw new Error('Current document proposal denial did not commit');
  await page.locator(`[data-change-request-id="${fixture.changeBID}"]`).getByText('nekad', { exact: true }).waitFor();
  await assertB();
  if (mutations.length !== 2 || mutations[0].path !== `${apiB}/comments` || mutations[1].path !== denyPath) {
    throw new Error('Navigation dispatched a mutation for the previous or wrong document');
  }
  if (errors.length) throw new Error('Browser exceptions during navigation');
  await page.screenshot({ path: '/private/tmp/hash-browser-document-navigation.png', fullPage: true });
  await Bun.write('/private/tmp/hash-browser-document-navigation-receipt.json', JSON.stringify({
    result: 'pass', documentAID: fixture.documentAID, documentBID: fixture.documentBID,
    samePageNavigation: true, lateInitialReadIgnored: true, lateProposalAndCommentReadsIgnored: true,
    cancelledNavigationRetainedChatDraft: true, confirmedNavigationDiscardedOnlyAcknowledgedDraft: true,
    sameDocumentQueryAndHashRetainedChatDraft: true,
    retainedProposalListDuringRefreshFailure: true, retryRecovered: true, injectedRefreshFailures: injectedFailures,
    mutations, browserErrors: errors,
    scope: 'actual Go HTTPS/PostgreSQL sender routes and rendered component reuse; delayed real responses and one injected GET503'
  }, null, 2));
  console.log('PASS: same-component document navigation fences late reads, protects unsent draft, retains failed proposal refresh and directs actions to current document');
} catch (error) {
  console.error('FAILED_STAGE', stage, 'BROWSER_ERROR_COUNT', errors.length);
  if (page) await page.screenshot({ path: '/private/tmp/hash-browser-document-navigation-failed.png', fullPage: true });
  throw error;
} finally {
  metadataRelease.release();
  commentsRelease.release();
  changesRelease.release();
  await browser.close();
}
