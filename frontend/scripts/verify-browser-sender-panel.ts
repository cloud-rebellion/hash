// Real Go HTTPS/PostgreSQL recipient routes, with actual old responses held for race acceptance.
import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';
const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; cookieName: string; cookie: string; documentAID: string; documentBID: string;
  documentAName: string; documentBName: string; recipientAID: string; recipientAName: string; recipientAEmail: string;
  createdAName: string; createdAEmail: string; createdBName: string; createdBEmail: string; editedBName: string;
  documentAText?: string; documentBText?: string;
};
for (const id of [fixture.documentAID, fixture.documentBID, fixture.recipientAID]) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('Fixture UUID required');
}
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base)) throw new Error('Isolated HTTPS fixture required');
function gate() { let release!: () => void; const promise = new Promise<void>((resolve) => { release = resolve; }); return { promise, release }; }
const initialHeld = gate(), initialRelease = gate(), actionHeld = gate(), actionRelease = gate();
const browser = await chromium.launch({ headless: true });
const errors: string[] = [], mutations: Array<{ method: string; path: string }> = [];
let page: any;
let stage = 'initialization';
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addCookies([{ name: fixture.cookieName, value: fixture.cookie, url: fixture.base,
    httpOnly: true, secure: true, sameSite: 'Lax' }]);
  const meResponse = await context.request.get(`${fixture.base}/api/v1/me`);
  const me = await meResponse.json();
  for (const id of [fixture.documentAID, fixture.documentBID]) {
    const response = await context.request.get(`${fixture.base}/api/v1/documents/${id}`);
    const document = await response.json();
    if (!meResponse.ok() || !response.ok() || document.sender_id !== me.user_id || document.status !== 'draft'
        || document.source_kind !== 'blocks') throw new Error('Two owned draft blocks documents required');
  }
  const recipientsA = `/api/v1/documents/${fixture.documentAID}/recipients`;
  const recipientsB = `/api/v1/documents/${fixture.documentBID}/recipients`;
  let firstRead = true, holdCreate = true;
  page = await context.newPage(); page.setDefaultTimeout(10000);
  page.on('pageerror', (error: Error) => errors.push(error.message));
  page.on('request', (request: any) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/api/v1/documents/') && ['POST', 'PATCH', 'DELETE'].includes(request.method())
        && (path.includes('/recipients') || /\/(send|remind|void)$/.test(path))) {
      mutations.push({ method: request.method(), path });
    }
  });
  await page.route('**/api/v1/documents/**/recipients', async (route: any) => {
    const path = new URL(route.request().url()).pathname;
    if (path === recipientsA && route.request().method() === 'GET' && firstRead) {
      firstRead = false; const response = await route.fetch(); initialHeld.release(); await initialRelease.promise; await route.fulfill({ response });
    } else if (path === recipientsA && route.request().method() === 'POST' && holdCreate) {
      holdCreate = false; const response = await route.fetch(); actionHeld.release(); await actionRelease.promise; await route.fulfill({ response });
    } else await route.continue();
  });
  const panel = page.getByRole('region', { name: 'Recipients and sending', exact: true });
  const form = () => panel.getByRole('heading', { name: /^(New|Edit) recipient$/ }).locator('..');
  async function navigate(id: string, suffix = '') {
    await page.evaluate((href: string) => {
      document.getElementById('sender-navigation-fixture')?.remove();
      const link = document.createElement('a'); link.id = 'sender-navigation-fixture'; link.href = href;
      link.textContent = 'Open fixture document'; document.body.append(link);
    }, `/documents/${id}${suffix}`);
    await page.locator('#sender-navigation-fixture').click();
    if (suffix) await page.waitForURL((url: URL) => url.pathname === `/documents/${id}` && `${url.search}${url.hash}` === suffix);
  }
  async function settle(response: any) {
    await response.finished();
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  }
  async function waitForCleanEditor(id: string) {
    const text = id === fixture.documentAID ? fixture.documentAText : fixture.documentBText;
    if (!text) return;
    await page.locator('.tiptap[contenteditable="true"]').waitFor();
    await page.waitForFunction((expected: string) => {
      const root = document.querySelector('.tiptap');
      if (!root) return false;
      const content = root.cloneNode(true) as HTMLElement;
      content.querySelectorAll('.collaboration-carets__caret,.collaboration-carets__label').forEach((node) => node.remove());
      return content.textContent?.trim() === expected;
    }, text);
    await page.getByText('Saved', { exact: true }).waitFor({ timeout: 15000 });
  }
  async function assertBEmpty() {
    await page.getByRole('heading', { name: fixture.documentBName, exact: true }).waitFor();
    await waitForCleanEditor(fixture.documentBID);
    await panel.getByText('No recipients yet.', { exact: false }).waitFor();
    if (await panel.getByText(fixture.recipientAName, { exact: true }).count()
        || await panel.getByText(fixture.createdAName, { exact: true }).count()
        || await panel.getByRole('heading', { name: /^(New|Edit) recipient$/ }).count()) throw new Error('Old recipients/form painted onto B');
    if (!await page.evaluate(() => (window as any).__senderNavigationMarker === 'same-page')) throw new Error('Navigation used a full reload');
  }
  stage = 'late initial recipients read';
  await page.goto(`${fixture.base}/documents/${fixture.documentAID}`, { waitUntil: 'domcontentloaded' });
  await initialHeld.promise;
  await waitForCleanEditor(fixture.documentAID);
  await page.evaluate(() => { (window as any).__senderNavigationMarker = 'same-page'; });
  await navigate(fixture.documentBID); await assertBEmpty();
  const initialReceipt = page.waitForResponse((response: any) => new URL(response.url()).pathname === recipientsA && response.request().method() === 'GET');
  initialRelease.release(); await settle(await initialReceipt); await assertBEmpty();

  stage = 'existing recipient edit cancellation';
  await navigate(fixture.documentAID);
  await page.getByRole('heading', { name: fixture.documentAName, exact: true }).waitFor();
  await waitForCleanEditor(fixture.documentAID);
  await panel.locator(`[data-recipient-id="${fixture.recipientAID}"]`).getByRole('button', { name: `Edit ${fixture.recipientAName}`, exact: true }).click();
  await form().getByLabel('Name', { exact: true }).fill('Unsent existing recipient rename');
  const cancelDenied = page.waitForEvent('dialog'); const attemptCancel = form().getByRole('button', { name: 'Cancel', exact: true }).click();
  await (await cancelDenied).dismiss(); await attemptCancel;
  if (await form().getByLabel('Name', { exact: true }).inputValue() !== 'Unsent existing recipient rename') throw new Error('Cancelled discard lost recipient edits');
  page.once('dialog', (dialog: any) => dialog.accept()); await form().getByRole('button', { name: 'Cancel', exact: true }).click();
  await panel.getByRole('heading', { name: 'Edit recipient', exact: true }).waitFor({ state: 'hidden' });

  stage = 'draft retention during same-document and preview navigation';
  await panel.getByRole('button', { name: 'Add recipient', exact: true }).click();
  await form().getByLabel('Name', { exact: true }).fill(fixture.createdAName);
  await form().getByLabel('Email', { exact: true }).fill(fixture.createdAEmail);
  await panel.locator('#lawful-basis').selectOption('contract');
  await navigate(fixture.documentAID, '?recipient=review#form');
  if (await form().getByLabel('Name', { exact: true }).inputValue() !== fixture.createdAName
      || await form().getByLabel('Email', { exact: true }).inputValue() !== fixture.createdAEmail
      || await panel.locator('#lawful-basis').inputValue() !== 'contract') throw new Error('Same-document navigation discarded recipient or basis draft');
  await page.getByRole('button', { name: 'Preview', exact: true }).click();
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  if (await form().getByLabel('Name', { exact: true }).inputValue() !== fixture.createdAName) throw new Error('Preview discarded recipient form');
  const cancelled = page.waitForEvent('dialog'); const attemptedNavigation = navigate(fixture.documentBID);
  await (await cancelled).dismiss(); await attemptedNavigation;
  if (new URL(page.url()).pathname !== `/documents/${fixture.documentAID}`
      || await form().getByLabel('Name', { exact: true }).inputValue() !== fixture.createdAName) throw new Error('Cancelled navigation discarded recipient draft');

  stage = 'late submitted recipient receipt';
  await form().getByRole('button', { name: 'Add recipient', exact: true }).click();
  await actionHeld.promise;
  const confirmed = page.waitForEvent('dialog'); const confirmedNavigation = navigate(fixture.documentBID);
  await (await confirmed).accept(); await confirmedNavigation; await assertBEmpty();
  const createReceipt = page.waitForResponse((response: any) => new URL(response.url()).pathname === recipientsA && response.request().method() === 'POST');
  actionRelease.release(); const savedA = await createReceipt;
  if (savedA.status() !== 201) throw new Error('A submitted recipient was not committed');
  await settle(savedA); await assertBEmpty();
  if (await panel.locator('#lawful-basis').inputValue() !== '') throw new Error('A lawful-basis choice crossed documents');

  stage = 'current B create and edit';
  await panel.getByRole('button', { name: 'Add recipient', exact: true }).click();
  await form().getByLabel('Name', { exact: true }).fill(fixture.createdBName);
  await form().getByLabel('Email', { exact: true }).fill(fixture.createdBEmail);
  const createB = page.waitForResponse((response: any) => new URL(response.url()).pathname === recipientsB && response.request().method() === 'POST');
  await form().getByRole('button', { name: 'Add recipient', exact: true }).click();
  const createdResponse = await createB; if (createdResponse.status() !== 201) throw new Error('B recipient create did not commit');
  const created = await createdResponse.json();
  await panel.locator(`[data-recipient-id="${created.id}"]`).getByRole('button', { name: `Edit ${fixture.createdBName}`, exact: true }).click();
  await form().getByLabel('Name', { exact: true }).fill(fixture.editedBName);
  const updateB = page.waitForResponse((response: any) => new URL(response.url()).pathname === `${recipientsB}/${created.id}` && response.request().method() === 'PATCH');
  await form().getByRole('button', { name: 'Save changes', exact: true }).click();
  if ((await updateB).status() !== 200) throw new Error('B recipient edit did not commit');
  await panel.getByText(fixture.editedBName, { exact: true }).waitFor();

  stage = 'current B delete and recreate';
  const deleteB = page.waitForResponse((response: any) => new URL(response.url()).pathname === `${recipientsB}/${created.id}` && response.request().method() === 'DELETE');
  page.once('dialog', (dialog: any) => dialog.accept());
  await panel.locator(`[data-recipient-id="${created.id}"]`).getByRole('button', { name: `Remove ${fixture.editedBName}`, exact: true }).click();
  if ((await deleteB).status() !== 204) throw new Error('B recipient delete did not commit');
  await panel.getByText('No recipients yet.', { exact: false }).waitFor();
  await panel.getByRole('button', { name: 'Add recipient', exact: true }).click();
  await form().getByLabel('Name', { exact: true }).fill(fixture.editedBName);
  await form().getByLabel('Email', { exact: true }).fill(fixture.createdBEmail);
  const recreateB = page.waitForResponse((response: any) => new URL(response.url()).pathname === recipientsB && response.request().method() === 'POST');
  await form().getByRole('button', { name: 'Add recipient', exact: true }).click();
  const recreatedResponse = await recreateB;
  if (recreatedResponse.status() !== 201) throw new Error('B recipient recreate did not commit');
  const recreated = await recreatedResponse.json();
  if (recreated.id === created.id) throw new Error('Deleted recipient identity was reused');
  await panel.locator(`[data-recipient-id="${recreated.id}"]`).getByText(fixture.editedBName, { exact: true }).waitFor();
  if (mutations.length !== 5 || mutations[0].method !== 'POST' || mutations[0].path !== recipientsA
      || mutations[1].method !== 'POST' || mutations[1].path !== recipientsB
      || mutations[2].method !== 'PATCH' || mutations[2].path !== `${recipientsB}/${created.id}`
      || mutations[3].method !== 'DELETE' || mutations[3].path !== `${recipientsB}/${created.id}`
      || mutations[4].method !== 'POST' || mutations[4].path !== recipientsB) throw new Error('Stale panel dispatched a wrong recipient/lifecycle action');
  if (errors.length) throw new Error('Browser exceptions during recipient draft acceptance');
  await page.screenshot({ path: '/private/tmp/hash-browser-sender-panel.png', fullPage: true });
  await Bun.write('/private/tmp/hash-browser-sender-panel-receipt.json', JSON.stringify({
    result: 'pass', documentAID: fixture.documentAID, documentBID: fixture.documentBID,
    recipientBID: recreated.id, deletedRecipientBID: created.id,
    lateInitialReadIgnored: true, editCancelRetainedDraft: true, sameDocumentQueryAndHashRetainedDraft: true,
    previewRetainedRecipientDraft: true, cancelledNavigationRetainedDraft: true, lateCreateReceiptIgnored: true,
    lawfulBasisDidNotCrossDocuments: true, currentDocumentCreateAndEditVerified: true,
    currentDocumentDeleteAndRecreateVerified: true, mutations, browserErrors: errors,
    scope: 'actual Go HTTPS/PostgreSQL recipient APIs and rendered owner forms; delayed real responses, no lifecycle send/SMTP/storage'
  }, null, 2));
  console.log('PASS: recipient drafts survive canceled/same-document/preview navigation, stale responses are isolated and B create/edit/delete/recreate targets B');
} catch (error) {
  console.error('FAILED_STAGE', stage, 'BROWSER_ERROR_COUNT', errors.length);
  if (page) await page.screenshot({ path: '/private/tmp/hash-browser-sender-panel-failed.png', fullPage: true });
  throw error;
} finally { initialRelease.release(); actionRelease.release(); await browser.close(); }
