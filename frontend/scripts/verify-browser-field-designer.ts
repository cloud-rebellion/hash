import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';

const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; cookieName: string; cookie: string; documentAID: string; documentBID: string;
  documentAName: string; documentBName: string; recipientAID: string; recipientBID: string;
  recipientCName: string; recipientCEmail: string;
};
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base)) throw new Error('Isolated HTTPS fixture required');
if (typeof fixture.recipientCName !== 'string' || !fixture.recipientCName.trim()
    || typeof fixture.recipientCEmail !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(fixture.recipientCEmail)) {
  throw new Error('Synthetic recipient sync inputs required');
}
for (const id of [fixture.documentAID, fixture.documentBID, fixture.recipientAID, fixture.recipientBID]) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('Synthetic UUID required');
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}
const readHeld = gate(), readRelease = gate(), readDelivered = gate(), saveHeld = gate(), saveRelease = gate(), saveDelivered = gate();
const browser = await chromium.launch({ headless: true });
const errors: string[] = [], mutations: Array<{method: string; path: string}> = [];
let stage = 'initialization', context: any, page: any;
const fieldsA = `/api/v1/documents/${fixture.documentAID}/fields`;
const fieldsB = `/api/v1/documents/${fixture.documentBID}/fields`;
const recipientsB = `/api/v1/documents/${fixture.documentBID}/recipients`;
try {
  context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addCookies([{ name: fixture.cookieName, value: fixture.cookie, url: fixture.base, httpOnly: true, secure: true, sameSite: 'Strict' }]);
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', (error: Error) => errors.push(error.message));
  await page.addInitScript(() => {
    (window as any).__fieldCspViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      (window as any).__fieldCspViolations.push({ directive: event.effectiveDirective, blocked: event.blockedURI });
    });
  });
  page.on('request', (request: any) => {
    const path = new URL(request.url()).pathname;
    if (['POST', 'PATCH', 'DELETE'].includes(request.method()) && path.startsWith('/api/v1/')) {
      mutations.push({ method: request.method(), path });
    }
  });
  let holdRead = true, holdSave = true;
  await page.route(`${fixture.base}${fieldsA}`, async (route: any) => {
    const method = route.request().method();
    if (method === 'GET' && holdRead) {
      holdRead = false;
      const response = await route.fetch();
      if (response.status() !== 200) throw new Error('Initial real field read failed');
      readHeld.release(); await readRelease.promise;
      await route.fulfill({ response }); readDelivered.release(); return;
    }
    if (method === 'POST' && holdSave) {
      holdSave = false;
      const response = await route.fetch();
      if (response.status() !== 201) throw new Error('Late real A field create failed');
      saveHeld.release(); await saveRelease.promise;
      await route.fulfill({ response }); saveDelivered.release(); return;
    }
    await route.continue();
  });
  const designer = () => page.locator('section').filter({ has: page.getByRole('heading', { name: 'Field designer', exact: true }) });
  const layer = () => designer().getByRole('application', { name: 'Field placement layer for page 1', exact: true });
  const waitCanvas = async () => {
    await layer().waitFor();
    await page.waitForFunction(() => {
      const layer = document.querySelector('[aria-label="Field placement layer for page 1"]');
      const canvas = layer?.parentElement?.querySelector('canvas');
      return canvas && canvas.width > 500 && canvas.height > 500 && layer!.getBoundingClientRect().width > 500;
    });
  };
  const navigate = async (id: string, name: string) => {
    await page.evaluate((target: string) => {
      document.querySelector('[data-field-fixture-nav]')?.remove();
      const link = document.createElement('a'); link.href = `/documents/${target}`;
      link.textContent = 'Open field fixture document'; link.dataset.fieldFixtureNav = '1'; document.body.append(link);
    }, id);
    await page.getByRole('link', { name: 'Open field fixture document', exact: true }).click();
    await page.getByRole('heading', { name, exact: true }).waitFor(); await waitCanvas();
  };
  const control = async (path: string) => {
    const response = await context.request.post(`${fixture.base}/__fixture/${path}`);
    if (response.status() !== 204) throw new Error(`Fixture control ${path} failed`);
  };
  const awaitAuditWait = async () => {
    for (let n = 0; n < 100; n++) {
      const response = await context.request.get(`${fixture.base}/__fixture/audit-wait`);
      if (response.status() === 204) return;
      if (response.status() !== 409) throw new Error('Exact audit wait observation failed');
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error('Field mutation did not wait on exact audit holder');
  };
  const previewRoundTrip = async () => {
    const original = await layer().elementHandle();
    await page.getByRole('button', { name: 'Preview', exact: true }).click();
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await layer().waitFor();
    if (!await page.evaluate((element: HTMLElement) => element.isConnected && element === document.querySelector('[aria-label="Field placement layer for page 1"]'), original)) {
      throw new Error('Preview replaced the pending field designer');
    }
  };
  const place = async (x: number, y: number) => {
    const box = await layer().boundingBox();
    if (!box || box.width < 500 || box.height < 500) throw new Error('Actual PDF canvas not rendered');
    await layer().click({ position: { x: box.width * x, y: box.height * y } });
  };

  stage = 'late initial A read';
  await page.goto(`${fixture.base}/documents/${fixture.documentAID}`, { waitUntil: 'domcontentloaded' });
  await readHeld.promise;
  await navigate(fixture.documentBID, fixture.documentBName);
  stage = 'actual B create audit wait and preview';
  await control('audit-hold');
  const createB = page.waitForResponse((response: any) => new URL(response.url()).pathname === fieldsB && response.request().method() === 'POST');
  await place(.25, .25); await awaitAuditWait();
  await designer().getByRole('status').waitFor();
  await previewRoundTrip();
  await control('audit-release');
  const createdResponse = await createB;
  if (createdResponse.status() !== 201) throw new Error('B signature field did not commit');
  const signature = await createdResponse.json();
  if (signature.document_id !== fixture.documentBID || signature.recipient_id !== fixture.recipientBID
      || Math.abs(signature.x_pct - 25) > .2 || Math.abs(signature.y_pct - 25) > .2 || signature.w_pct !== 26 || signature.h_pct !== 7) throw new Error('Actual field placement units/identity differ');
  await designer().locator(`[data-field-id="${signature.id}"]`).waitFor();
  readRelease.release(); await readDelivered.promise;
  await designer().locator(`[data-field-id="${signature.id}"]`).waitFor();
  stage = 'edge rectangle placement';
  await designer().getByRole('button', { name: 'Text', exact: true }).click();
  const createText = page.waitForResponse((response: any) => new URL(response.url()).pathname === fieldsB && response.request().method() === 'POST');
  await place(.98, .98);
  const textResponse = await createText;
  if (textResponse.status() !== 201) throw new Error('Edge field did not fit page');
  const text = await textResponse.json();
  if (text.x_pct !== 82 || text.y_pct !== 96 || text.w_pct !== 18 || text.h_pct !== 4) throw new Error('Edge default rectangle overflowed page');
  await designer().locator(`[data-field-id="${text.id}"]`).waitFor();
  stage = 'actual B delete audit wait and preview';
  await control('audit-hold');
  const deleted = page.waitForResponse((response: any) => new URL(response.url()).pathname === `/api/v1/fields/${signature.id}` && response.request().method() === 'DELETE');
  await designer().locator(`[data-field-id="${signature.id}"]`).getByRole('button', { name: 'Remove field', exact: true }).click();
  await awaitAuditWait(); await previewRoundTrip(); await control('audit-release');
  if ((await deleted).status() !== 204) throw new Error('B field deletion did not commit');
  await designer().locator(`[data-field-id="${signature.id}"]`).waitFor({ state: 'detached' });
  await designer().locator(`[data-field-id="${text.id}"]`).waitFor();
  stage = 'late submitted A save';
  await navigate(fixture.documentAID, fixture.documentAName);
  await place(.3, .3); await saveHeld.promise;
  await navigate(fixture.documentBID, fixture.documentBName);
  await designer().locator(`[data-field-id="${text.id}"]`).waitFor();
  saveRelease.release(); await saveDelivered.promise;
  if (await designer().locator('[data-field-id]').count() !== 1) throw new Error('Late A save changed B fields');
  await designer().locator(`[data-field-id="${text.id}"]`).waitFor();

  stage = 'recipient create sync without designer remount';
  const recipientSyncDesigner = await designer().elementHandle();
  const assertSameDesigner = async () => {
    if (!await page.evaluate((element: HTMLElement) => {
      const currentLayer = document.querySelector('[aria-label="Field placement layer for page 1"]');
      return element.isConnected && element === currentLayer?.closest('section');
    }, recipientSyncDesigner)) throw new Error('Recipient change remounted the field designer');
  };
  const panel = page.getByRole('region', { name: 'Recipients and sending', exact: true });
  const recipientForm = () => panel.getByRole('heading', { name: 'New recipient', exact: true }).locator('..');
  const recipientChoice = () => designer().getByLabel('Recipient', { exact: true });
  await panel.getByRole('button', { name: 'Add recipient', exact: true }).click();
  await recipientForm().getByLabel('Name', { exact: true }).fill(fixture.recipientCName);
  await recipientForm().getByLabel('Email', { exact: true }).fill(fixture.recipientCEmail);
  const createRecipient = page.waitForResponse((response: any) => new URL(response.url()).pathname === recipientsB && response.request().method() === 'POST');
  await recipientForm().getByRole('button', { name: 'Add recipient', exact: true }).click();
  const recipientResponse = await createRecipient;
  if (recipientResponse.status() !== 201) throw new Error('Current B recipient creation did not commit');
  const recipientC = await recipientResponse.json();
  if (!/^[0-9a-f-]{36}$/i.test(recipientC.id) || recipientC.document_id !== fixture.documentBID
      || recipientC.name !== fixture.recipientCName || recipientC.email !== fixture.recipientCEmail) throw new Error('Recipient sync committed a different identity');
  await panel.locator(`[data-recipient-id="${recipientC.id}"]`).waitFor();
  await recipientChoice().locator(`option[value="${recipientC.id}"]`).waitFor({ state: 'attached' });
  if (await recipientChoice().locator(`option[value="${recipientC.id}"]`).textContent() !== fixture.recipientCName) throw new Error('Designer did not show the new recipient');
  await assertSameDesigner();

  stage = 'new recipient signature assignment';
  await recipientChoice().selectOption(recipientC.id);
  await designer().getByRole('button', { name: 'Signature', exact: true }).click();
  if (await recipientChoice().inputValue() !== recipientC.id) throw new Error('Signature placement lost the selected recipient');
  const createAssignedField = page.waitForResponse((response: any) => new URL(response.url()).pathname === fieldsB && response.request().method() === 'POST');
  await place(.5, .5);
  const assignedResponse = await createAssignedField;
  if (assignedResponse.status() !== 201) throw new Error('New recipient signature field did not commit');
  const assignedSignature = await assignedResponse.json();
  if (!/^[0-9a-f-]{36}$/i.test(assignedSignature.id) || assignedSignature.document_id !== fixture.documentBID
      || assignedSignature.recipient_id !== recipientC.id || assignedSignature.type !== 'signature'
      || Math.abs(assignedSignature.x_pct - 50) > .2 || Math.abs(assignedSignature.y_pct - 50) > .2
      || assignedSignature.w_pct !== 26 || assignedSignature.h_pct !== 7) throw new Error('New signature placement did not bind the current recipient');
  await designer().locator(`[data-field-id="${assignedSignature.id}"]`).waitFor();
  await designer().locator(`[data-field-id="${text.id}"]`).waitFor();
  await assertSameDesigner();

  stage = 'recipient delete cascades field and refreshes selection';
  const deleteRecipient = page.waitForResponse((response: any) => new URL(response.url()).pathname === `${recipientsB}/${recipientC.id}` && response.request().method() === 'DELETE');
  const confirmation = page.waitForEvent('dialog');
  const removeClick = panel.locator(`[data-recipient-id="${recipientC.id}"]`).getByRole('button', { name: `Remove ${fixture.recipientCName}`, exact: true }).click();
  const dialog = await confirmation;
  if (dialog.type() !== 'confirm' || !dialog.message().includes(fixture.recipientCName)) throw new Error('Recipient removal skipped its identity confirmation');
  await dialog.accept(); await removeClick;
  if ((await deleteRecipient).status() !== 204) throw new Error('Current B recipient deletion did not commit');
  await panel.locator(`[data-recipient-id="${recipientC.id}"]`).waitFor({ state: 'detached' });
  await recipientChoice().locator(`option[value="${recipientC.id}"]`).waitFor({ state: 'detached' });
  await designer().locator(`[data-field-id="${assignedSignature.id}"]`).waitFor({ state: 'detached' });
  await designer().locator(`[data-field-id="${text.id}"]`).waitFor();
  await page.waitForFunction((expected: string) => {
    const currentLayer = document.querySelector('[aria-label="Field placement layer for page 1"]');
    return currentLayer?.closest('section')?.querySelector('select')?.value === expected;
  }, fixture.recipientBID);
  if (await designer().locator('[data-field-id]').count() !== 1) throw new Error('Recipient cascade removed or duplicated unrelated fields');
  const retainedGeometry = await designer().locator(`[data-field-id="${text.id}"]`).evaluate((element: HTMLElement) => [element.style.left, element.style.top, element.style.width, element.style.height]);
  if (JSON.stringify(retainedGeometry) !== JSON.stringify(['82%', '96%', '18%', '4%'])) throw new Error('Recipient cascade changed the existing text placement');
  await assertSameDesigner();

  const csp = await page.evaluate(() => (window as any).__fieldCspViolations);
  if (errors.length || csp.length) throw new Error('Browser/CSP errors during real PDF field acceptance');
  if (mutations.length !== 7 || mutations[0].path !== fieldsB || mutations[0].method !== 'POST'
      || mutations[1].path !== fieldsB || mutations[1].method !== 'POST'
      || mutations[2].path !== `/api/v1/fields/${signature.id}` || mutations[2].method !== 'DELETE'
      || mutations[3].path !== fieldsA || mutations[3].method !== 'POST'
      || mutations[4].path !== recipientsB || mutations[4].method !== 'POST'
      || mutations[5].path !== fieldsB || mutations[5].method !== 'POST'
      || mutations[6].path !== `${recipientsB}/${recipientC.id}` || mutations[6].method !== 'DELETE') throw new Error('Unexpected field/recipient/lifecycle mutations');
  await page.screenshot({ path: '/private/tmp/hash-browser-field-designer.png', fullPage: true });
  await Bun.write('/private/tmp/hash-browser-field-designer-receipt.json', JSON.stringify({
    result: 'pass', documentAID: fixture.documentAID, documentBID: fixture.documentBID,
    deletedFieldBID: signature.id, finalFieldBID: text.id, finalFieldB: text,
    newRecipientBID: recipientC.id, cascadedFieldBID: assignedSignature.id, cascadedFieldB: assignedSignature,
    realPdfCanvasRendered: true, createPreviewSameDesigner: true, deletePreviewSameDesigner: true,
    lateInitialReadIsolated: true, lateSubmittedSaveIsolated: true, edgePlacementFitsPage: true,
    recipientSyncWithoutRemount: true,
    browserErrors: errors, cspViolations: csp, mutations,
    scope: 'actual Go HTTPS/PG field APIs, verified-version PDF read via controlled S3 fixture, actual PDF.js/Chromium; synthetic session'
  }, null, 2));
  console.log('PASS: actual PDF canvas, scoped placement, pending preview writes, delayed A isolation and recipient assignment/cascade sync without remount');
} catch (error) {
  console.error('FAILED_STAGE', stage, 'BROWSER_ERRORS', errors.length);
  if (page) await page.screenshot({ path: '/private/tmp/hash-browser-field-designer-failed.png', fullPage: true });
  throw error;
} finally {
  readRelease.release(); saveRelease.release();
  if (context) await context.request.post(`${fixture.base}/__fixture/audit-release`).catch(() => {});
  await browser.close();
}
