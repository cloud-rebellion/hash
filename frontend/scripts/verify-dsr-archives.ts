// Real Go HTTPS/DSR/archive routes and PostgreSQL; an isolated synthetic owner session.
import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';
const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; documentID: string; archiveID: string; cookieName: string; cookie: string;
  requestID: string; archiveBytesBase64?: string;
};
for (const id of [fixture.documentID, fixture.archiveID, fixture.requestID]) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) throw new Error('Fixture UUID required');
}
const browser = await chromium.launch({ headless: true });
const errors: string[] = [];
let stage = 'initialization';
let page: any;
let resetRequests = 0;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addCookies([{ name: fixture.cookieName, value: fixture.cookie, url: fixture.base,
    httpOnly: true, secure: true, sameSite: 'Lax' }]);
  const meResponse = await context.request.get(`${fixture.base}/api/v1/me`);
  const me = await meResponse.json();
  if (!meResponse.ok() || me.role !== 'owner') throw new Error('Owner fixture session required');
  const recoveryPath = `/api/v1/documents/${encodeURIComponent(fixture.documentID)}/collab/recovery`;
  const archivePath = `${recoveryPath}/archives/${encodeURIComponent(fixture.archiveID)}`;
  const archiveResponse = await context.request.get(`${fixture.base}${recoveryPath}`);
  const archiveState = await archiveResponse.json();
  const metadata = archiveState.archives?.find((archive: any) => archive.id === fixture.archiveID);
  if (!archiveResponse.ok() || archiveState.document_deleted !== true || !metadata) {
    throw new Error('Soft-deleted fixture with accessible retained archive required');
  }
  const requestResponse = await context.request.get(`${fixture.base}/api/v1/dsr?status=open`);
  const requests = await requestResponse.json();
  if (!requestResponse.ok() || !requests.requests?.some((request: any) => request.id === fixture.requestID
      && request.org_id === me.org_id && request.document_id === fixture.documentID && request.kind === 'access')) {
    throw new Error('Actual linked open access request required');
  }
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', (error: Error) => errors.push(error.message));
  page.on('request', (request: any) => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === recoveryPath) resetRequests++;
  });
  stage = 'DSR document selection';
  await page.goto(`${fixture.base}/settings/dsr`);
  const selected = page.locator(`[data-request-id="${fixture.requestID}"]`);
  await selected.getByRole('button', { name: 'Review document archives', exact: true }).click();
  const panel = page.getByRole('region', { name: 'Collaboration archive review' });
  await panel.getByText('This document was deleted.', { exact: false }).waitFor();
  if (await panel.getByRole('button', { name: 'Reset shared editing to saved document', exact: true }).count()
      || await panel.getByRole('button', { name: 'Reload saved document', exact: true }).count()
      || await panel.getByRole('button', { name: 'Download local draft for recovery', exact: true }).count()) {
    throw new Error('Deleted-document archive review exposed editing recovery controls');
  }
  stage = 'deleted archive attachment download';
  const archiveLink = panel.locator(`a[href="${archivePath}"]`);
  const download = page.waitForEvent('download');
  await archiveLink.click();
  await (await download).saveAs('/private/tmp/hash-dsr-deleted-archive.bin');
  const bytes = await Bun.file('/private/tmp/hash-dsr-deleted-archive.bin').bytes();
  if (!bytes.byteLength || bytes.byteLength !== metadata.size_bytes || bytes.byteLength > 8 * 1024 * 1024) {
    throw new Error('Deleted archive attachment lost the bounded retained payload');
  }
  if (fixture.archiveBytesBase64 && !Buffer.from(bytes).equals(Buffer.from(fixture.archiveBytesBase64, 'base64'))) {
    throw new Error('Deleted archive download differs from the exact fixture history');
  }
  stage = 'explicit archive deletion deferred by open access request';
  page.once('dialog', (dialog: any) => dialog.accept());
  const deleteResponse = page.waitForResponse((response: any) => new URL(response.url()).pathname === archivePath
    && response.request().method() === 'DELETE');
  await archiveLink.locator('..').locator('..').getByRole('button', { name: 'Delete archive…', exact: true }).click();
  const deferred = await deleteResponse;
  if (deferred.status() !== 409) throw new Error(`Open access request did not defer deletion: ${deferred.status()}`);
  await panel.getByRole('alert').waitFor();
  await archiveLink.waitFor();
  const retainedResponse = await context.request.get(`${fixture.base}${recoveryPath}`);
  const retained = await retainedResponse.json();
  if (!retainedResponse.ok() || !retained.archives.some((archive: any) => archive.id === fixture.archiveID)) {
    throw new Error('Deferred deletion lost retained archive metadata');
  }
  if (resetRequests) throw new Error('Archive-only review attempted to reset deleted shared editing');
  if (errors.length) throw new Error(`Browser exceptions: ${errors.join('; ')}`);
  await page.screenshot({ path: '/private/tmp/hash-dsr-deleted-archives.png', fullPage: true });
  await Bun.write('/private/tmp/hash-dsr-deleted-archives-receipt.json', JSON.stringify({
    result: 'pass', documentID: fixture.documentID, requestID: fixture.requestID, archiveID: fixture.archiveID,
    documentDeleted: true, archiveAttachmentBytes: bytes.byteLength,
    exactArchiveBytesVerified: Boolean(fixture.archiveBytesBase64), deletionDeferredStatus: deferred.status(),
    resetRequests, browserErrors: errors,
    scope: 'real rendered DSR selection and Go HTTPS/PostgreSQL owner/archive APIs; isolated synthetic owner session'
  }, null, 2));
  console.log('PASS: DSR owner review downloads deleted archive bytes; no editing/reset controls; explicit deletion deferred409 preserves archive');
} catch (error) {
  console.error('FAILED_STAGE', stage, 'PAGE_ERRORS', errors);
  if (page) {
    console.error('PAGE_TEXT', await page.locator('body').innerText());
    await page.screenshot({ path: '/private/tmp/hash-dsr-deleted-archives-failed.png', fullPage: true });
  }
  throw error;
} finally { await browser.close(); }
