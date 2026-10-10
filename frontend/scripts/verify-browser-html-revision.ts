// Disposable actual HTTPS Go/PostgreSQL routes and isolated PDF worker. The
// fixture supplies synthetic renderer/storage, participants and credentials.
// Credentials stay on stdin and are never written to receipts or stdout.
const configuredModule = Bun.env.HASH_BROWSER_E2E_PLAYWRIGHT_MODULE;
const moduleURL = configuredModule ? new URL(configuredModule)
  : new URL('../../../brightcrm/tests/e2e/node_modules/playwright/index.mjs', import.meta.url);
if (moduleURL.protocol !== 'file:' || moduleURL.hostname || !moduleURL.pathname.endsWith('/playwright/index.mjs')) {
  throw new Error('Explicit locally cached Playwright module required');
}
// Test-only host orchestration may select the already installed module when
// the isolated checkout has no dependency tree. This never installs a package.
const { chromium } = await import(moduleURL.href);

const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; documentID: string; cookieName: string; cookie: string;
  artifactDir: string; receiptPath: string;
};
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base) || !/^[a-f0-9-]{36}$/i.test(fixture.documentID)
    || !fixture.cookieName || !fixture.cookie || !fixture.artifactDir.startsWith('/private/tmp/') || !fixture.receiptPath.startsWith('/private/tmp/')) {
  throw new Error('Disposable loopback HTTPS HTML revision fixture required');
}
const hash = (bytes: Uint8Array) => new Bun.CryptoHasher('sha256').update(bytes).digest('hex');
const browser = await chromium.launch({ headless: true });
let stage = 'initialization', page: any;
let sendRequests = 0;
const pageErrors: string[] = [], failedAssets: string[] = [], writes: { path: string; keys: string[]; pdfSHA?: string; sourceCommitment?: string; observedAt?: string }[] = [];
const screenshots: { path: string; sha256: string }[] = [];
try {
  stage = 'browser context';
  const owner = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
  stage = 'private session cookie adoption';
  await owner.addCookies([{ name: fixture.cookieName, value: fixture.cookie, url: fixture.base, httpOnly: true, secure: true, sameSite: 'Lax' }]);
  const api = `/api/v1/documents/${fixture.documentID}`;
  stage = 'initial authenticated session GET';
  const meResponse = await owner.request.get(`${fixture.base}/api/v1/me`);
  console.log('INITIAL_API_STATUS', 'session', meResponse.status());
  const me = await meResponse.json();
  stage = 'initial document GET';
  const beforeResponse = await owner.request.get(`${fixture.base}${api}`);
  console.log('INITIAL_API_STATUS', 'document', beforeResponse.status());
  const before = await beforeResponse.json();
  stage = 'initial retained source GET';
  const sourceResponse = await owner.request.get(`${fixture.base}${api}/html/source`);
  console.log('INITIAL_API_STATUS', 'source', sourceResponse.status());
  const initial = await sourceResponse.json();
  if (!meResponse.ok() || !beforeResponse.ok() || !sourceResponse.ok() || before.id !== fixture.documentID || before.org_id !== me.org_id
      || !(me.role === 'owner' || (me.role === 'sender' && me.user_id === before.sender_id)) || before.status !== 'draft'
      || before.source_kind !== 'pdf' || !before.has_html_source || !initial.can_edit || initial.materialization_revision !== 1
      || initial.html_source_commitment !== before.html_source_commitment || initial.pdf_sha256 !== before.pdf_sha256
      || !initial.values?.some((v: any) => v.name === 'customer') || !initial.sections?.some((s: any) => s.name === 'scope')) {
    throw new Error('Draft HTML origin with editable customer/scope and original sender or owner session required');
  }
  stage = 'initial named party and placement GET';
  const initialRecipientsResponse = await owner.request.get(`${fixture.base}${api}/recipients`);
  console.log('INITIAL_API_STATUS', 'recipients', initialRecipientsResponse.status());
  const initialRecipients = (await initialRecipientsResponse.json()).recipients;
  const initialFieldsResponse = await owner.request.get(`${fixture.base}${api}/fields`);
  console.log('INITIAL_API_STATUS', 'fields', initialFieldsResponse.status());
  const initialFields = (await initialFieldsResponse.json()).fields;
  const initialNamed = initialRecipients?.find((recipient: any) => recipient.name && recipient.document_id === fixture.documentID);
  if (!initialRecipientsResponse.ok() || !initialFieldsResponse.ok() || !initialNamed || initialFields?.length !== 1
      || initialFields[0].document_id !== fixture.documentID || initialFields[0].recipient_id !== initialNamed.id || initialFields[0].type !== 'signature') {
    throw new Error('One persisted original named-party signature placement required before revision');
  }
  page = await owner.newPage(); page.setDefaultTimeout(15000);
  page.on('pageerror', () => pageErrors.push('browser exception'));
  page.on('requestfailed', (request: any) => {
    if (!new URL(request.url()).pathname.startsWith('/api/v1/') && !request.failure()?.errorText.includes('ERR_ABORTED')) failedAssets.push(new URL(request.url()).pathname);
  });
  page.on('request', (request: any) => {
    const path = new URL(request.url()).pathname;
    if (request.method() === 'POST' && path === api + '/send') sendRequests++;
    if (request.method() === 'POST' && [api + '/html/revisions', api + '/html/review', api + '/fields'].includes(path)) {
      const body = request.postDataJSON();
      writes.push({ path, keys: Object.keys(body).sort(), pdfSHA: body.expected_pdf_sha256,
        sourceCommitment: body.expected_html_source_commitment, observedAt: body.expected_updated_at });
    }
  });
  const editor = () => page.getByRole('region', { name: 'Revise HTML document', exact: true });
  const history = () => page.getByRole('region', { name: 'HTML PDF revision history', exact: true });
  const review = () => page.getByRole('region', { name: 'Review generated PDF', exact: true });
  const customerDefinition = initial.values.find((value: any) => value.name === 'customer');
  const customerLabel = `Document customer${customerDefinition.required ? ' (required)' : ''}`;
  // Help text is part of each wrapping label. Match the literal semantic
  // textbox name within this editor, then require exactly one control below.
  const customerInput = () => editor().getByRole('textbox', { name: customerLabel, exact: false });
  const summaryInput = () => editor().getByRole('textbox', { name: 'Revision summary', exact: false });
  async function nonblank(canvas: any) {
    const geometry = await canvas.evaluate((c: HTMLCanvasElement) => {
      const context = c.getContext('2d'); if (!context || !c.width || !c.height) throw new Error('Missing canvas');
      const data = context.getImageData(0, 0, c.width, c.height).data; let ink = 0;
      for (let i = 0; i < data.length; i += 4) if (data[i + 3] && data[i] + data[i + 1] + data[i + 2] < 650) ink++;
      return { width: c.width, height: c.height, ink };
    });
    if (geometry.width < 200 || geometry.height < 200 || geometry.ink < 100) throw new Error('PDF page was not visibly rendered');
    return geometry;
  }
  async function screenshot(name: string) {
    const path = `${fixture.artifactDir}/${name}.png`; await page.screenshot({ path, fullPage: true });
    screenshots.push({ path, sha256: hash(new Uint8Array(await Bun.file(path).arrayBuffer())) });
  }
  async function viewPages(region: any, pages: number, label: string) {
    for (let n = 1; n <= pages; n++) {
      await region.getByRole('status').filter({ hasText: `Page ${n} of ${pages}` }).waitFor();
      // A page number is recorded only after pdf.js's render promise resolves.
      await region.getByRole('status').filter({ hasText: `Page ${n} of ${pages}` }).filter({ hasNotText: 'Rendering' }).waitFor();
      await nonblank(region.getByLabel(`${label}, page ${n}`, { exact: true }));
      if (n < pages) { await region.getByRole('button', { name: 'Next page', exact: true }).click(); }
    }
  }

  stage = 'declared-value and wording revision';
  await page.goto(`${fixture.base}/documents/${fixture.documentID}`);
  stage = 'retained editor accessible fields';
  await customerInput().waitFor();
  if (await customerInput().count() !== 1 || await summaryInput().count() !== 1) throw new Error('Declared customer and summary fields must resolve uniquely');
  await page.waitForFunction(() => !document.querySelector('[aria-label="Revise HTML document"] fieldset')?.hasAttribute('disabled'));
  stage = 'original persisted visible named-party placement';
  await page.locator(`[data-field-id="${initialFields[0].id}"]`).waitFor();
  if (await page.locator('[data-field-id]').count() !== 1) throw new Error('Original persisted placement was not visible before revision');
  stage = 'declared inputs and dirty-proof gate';
  await customerInput().fill('Negotiated Synthetic Customer');
  await editor().getByLabel('Document wording: scope', { exact: true }).fill('Human-proposed wording for the isolated negotiation fixture.');
  await summaryInput().fill('Declared customer and scope revised after discussion');
  const oldReviewButton = review().getByRole('button', { name: 'Approve this PDF for sending', exact: true });
  if (await oldReviewButton.count() && await oldReviewButton.isEnabled()) throw new Error('Dirty form allowed review of old PDF');
  const revisionResponse = page.waitForResponse((response: any) => new URL(response.url()).pathname === api + '/html/revisions' && response.request().method() === 'POST');
  stage = 'revision write and exact source readback';
  await editor().getByRole('button', { name: 'Save revision and render PDF', exact: true }).click();
  const written = await revisionResponse;
  if (written.status() !== 201) throw new Error('HTML revision was not committed');
  const result = await written.json(), revised = result.document;
  if (revised.id !== fixture.documentID || revised.org_id !== before.org_id || result.materialization_revision !== 2 || revised.html_materialization_revision !== 2
      || revised.html_source_commitment === initial.html_source_commitment || revised.source_kind !== 'pdf' || !revised.html_review_required
      || result.placement_reset !== true || !Number.isInteger(result.page_count) || result.page_count < 1) throw new Error('New immutable revision/reset contract missing');
  await editor().getByText(`Retained template version ${initial.template_version} · PDF revision 2`, { exact: true }).waitFor();
  const fieldsBeforePlacement = await (await owner.request.get(`${fixture.base}${api}/fields`)).json();
  if (fieldsBeforePlacement.fields?.length || await page.locator('[data-field-id]').count()) throw new Error('Old field placement survived rerender');
  if (writes.filter(w => w.path === api + '/html/revisions').length !== 1 || writes[0].sourceCommitment !== initial.html_source_commitment
      || writes[0].observedAt !== initial.updated_at) throw new Error('Revision write omitted original source pins');
  if (await page.getByRole('button', { name: 'Save as template', exact: true }).count()) throw new Error('HTML origin exposed static PDF export');

  stage = 'immutable historical source and PDF';
  await history().getByRole('button', { name: 'Refresh PDF history', exact: true }).click();
  await history().getByRole('button', { name: 'Open PDF revision 1', exact: true }).click();
  const historicalSourceResponse = await owner.request.get(`${fixture.base}${api}/html/revisions/1/source`);
  const historicalSource = await historicalSourceResponse.json();
  const historicalPDF = await owner.request.get(`${fixture.base}${api}/html/revisions/1/pdf`), headers = historicalPDF.headers(), historicalBytes = await historicalPDF.body();
  if (!historicalSourceResponse.ok() || !historicalPDF.ok() || historicalSource.can_edit !== false || historicalSource.html_source_commitment !== initial.html_source_commitment
      || headers['x-hash-document-id'] !== fixture.documentID || headers['x-hash-materialization-revision'] !== '1'
      || headers['x-hash-html-source-commitment'] !== initial.html_source_commitment || headers['x-hash-pdf-sha256'] !== initial.pdf_sha256
      || headers['x-hash-pdf-pages'] !== String(initial.page_count) || hash(historicalBytes) !== initial.pdf_sha256) throw new Error('Historical immutable source/PDF pins differ');
  await viewPages(history(), initial.page_count, 'Saved design preview'); await screenshot('historical-pdf-desktop');
  await history().getByRole('button', { name: 'Close revision', exact: true }).click();

  stage = 'fresh all-page manual PDF review';
  const acknowledgement = review().getByRole('checkbox');
  if (await acknowledgement.isChecked()) throw new Error('Prior acknowledgement survived source change');
  if (result.page_count > 1 && await acknowledgement.isEnabled()) throw new Error('Review enabled before every page rendered');
  await viewPages(review(), result.page_count, 'Generated PDF');
  await acknowledgement.check();
  const reviewResponse = page.waitForResponse((response: any) => new URL(response.url()).pathname === api + '/html/review' && response.request().method() === 'POST');
  await review().getByRole('button', { name: 'Approve this PDF for sending', exact: true }).click();
  if ((await reviewResponse).status() !== 200) throw new Error('Exact PDF review was not committed');
  await review().getByText('This exact PDF has been reviewed.', { exact: false }).waitFor();
  const reviewWrite = writes.find(w => w.path === api + '/html/review');
  if (!reviewWrite || reviewWrite.pdfSHA !== revised.pdf_sha256 || reviewWrite.sourceCommitment !== revised.html_source_commitment
      || reviewWrite.observedAt !== revised.updated_at) throw new Error('Review omitted exact new source/PDF pins');

  stage = 'fresh named-party signature placement';
  const recipientsResponse = await owner.request.get(`${fixture.base}${api}/recipients`), recipients = (await recipientsResponse.json()).recipients;
  const named = recipients?.find((recipient: any) => recipient.name && recipient.document_id === fixture.documentID);
  if (!recipientsResponse.ok() || !named || named.id !== initialNamed.id) throw new Error('Original named synthetic recipient required');
  const placement = page.getByRole('region', { name: 'PDF field placement pages', exact: true });
  await placement.waitFor(); await page.getByLabel('Recipient', { exact: true }).selectOption(named.id);
  await page.waitForFunction(() => [...document.querySelectorAll('[aria-label="PDF field placement pages"] canvas')].every((c: any) => c.width > 200 && c.height > 200));
  const fieldResponse = page.waitForResponse((response: any) => new URL(response.url()).pathname === api + '/fields' && response.request().method() === 'POST');
  await page.getByLabel('Field placement layer for page 1', { exact: true }).click({ position: { x: 100, y: 140 } });
  const placedResponse = await fieldResponse;
  if (placedResponse.status() !== 201) throw new Error('Fresh field was not committed');
  const field = await placedResponse.json(); await page.locator(`[data-field-id="${field.id}"]`).waitFor();
  const fieldWrite = writes.find(w => w.path === api + '/fields');
  if (field.document_id !== fixture.documentID || field.recipient_id !== named.id || field.type !== 'signature'
      || !fieldWrite || fieldWrite.pdfSHA !== revised.pdf_sha256 || fieldWrite.sourceCommitment !== revised.html_source_commitment) throw new Error('Field omitted exact current PDF/source binding');
  const persistedFieldsResponse = await owner.request.get(`${fixture.base}${api}/fields`);
  const persistedFields = (await persistedFieldsResponse.json()).fields;
  if (!persistedFieldsResponse.ok() || persistedFields?.length !== 1 || persistedFields[0].id !== field.id
      || persistedFields[0].recipient_id !== named.id) throw new Error('Fresh named-party placement was not persisted');
  stage = 'reviewed and placed draft send eligibility without dispatch';
  await page.locator('#lawful-basis').selectOption('contract');
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some(button => button.textContent?.trim() === 'Send for signature' && !button.disabled));
  if (sendRequests !== 0) throw new Error('Fixture must not dispatch a ceremony');
  const eligibleResponse = await owner.request.get(`${fixture.base}${api}`), eligible = await eligibleResponse.json();
  if (!eligibleResponse.ok() || eligible.status !== 'draft' || eligible.has_html_source !== true
      || (eligible.html_review_required !== undefined && eligible.html_review_required !== false)
      || eligible.html_source_commitment !== revised.html_source_commitment || eligible.pdf_sha256 !== revised.pdf_sha256
      || eligible.html_materialization_revision !== 2) throw new Error('Reviewed source changed before send eligibility witness');
  await screenshot('fresh-reviewed-pdf-desktop');
  stage = 'mobile visual containment';
  await page.setViewportSize({ width: 390, height: 844 });
  await screenshot('fresh-reviewed-pdf-mobile');
  const mobile = await page.evaluate(() => ({ viewport: innerWidth, scroll: document.documentElement.scrollWidth }));
  if (mobile.scroll !== mobile.viewport || pageErrors.length || failedAssets.length) throw new Error('Mobile overflow or browser/asset error');
  await Bun.write(fixture.receiptPath, JSON.stringify({ result: 'pass', documentID: fixture.documentID,
    scope: 'Built Svelte/pdf.js against disposable actual Go HTTPS/PostgreSQL/isolated PDF worker. Renderer/storage and parties synthetic; no SMTP delivery, signing, provider, deployment or legal acceptance claim.',
    originalRevision: 1, newRevision: 2, originalSourceCommitment: initial.html_source_commitment, newSourceCommitment: revised.html_source_commitment,
    historicalPDFSHA256: initial.pdf_sha256, revisedPDFSHA256: revised.pdf_sha256, pageCount: result.page_count,
    originalNamedRecipientPlacementCount: initialFields.length, placementCountAfterRevision: fieldsBeforePlacement.fields.length,
    staleFieldPlacementReset: true, historicalPDFHeadersAndBytesVerified: true, historicalPagesRendered: initial.page_count,
    freshPagesRendered: result.page_count, exactManualReview: true, namedRecipientFieldPinned: true, staticTemplateExportAbsent: true,
    sendEnabledAfterReviewAndPersistedPlacement: true, sendDispatched: false,
    writes, screenshots, mobile, pageErrors, failedAssets }, null, 2) + '\n');
  console.log('PASS: HTML draft revision, original placement reset, immutable historical PDF, exact review, fresh named-recipient placement and send eligibility without dispatch');
} catch {
  if (page) await page.screenshot({ path: `${fixture.artifactDir}/failed.png`, fullPage: true }).catch(() => {});
  console.error('FAILED_STAGE', stage, 'BROWSER_ERROR_COUNT', pageErrors.length);
  throw new Error(`HTML revision verifier failed at ${stage}`);
} finally { await browser.close(); }
