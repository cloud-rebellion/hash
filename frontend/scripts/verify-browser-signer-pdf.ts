// Actual HTTPS Go/PostgreSQL/source worker + exact real Chromium renderer.
// S3 retention, participants, keys and delivery outbox remain synthetic.
// Original credentials enter on stdin only; no URLs/tokens/cookies are logged.
const configuredModule = Bun.env.HASH_BROWSER_E2E_PLAYWRIGHT_MODULE;
const moduleURL = configuredModule ? new URL(configuredModule)
  : new URL('../../../brightcrm/tests/e2e/node_modules/playwright/index.mjs', import.meta.url);
if (moduleURL.protocol !== 'file:' || moduleURL.hostname || !moduleURL.pathname.endsWith('/playwright/index.mjs')) {
  throw new Error('Explicit locally cached Playwright module required');
}
const { chromium } = await import(moduleURL.href);

type Party = { token: string; recipientID: string; name: string; role: string; fieldID: string };
type Observation = { document_id: string; recipient_id: string; pdf_sha256: string; page_count?: number;
  html_source_commitment?: string; materialization_revision?: number };
const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; documentID: string; pdfSHA256: string; sourceCommitment: string; pageCount: number;
  materializationRevision: number; rendererVersion: string; parties: Party[];
  ownerCookie: string;
  legacy: { documentID: string; token: string; recipientID: string; name: string; textFieldID: string; signatureFieldID: string };
  artifactDir: string; receiptPath: string;
};
const uuid = /^[a-f0-9-]{36}$/i, digest = /^[a-f0-9]{64}$/;
const validToken = (value: string) => /^[A-Za-z0-9_-]{32,256}$/.test(value);
const ownerCookie = typeof fixture.ownerCookie === 'string' ? /^([A-Za-z0-9_-]{1,64})=([^;\s\u0000-\u001f\u007f]{16,4096})$/.exec(fixture.ownerCookie) : null;
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base) || !uuid.test(fixture.documentID)
  || !digest.test(fixture.pdfSHA256) || !digest.test(fixture.sourceCommitment)
  || !Number.isInteger(fixture.pageCount) || fixture.pageCount < 2 || fixture.pageCount > 12
  || fixture.materializationRevision !== 1 || fixture.rendererVersion !== '8.36.0-hash.1'
  || !ownerCookie || fixture.parties?.length !== 2 || fixture.parties[0].recipientID === fixture.parties[1].recipientID
  || fixture.parties.some(p => !validToken(p.token) || !uuid.test(p.recipientID) || !uuid.test(p.fieldID) || !p.name)
  || !fixture.legacy || !validToken(fixture.legacy.token) || !uuid.test(fixture.legacy.documentID)
  || !uuid.test(fixture.legacy.recipientID) || !uuid.test(fixture.legacy.textFieldID) || !uuid.test(fixture.legacy.signatureFieldID)
  || !fixture.artifactDir.startsWith('/private/tmp/') || !fixture.receiptPath.startsWith('/private/tmp/')) {
  throw new Error('Disposable real-rendered multi-party signer fixture required');
}
const hash = (bytes: Uint8Array) => new Bun.CryptoHasher('sha256').update(bytes).digest('hex');
const browser = await chromium.launch({ headless: true });
let stage = 'initialization';
const pageErrors: string[] = [], failedAssets: string[] = [];
const contexts: any[] = [], screenshots: { name: string; sha256: string }[] = [];
const faults: { case: string; requestsToSign: number; gateDisabled?: boolean;
  gateDisabledDuringOldLoad?: boolean; currentRecipientReadyAfterSettlement?: boolean;
  lateRouteOutcome?: 'fulfilled' | 'aborted' }[] = [];
let signRequests = 0, savedFields = 0;
let ownerFieldMutations = 0;
let ownerReadOnlyProof: unknown;

function witnessHeaders(headers: Record<string, string>, observation: Observation) {
  for (const [name, expected] of [
    ['x-hash-document-id', observation.document_id], ['x-hash-recipient-id', observation.recipient_id],
    ['x-hash-pdf-sha256', observation.pdf_sha256], ['x-hash-pdf-pages', observation.page_count?.toString()],
    ['x-hash-html-source-commitment', observation.html_source_commitment],
    ['x-hash-materialization-revision', observation.materialization_revision?.toString()],
  ]) {
    if (expected === undefined ? headers[name] !== undefined : headers[name] !== expected) {
      throw new Error('Signer response witness differs from original recipient observation');
    }
  }
}

function observationFor(ctx: any, party: { recipientID: string }, legacy = false): Observation {
  const o = ctx.pdf_observation as Observation;
  if (!o || o.document_id !== (legacy ? fixture.legacy.documentID : fixture.documentID)
    || o.recipient_id !== party.recipientID || o.pdf_sha256 !== fixture.pdfSHA256
    || ctx.document_id !== o.document_id || ctx.recipient?.id !== party.recipientID || ctx.source_kind !== 'pdf'
    || !digest.test(ctx.privacy?.notice_digest ?? '')) throw new Error('Original signer context is not bound to fixture source');
  if (legacy ? o.page_count !== undefined || o.html_source_commitment !== undefined || o.materialization_revision !== undefined
    : o.page_count !== fixture.pageCount || o.html_source_commitment !== fixture.sourceCommitment || o.materialization_revision !== fixture.materializationRevision) {
    throw new Error('Optional source witness does not match original artifact kind');
  }
  return o;
}

async function newPage(init?: () => void) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
  contexts.push(context);
  if (init) await context.addInitScript(init);
  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  page.on('pageerror', () => pageErrors.push('browser exception'));
  page.on('requestfailed', (request: any) => {
    const path = new URL(request.url()).pathname;
    if ((path.startsWith('/_app/') || path.startsWith('/assets/')) && !request.failure()?.errorText?.includes('ERR_ABORTED')) failedAssets.push('built asset failed');
  });
  page.on('request', (request: any) => {
    if (request.method() === 'POST' && /^\/sign\/[^/]+\/sign$/.test(new URL(request.url()).pathname)) signRequests++;
  });
  return { context, page };
}

async function contextFor(context: any, token: string) {
  const response = await context.request.get(`${fixture.base}/sign/${token}`, { headers: { accept: 'application/json' } });
  if (!response.ok()) throw new Error('Original signer context unavailable');
  return await response.json();
}

async function acknowledge(page: any, ctx: any) {
  const dialog = page.getByRole('dialog').filter({ has: page.getByRole('heading', { name: ctx.privacy.copy.title, exact: true }) });
  await dialog.waitFor();
  await dialog.getByRole('button', { name: ctx.privacy.copy.acknowledgement_label, exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
}

async function disabledGate(page: any) {
  const adopt = page.getByRole('button', { name: 'Adopt and sign', exact: true });
  await adopt.waitFor();
  if (await adopt.isEnabled() || await page.getByRole('button', { name: 'Sign with this signature', exact: true }).count()) {
    throw new Error('Signing became available before current document readiness');
  }
  if (await page.locator('.pdf-signer').getAttribute('data-pdf-ready') === 'true') throw new Error('Failed artifact exposed ready witness');
}

async function renderedPages(page: any) {
  const viewer = page.locator('.pdf-signer[data-pdf-ready="true"]');
  await viewer.waitFor();
  if (await viewer.getAttribute('data-pdf-page-count') !== String(fixture.pageCount)
    || await viewer.locator('canvas').count() !== fixture.pageCount) throw new Error('Viewer omitted an actual PDF page');
  const result: { page: number; width: number; height: number; ink: number; visible: boolean }[] = [];
  for (let n = 1; n <= fixture.pageCount; n++) {
    const wrapper = viewer.getByLabel(`Document page ${n}`, { exact: true });
    await wrapper.scrollIntoViewIfNeeded();
    const canvas = wrapper.locator('canvas');
    const visible = await canvas.isVisible();
    const geometry = await canvas.evaluate((node: HTMLCanvasElement) => {
      const ctx = node.getContext('2d');
      if (!ctx) throw new Error('Canvas context missing');
      const data = ctx.getImageData(0, 0, node.width, node.height).data;
      let ink = 0;
      for (let i = 0; i < data.length; i += 4) if (data[i + 3] && data[i] + data[i + 1] + data[i + 2] < 650) ink++;
      return { width: node.width, height: node.height, ink };
    });
    if (!visible || geometry.width < 200 || geometry.height < 200 || geometry.ink < 100) throw new Error('PDF page is blank, unrendered or invisible');
    result.push({ page: n, ...geometry, visible });
  }
  return result;
}

async function screenshot(page: any, name: string) {
  // Locator screenshots contain synthetic PDF content, never browser address
  // chrome, original invitations or credential-bearing response dumps.
  const target = `${fixture.artifactDir}/${name}.png`;
  await page.locator('.pdf-signer').getByLabel(`Document page ${fixture.pageCount}`, { exact: true }).screenshot({ path: target });
  screenshots.push({ name, sha256: hash(new Uint8Array(await Bun.file(target).arrayBuffer())) });
}

async function inspectOwnFields(context: any, token: string, observation: Observation, expectedIDs: string[]) {
  const response = await context.request.get(`${fixture.base}/sign/${token}/fields`);
  if (!response.ok()) throw new Error('Recipient fields unavailable');
  witnessHeaders(response.headers(), observation);
  const body = await response.json();
  if (body.fields?.length !== expectedIDs.length || body.fields.some((field: any) => !expectedIDs.includes(field.id)
    || field.document_id !== observation.document_id || field.recipient_id !== observation.recipient_id)) {
    throw new Error('Recipient received another party field or wrong artifact');
  }
  return body.fields;
}

async function inspectOwnerReadOnlyLocations() {
  const { context, page } = await newPage();
  await context.addCookies([{ name: ownerCookie![1], value: ownerCookie![2], url: fixture.base,
    httpOnly: true, secure: true, sameSite: 'Lax' }]);
  page.on('request', (request: any) => {
    if (['POST', 'PATCH', 'DELETE'].includes(request.method()) && /^\/api\/v1\/(?:documents\/[^/]+\/fields|fields\/[^/]+)/.test(new URL(request.url()).pathname)) ownerFieldMutations++;
  });
  const responses = await Promise.all([
    context.request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}/html/source`),
    context.request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}/fields`),
    context.request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}/recipients`),
  ]);
  if (responses.some((response: any) => !response.ok())) throw new Error('Owner source and generated fields unavailable');
  const [source, fieldResponse, recipientResponse] = await Promise.all(responses.map((response: any) => response.json()));
  const fields = fieldResponse.fields, recipients = recipientResponse.recipients;
  if (source.source_schema_version !== 3 || source.document_id !== fixture.documentID || source.pdf_sha256 !== fixture.pdfSHA256
      || source.html_source_commitment !== fixture.sourceCommitment || source.page_count !== fixture.pageCount
      || source.signing_page?.version !== 1 || source.signing_page?.policy !== 'hash-branded-signing-page-a4-v1'
      || source.signing_page.font_sha256 !== '3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62'
      || source.signing_page.branding?.logo_url !== '' || source.signing_page.branding?.logo_alt !== ''
      || source.signing_artifact?.composition?.output_sha256 !== fixture.pdfSHA256 || source.signing_artifact?.composition?.final_pages !== fixture.pageCount
      || source.signing_artifact?.fields?.length !== 2 || fields?.length !== 2 || recipients?.length !== 2) {
    throw new Error('Owner page source is not the automatic branded artifact');
  }
  const assignments: { slot: string; fieldID: string; recipientID: string; page: number }[] = [];
  const partyBindings = [
    ['company_name', 'company_name', 'Company name'],
    ['company_id', 'company_id', 'Company or registration identifier'],
    ['representative_name', 'name', 'Representative name'],
    ['representative_email', 'email', 'Representative email'],
    ['representative_authority', 'representative_authority', 'Declared representative authority'],
  ] as const;
  for (const slot of ['customer', 'provider']) {
    const party = source.contract_parties?.find((candidate: any) => candidate.slot === slot);
    const mapping = source.contract_profile?.parties?.find((candidate: any) => candidate.slot === slot);
    const expected = source.signing_artifact.fields.find((candidate: any) => candidate.slot === slot);
    const field = fields.find((candidate: any) => candidate.recipient_id === party?.recipient_id);
    const recipient = recipients.find((candidate: any) => candidate.id === party?.recipient_id);
    const packetParty = fixture.parties.find((candidate) => candidate.role === slot);
    if (!party || !mapping || !expected || !field || !recipient || !packetParty || party.recipient_id !== packetParty.recipientID
        || field.id !== packetParty.fieldID || field.type !== 'signature' || field.required !== true || field.document_id !== fixture.documentID
        || field.page !== fixture.pageCount || field.x_pct !== 10 || field.y_pct !== (slot === 'customer' ? 42 : 79) || field.w_pct !== 80 || field.h_pct !== 7
        || expected.page !== field.page || expected.x !== 100000 || expected.y !== field.y_pct * 10000 || expected.w !== 800000 || expected.h !== 70000
        || recipient.document_id !== fixture.documentID || recipient.role !== slot || recipient.name !== party.name || recipient.email !== party.email) {
      throw new Error('Owner generated slot differs from printed party or exact PDF');
    }
    for (const [binding, assertion] of partyBindings) {
      const declared = source.values?.find((candidate: any) => candidate.name === mapping[binding]);
      if (!declared || declared.required !== true || declared.text !== party[assertion]) throw new Error('Owner printed party assertion differs from its frozen declaration');
    }
    assignments.push({ slot, fieldID: field.id, recipientID: party.recipient_id, page: field.page });
  }
  await page.goto(`${fixture.base}/documents/${fixture.documentID}`);
  await page.getByText('Saved document information and intended parties', { exact: true }).click();
  for (const slot of ['provider', 'customer']) {
    const party = source.contract_parties.find((candidate: any) => candidate.slot === slot);
    const group = page.getByRole('region', { name: slot === 'provider' ? 'Our company' : 'Customer', exact: true });
    await group.waitFor();
    for (const [, assertion, label] of partyBindings) {
      const input = group.getByLabel(new RegExp(`^${label}\\s*\\(required\\)`));
      if (!await input.isVisible() || !await input.isDisabled() || await input.inputValue() !== party[assertion]) throw new Error('Owner saved party details do not visibly preserve their frozen printed values');
    }
  }
  await page.getByRole('button', { name: 'Signature locations', exact: true }).click();
  const designer = page.getByRole('region', { name: 'PDF signature locations', exact: true });
  await page.locator('[aria-label="PDF signature locations"][data-generated-signatures="true"][data-placement-ready="true"]').waitFor();
  await designer.getByRole('heading', { name: 'Signature locations', exact: true }).waitFor();
  if (!(await designer.getByText('Both signature locations are generated from the approved design and locked to this exact PDF and its printed parties.', { exact: false }).isVisible())
      || await designer.getByRole('button', { name: 'Remove field', exact: true }).count()
      || await designer.getByRole('combobox', { name: 'Recipient', exact: true }).count()
      || await designer.getByRole('button', { name: /^(Signature|Text|Date|Checkbox|Initial)$/ }).count()
      || await designer.locator('[data-field-id]').count() !== 2) throw new Error('Owner generated positions are not visibly locked');
  const canvas = designer.getByLabel(`Document page ${fixture.pageCount}`, { exact: true });
  await canvas.scrollIntoViewIfNeeded();
  const geometry = await canvas.evaluate((node: HTMLCanvasElement) => {
    const ctx = node.getContext('2d');
    if (!ctx) throw new Error('Owner canvas unavailable');
    const pixels = ctx.getImageData(0, 0, node.width, node.height).data;
    let ink = 0;
    for (let i = 0; i < pixels.length; i += 4) if (pixels[i + 3] && pixels[i] + pixels[i + 1] + pixels[i + 2] < 650) ink++;
    return { width: node.width, height: node.height, ink };
  });
  if (!await canvas.isVisible() || geometry.width < 200 || geometry.height < 200 || geometry.ink < 100) throw new Error('Owner signing page is not visible and rendered');
  for (const assignment of assignments) {
    const box = designer.locator(`[data-field-id="${assignment.fieldID}"][data-recipient-id="${assignment.recipientID}"]`);
    if (!await box.isVisible()) throw new Error('Owner generated party overlay is absent');
  }
  await designer.getByRole('application', { name: `Field placement layer for page ${fixture.pageCount}`, exact: true }).click();
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  if (ownerFieldMutations !== 0) throw new Error('Owner generated page dispatched a field mutation');
  const name = 'owner-automatic-signature-locations';
  const target = `${fixture.artifactDir}/${name}.png`;
  await canvas.screenshot({ path: target });
  screenshots.push({ name, sha256: hash(new Uint8Array(await Bun.file(target).arrayBuffer())) });
  ownerReadOnlyProof = { sourceSchemaVersion: 3, originalPDFSHA256: fixture.pdfSHA256, sourceCommitment: fixture.sourceCommitment,
    pageCount: fixture.pageCount, signingPage: fixture.pageCount, assignments, visibleNonblankCanvas: geometry,
    lockedPlacementVerified: true, printedPartyBindingsVerified: true, lockedExplanationVisible: true,
    manualControlsAbsent: true, attemptedPointerMutationRequests: ownerFieldMutations };
  await context.close();
}

try {
  stage = 'owner automatic signing-page locations are source-bound and read-only';
  await inspectOwnerReadOnlyLocations();
  const first = fixture.parties[0], second = fixture.parties[1];
  stage = 'failed PDF responses cannot authorize signing';
  for (const kind of ['pdf503', 'invalid_digest', 'failed_render', 'pins_mismatch', 'fields_pins_mismatch']) {
    const before = signRequests;
    const init = kind === 'failed_render' ? () => {
      const original = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function (...args: any[]) {
        if (this.closest('.pdf-signer')) throw new Error('Synthetic canvas render refusal');
        return (original as any).apply(this, args);
      } as any;
    } : undefined;
    const { context, page } = await newPage(init);
    const ctx = await contextFor(context, first.token);
    observationFor(ctx, first);
    const path = `${fixture.base}/sign/${first.token}/${kind === 'fields_pins_mismatch' ? 'fields' : 'pdf'}`;
    if (kind !== 'failed_render') await page.route(path, async (route: any) => {
      if (kind === 'pdf503') { await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Synthetic PDF outage"}' }); return; }
      const response = await route.fetch(), headers = response.headers(), body = await response.body();
      if (kind === 'invalid_digest') {
        const changed = new Uint8Array(body); changed[changed.length - 1] ^= 1;
        await route.fulfill({ response, body: Buffer.from(changed) });
      } else {
        headers['x-hash-recipient-id'] = second.recipientID;
        await route.fulfill({ response, headers, body });
      }
    });
    await page.goto(`${fixture.base}/sign/${first.token}`);
    await acknowledge(page, ctx);
    await page.locator('.pdf-signer').getByRole('alert').first().waitFor();
    await disabledGate(page);
    if (signRequests !== before || await page.locator('[data-field-id]').count()) throw new Error('Failed source rendered actionable fields or dispatched signing');
    faults.push({ case: kind, requestsToSign: signRequests - before, gateDisabled: true });
    await context.close();
  }

  stage = 'late previous-token PDF completion cannot authorize new recipient';
  {
    const before = signRequests;
    const { context, page } = await newPage();
    const ctx = await contextFor(context, first.token);
    let release!: () => void, started!: () => void;
    let settle!: (outcome: 'fulfilled' | 'aborted') => void;
    const waiting = new Promise<void>(resolve => { release = resolve; });
    const entered = new Promise<void>(resolve => { started = resolve; });
    const settled = new Promise<'fulfilled' | 'aborted'>(resolve => { settle = resolve; });
    await page.route(`${fixture.base}/sign/${first.token}/pdf`, async (route: any) => {
      let outcome: 'fulfilled' | 'aborted' = 'aborted';
      try {
        const response = await route.fetch(); started(); await waiting;
        await route.fulfill({ response }); outcome = 'fulfilled';
      } catch { /* An aborted old-token request is an allowed disposed outcome. */ }
      finally { settle(outcome); }
    });
    await page.goto(`${fixture.base}/sign/${first.token}`);
    await acknowledge(page, ctx);
    await entered;
    await disabledGate(page);
    const gateDisabledDuringOldLoad = !await page.getByRole('button', { name: 'Adopt and sign', exact: true }).isEnabled()
      && await page.locator('.pdf-signer').getAttribute('data-pdf-ready') !== 'true';
    const next = await contextFor(context, second.token), nextObservation = observationFor(next, second);
    const secondPDF = page.waitForResponse((response: any) => response.url() === `${fixture.base}/sign/${second.token}/pdf`);
    await page.evaluate((target: string) => {
      (window as any).__signerFixtureNavigationMarker = true;
      const link = document.createElement('a'); link.href = target; link.textContent = 'Open independent fixture recipient';
      link.id = 'signer-fixture-navigation'; document.body.append(link);
    }, `/sign/${second.token}`);
    await page.locator('#signer-fixture-navigation').click();
    await acknowledge(page, next);
    await renderedPages(page);
    const currentResponse = await secondPDF;
    if (!currentResponse.ok()) throw new Error('New recipient PDF unavailable after navigation');
    witnessHeaders(currentResponse.headers(), nextObservation);
    if (hash(await currentResponse.body()) !== nextObservation.pdf_sha256) throw new Error('New recipient PDF bytes changed during navigation');
    release();
    let settlementTimer: ReturnType<typeof setTimeout> | undefined;
    const lateRouteOutcome = await Promise.race([settled, new Promise<never>((_, reject) => {
      settlementTimer = setTimeout(() => reject(new Error('Previous recipient PDF request did not settle')), 20000);
    })]).finally(() => { if (settlementTimer) clearTimeout(settlementTimer); });
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    const currentRecipientReadyAfterSettlement = await page.locator('.pdf-signer').getAttribute('data-pdf-ready') === 'true';
    await page.locator(`[data-field-id="${second.fieldID}"][data-recipient-id="${second.recipientID}"]`).waitFor();
    if (!await page.evaluate(() => (window as any).__signerFixtureNavigationMarker === true)
      || !gateDisabledDuringOldLoad || !currentRecipientReadyAfterSettlement
      || await page.locator('[data-field-id]').count() !== 1
      || await page.locator(`[data-recipient-id="${first.recipientID}"]`).count()
      || signRequests !== before) throw new Error('Token route change lost its new-recipient scope');
    await inspectOwnFields(context, second.token, nextObservation, [second.fieldID]);
    faults.push({ case: 'late_previous_token', requestsToSign: signRequests - before,
      gateDisabledDuringOldLoad, currentRecipientReadyAfterSettlement, lateRouteOutcome });
    await context.close();
  }

  stage = 'legacy exact-receipt autosave and failure gating';
  let autosaveWitness: Record<string, unknown>;
  {
    const { context, page } = await newPage();
    const ctx = await contextFor(context, fixture.legacy.token), observation = observationFor(ctx, fixture.legacy, true);
    await inspectOwnFields(context, fixture.legacy.token, observation, [fixture.legacy.textFieldID, fixture.legacy.signatureFieldID]);
    await page.goto(`${fixture.base}/sign/${fixture.legacy.token}`); await acknowledge(page, ctx); await renderedPages(page);
    const adopt = page.getByRole('button', { name: 'Adopt and sign', exact: true });
    if (await adopt.isEnabled()) throw new Error('Required blank field did not block signing');
    const field = page.locator(`[data-field-id="${fixture.legacy.textFieldID}"]`);
    const endpoint = `${fixture.base}/sign/${fixture.legacy.token}/fields`;
    await page.route(endpoint, async (route: any) => {
      if (route.request().method() === 'POST') await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Synthetic save outage"}' });
      else await route.continue();
    });
    await field.fill('Unconfirmed fixture reference'); await field.blur();
    await page.getByRole('alert').filter({ hasText: 'Could not save' }).waitFor();
    if (await field.inputValue() !== '' || await adopt.isEnabled()) throw new Error('Failed autosave authorized signing or kept unconfirmed value');
    await page.unroute(endpoint);
    const saved = page.waitForResponse((response: any) => response.url() === endpoint && response.request().method() === 'POST');
    await field.fill('Agreed browser reference ÅÄÖ'); await field.blur();
    const response = await saved;
    if (!response.ok()) throw new Error('Real autosave failed');
    witnessHeaders(response.headers(), observation);
    const result = await response.json();
    if (result.updated?.length !== 1 || result.updated[0].id !== fixture.legacy.textFieldID
      || result.updated[0].recipient_id !== fixture.legacy.recipientID || result.updated[0].value !== 'Agreed browser reference ÅÄÖ') throw new Error('Autosave receipt did not confirm exact own field');
    await page.waitForFunction(() => [...document.querySelectorAll('button')].some(button => button.textContent?.trim() === 'Adopt and sign' && !button.disabled));
    const persisted = await inspectOwnFields(context, fixture.legacy.token, observation, [fixture.legacy.textFieldID, fixture.legacy.signatureFieldID]);
    if (persisted.find((f: any) => f.id === fixture.legacy.textFieldID)?.value !== 'Agreed browser reference ÅÄÖ') throw new Error('Autosave was not persisted');
    savedFields++;
    autosaveWitness = { failedSaveBlocked: true, originalValueRestored: true, exactReceiptVerified: true, persisted: true, signDispatched: false };
    await context.close();
  }

  const partyProofs: Record<string, unknown>[] = [];
  let finalPDFSHA256 = '', userVisibleDownloadVerified = false;
  for (let index = 0; index < fixture.parties.length; index++) {
    stage = `real recipient ${index + 1} visible PDF and signing`;
    const party = fixture.parties[index], { context, page } = await newPage();
    const ctx = await contextFor(context, party.token), observation = observationFor(ctx, party);
    const fields = await inspectOwnFields(context, party.token, observation, [party.fieldID]);
    const pdf = await context.request.get(`${fixture.base}/sign/${party.token}/pdf`);
    if (!pdf.ok()) throw new Error('Exact PDF read unavailable');
    witnessHeaders(pdf.headers(), observation);
    const bytes = await pdf.body();
    if (hash(bytes) !== observation.pdf_sha256) throw new Error('Original committed PDF bytes do not match server SHA');
    let release!: () => void, entered!: () => void;
    const hold = new Promise<void>(resolve => { release = resolve; });
    const started = new Promise<void>(resolve => { entered = resolve; });
    await page.route(`${fixture.base}/sign/${party.token}/pdf`, async (route: any) => {
      const response = await route.fetch(); witnessHeaders(response.headers(), observation); entered(); await hold;
      await route.fulfill({ response });
    });
    await page.goto(`${fixture.base}/sign/${party.token}`); await acknowledge(page, ctx); await started;
    await disabledGate(page);
    release();
    const geometry = await renderedPages(page);
    const own = page.locator(`[data-field-id="${party.fieldID}"][data-recipient-id="${party.recipientID}"]`);
    await own.waitFor();
    if (await page.locator('[data-field-id]').count() !== 1 || fields[0].page !== fixture.pageCount || fields[0].type !== 'signature') throw new Error('Own visible signature placement differs from exact fixture page');
    await page.getByPlaceholder('Type your full name', { exact: true }).fill(party.name);
    await screenshot(page, `recipient-${index + 1}-reviewed-signature-page`);
    const pending = page.waitForResponse((response: any) => response.url() === `${fixture.base}/sign/${party.token}/sign` && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Adopt and sign', exact: true }).click();
    await page.getByRole('button', { name: 'Sign with this signature', exact: true }).click();
    const signed = await pending;
    if (!signed.ok()) throw new Error('Real bound signature submission failed');
    const result = await signed.json();
    if (index === 0) {
      if (result.completed !== false || result.final_pdf_url) throw new Error('First signer prematurely received completed artifact');
      await page.getByText('Your signature is recorded. The document will finalise once all parties have signed.', { exact: true }).waitFor();
      if (await page.getByRole('link', { name: 'Download signed PDF', exact: true }).count()) throw new Error('Waiting signer exposed download');
    } else {
      if (result.completed !== true || typeof result.final_pdf_url !== 'string' || !result.final_pdf_url) throw new Error('Second signer did not complete bound PDF');
      await page.getByText('The document is fully signed by all parties.', { exact: true }).waitFor();
      const finalURL = new URL(result.final_pdf_url, fixture.base);
      if (finalURL.origin !== fixture.base) throw new Error('Final PDF download left disposable fixture origin');
      const downloadLink = page.getByRole('link', { name: 'Download signed PDF', exact: true });
      await downloadLink.waitFor();
      const href = await downloadLink.getAttribute('href');
      if (!href || new URL(href, fixture.base).href !== finalURL.href) throw new Error('Visible final PDF link differs from completion result');
      const completed = await context.request.get(finalURL.href);
      const completedBytes = await completed.body();
      if (!completed.ok() || completedBytes.length > 50 * 1024 * 1024
        || !completedBytes.subarray(0, 5).equals(Buffer.from('%PDF-'))) throw new Error('Time-limited final PDF download unavailable');
      finalPDFSHA256 = hash(completedBytes);
      const pendingDownload = page.waitForEvent('download');
      await downloadLink.click();
      const download = await pendingDownload;
      if (await download.failure() !== null) throw new Error('Visible final PDF download failed');
      const downloadPath = await download.path();
      if (!downloadPath) throw new Error('Visible final PDF download produced no artifact');
      const downloadedFile = Bun.file(downloadPath);
      if (downloadedFile.size > 50 * 1024 * 1024) throw new Error('Visible final PDF download exceeded artifact limit');
      const downloadedBytes = new Uint8Array(await downloadedFile.arrayBuffer());
      if (downloadedBytes.length < 5 || new TextDecoder().decode(downloadedBytes.subarray(0, 5)) !== '%PDF-'
        || hash(downloadedBytes) !== finalPDFSHA256) throw new Error('Visible final PDF download differs from completed evidence');
      userVisibleDownloadVerified = true;
    }
    partyProofs.push({ recipientID: party.recipientID, fieldID: party.fieldID, role: party.role, allPagesRenderedVisible: geometry,
      serverAndBrowserSHA256Verified: true, privacyAcknowledgedIndependently: true, ownFieldOnly: true,
      loadingGateDisabled: true, completedAfterThisSignature: result.completed });
    await context.close();
  }
  if (signRequests !== 2 || savedFields !== 1 || pageErrors.length || failedAssets.length) throw new Error('Unexpected dispatch count or browser/asset error');
  await Bun.write(fixture.receiptPath, JSON.stringify({ result: 'pass', documentID: fixture.documentID,
    scope: 'Actual built Svelte/pdf.js on disposable real Go HTTPS/PostgreSQL/source worker and exact real Chromium. S3/retention, participants, certificate key and delivery outbox synthetic; no live SMTP/provider/production/legal acceptance.',
    rendererVersion: fixture.rendererVersion, pageCount: fixture.pageCount, originalPDFSHA256: fixture.pdfSHA256,
    originalSourceCommitment: fixture.sourceCommitment, finalPDFSHA256, userVisibleDownloadVerified, manualSignaturePlacement: false,
    automaticBrandedPageSupport: true, owner: ownerReadOnlyProof, independentContexts: true, signRequests, savedFields, faults,
    autosave: autosaveWitness!, parties: partyProofs, screenshots, pageErrors, failedAssets }, null, 2) + '\n');
  console.log('PASS: exact rendered multi-page PDF, refusal gates, independent two-party signing and confirmed autosave');
} catch {
  // Never print Playwright's underlying exception: it can contain a private
  // invitation URL. Only predetermined stages and counts leave this process.
  console.error('FAILED_STAGE', stage, 'BROWSER_ERROR_COUNT', pageErrors.length, 'ASSET_FAILURE_COUNT', failedAssets.length);
  throw new Error(`Signer PDF verifier failed at ${stage}`);
} finally {
  for (const context of contexts) await context.close().catch(() => {});
  await browser.close();
}
