// Actual Go HTTPS/magic-link/session routes and PostgreSQL; isolated synthetic participants.
import { chromium } from '../../../brightcrm/tests/e2e/node_modules/playwright';

const fixture = JSON.parse(await Bun.stdin.text()) as {
  base: string; token: string; documentID: string; cookieName: string; cookie: string;
  fieldID?: string; documentText?: string; requestMessage?: string;
  signerFollowup?: string; senderReply?: string; signerFinalReply?: string;
};
if (!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.base)
    || !/^[0-9a-f-]{36}$/i.test(fixture.documentID) || !fixture.token || !fixture.cookieName || !fixture.cookie) {
  throw new Error('Isolated HTTPS negotiation fixture required');
}
const requestMessage = fixture.requestMessage ?? 'Please revise the renewal term.';
const signerFollowup = fixture.signerFollowup ?? 'Can we discuss the renewal while signing is paused?';
const senderReply = fixture.senderReply ?? 'Yes, we can agree the renewal here before revising.';
const signerFinalReply = fixture.signerFinalReply ?? 'Thank you. Please send the revised version when ready.';
const browser = await chromium.launch({ headless: true });
const errors: string[] = [];
const signerActions: Record<string, number> = {};
let stage = 'initialization';
let page: any;
try {
  // Keep the authenticated sender session separate from the bearer-link portal.
  const owner = await browser.newContext({ ignoreHTTPSErrors: true });
  await owner.addCookies([{ name: fixture.cookieName, value: fixture.cookie, url: fixture.base,
    httpOnly: true, secure: true, sameSite: 'Lax' }]);
  const meResponse = await owner.request.get(`${fixture.base}/api/v1/me`);
  const me = await meResponse.json();
  const documentResponse = await owner.request.get(`${fixture.base}/api/v1/documents/${fixture.documentID}`);
  const document = await documentResponse.json();
  if (!meResponse.ok() || !documentResponse.ok() || document.sender_id !== me.user_id
      || document.status !== 'sent' || document.source_kind !== 'blocks') {
    throw new Error('Sent blocks document and its actual owner session required');
  }

  const signer = await browser.newContext({ ignoreHTTPSErrors: true });
  const signerPath = `/sign/${encodeURIComponent(fixture.token)}`;
  const contextResponse = await signer.request.get(`${fixture.base}${signerPath}`);
  const ceremony = await contextResponse.json();
  if (!contextResponse.ok() || ceremony.document_id !== fixture.documentID || !ceremony.privacy?.notice_digest) {
    throw new Error('Current signer notice/context required');
  }
  page = await signer.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', (error: Error) => errors.push(error.message));
  page.on('request', (request: any) => {
    const path = new URL(request.url()).pathname;
    if (request.method() === 'POST' && path.startsWith(`${signerPath}/`)) {
      const action = path.slice(signerPath.length + 1);
      signerActions[action] = (signerActions[action] ?? 0) + 1;
    }
  });
  async function acknowledgeNotice() {
    const button = page.getByRole('button', { name: ceremony.privacy.copy.acknowledgement_label, exact: true });
    if (await button.isVisible()) await button.click();
    await page.locator('.a13-overlay').waitFor({ state: 'hidden' });
  }
  async function assertPausedPortal() {
    await page.getByRole('status', { name: 'Changes requested', exact: true }).waitFor();
    const current = page.getByRole('article', { name: 'Current document' });
    await current.waitFor();
    const currentText = await current.innerText();
    if (!currentText.trim() || (fixture.documentText && !currentText.includes(fixture.documentText))) {
      throw new Error('Paused portal lost the current document');
    }
    await page.getByRole('heading', { name: 'Comments', exact: true }).waitFor();
    await page.getByPlaceholder('Ask a question…').waitFor();
    for (const name of ['Adopt and sign', 'Sign with this signature', 'Accept', 'Decline', 'Decline document', 'Save fields']) {
      if (await page.getByRole('button', { name, exact: true }).count()) throw new Error(`Paused portal exposes ${name}`);
    }
    if (await page.locator('.signer-actions input, .signer-actions select').count()) {
      throw new Error('Paused portal exposes name or fillable-field controls');
    }
    if (signerActions.sign || signerActions.accept || signerActions.decline || signerActions.fields || signerActions['qes/start']) {
      throw new Error('Negotiation dispatched a signature, acceptance, decline or field mutation');
    }
  }
  async function postSignerComment(body: string) {
    const draft = page.getByPlaceholder('Ask a question…');
    await draft.fill(body);
    const receipt = page.waitForResponse((response: any) => new URL(response.url()).pathname === `${signerPath}/comments`
      && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Send comment', exact: true }).click();
    if ((await receipt).status() !== 201) throw new Error('Signer reply was not committed');
    await page.getByText(body, { exact: true }).waitFor();
    if (await draft.inputValue() !== '') throw new Error('Confirmed comment left the submitted draft unsent');
    await assertPausedPortal();
  }

  stage = 'notice-gated request changes';
  await page.goto(`${fixture.base}${signerPath}`);
  await page.getByRole('article', { name: 'Current document' }).waitFor();
  await acknowledgeNotice();
  if (fixture.fieldID) await page.getByPlaceholder('Negotiation reference', { exact: true }).waitFor();
  const retainedDraft = 'Keep this conversation draft after requesting changes.';
  await page.getByPlaceholder('Ask a question…').fill(retainedDraft);
  await page.getByRole('button', { name: 'Request changes', exact: true }).click();
  await page.getByPlaceholder('What should change?', { exact: true }).fill(requestMessage);
  const changesReceipt = page.waitForResponse((response: any) => new URL(response.url()).pathname === `${signerPath}/request-changes`
    && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Send request', exact: true }).click();
  if ((await changesReceipt).status() !== 200) throw new Error('Change request was not committed');
  await assertPausedPortal();
  if (await page.getByPlaceholder('Ask a question…').inputValue() !== retainedDraft) {
    throw new Error('Pausing signing discarded the local conversation draft');
  }

  stage = 'reopened waiting portal';
  await page.reload();
  await page.getByRole('status', { name: 'Changes requested', exact: true }).waitFor();
  await acknowledgeNotice();
  await assertPausedPortal();
  await postSignerComment(signerFollowup);

  stage = 'authenticated sender reply';
  const senderReceipt = await owner.request.post(`${fixture.base}/api/v1/documents/${fixture.documentID}/comments`, {
    data: { body: senderReply }, headers: { Origin: fixture.base }
  });
  if (senderReceipt.status() !== 201) throw new Error('Sender reply was not committed');

  stage = 'recipient returns from sender notification';
  await page.reload();
  await page.getByRole('status', { name: 'Changes requested', exact: true }).waitFor();
  await acknowledgeNotice();
  await page.getByText(signerFollowup, { exact: true }).waitFor();
  await page.getByText(senderReply, { exact: true }).waitFor();
  await assertPausedPortal();
  await postSignerComment(signerFinalReply);
  if (signerActions['request-changes'] !== 1 || signerActions.comments !== 2) throw new Error('Unexpected negotiation dispatch counts');
  if (errors.length) throw new Error('Browser exceptions during negotiation');

  await page.screenshot({ path: '/private/tmp/hash-browser-negotiation.png', fullPage: true });
  await Bun.write('/private/tmp/hash-browser-negotiation-receipt.json', JSON.stringify({
    result: 'pass', documentID: fixture.documentID,
    documentVisibleAfterRequestAndReload: true, conversationDraftRetainedOnPause: true,
    signerFollowupVisible: true, senderReplyVisibleAfterReturn: true, signerFinalReplyVisible: true,
    pausedSigningControlsAbsent: true, signerActions, browserErrors: errors,
    scope: 'actual rendered magic-link portal and Go HTTPS/PostgreSQL request/comment APIs; synthetic parties, no SMTP delivery'
  }, null, 2));
  console.log('PASS: paused signer portal keeps document and conversation, preserves draft, receives sender reply and continues without signing/field mutations');
} catch (error) {
  console.error('FAILED_STAGE', stage, 'BROWSER_ERROR_COUNT', errors.length);
  if (page) await page.screenshot({ path: '/private/tmp/hash-browser-negotiation-failed.png', fullPage: true });
  // Do not include bearer link URLs, cookies or browser exception text in stdout.
  throw new Error(`Negotiation verifier failed at ${stage}: ${error instanceof Error ? error.message.replaceAll(fixture.token, '[redacted]') : 'unknown error'}`);
} finally { await browser.close(); }
