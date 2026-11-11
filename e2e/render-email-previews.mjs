// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
// Synthetic native-mail visual verification. No server, mailbox or credentials.
// bun render-email-previews.mjs <fresh-fixture-directory> <fresh-output-directory>
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from '@playwright/test';

const input = process.argv[2] || process.env.HASH_EMAIL_PREVIEW_DIR;
const output = process.argv[3] || process.env.HASH_EMAIL_PREVIEW_OUTPUT_DIR;
for (const value of [input, output]) {
  assert(typeof value === 'string' && path.isAbsolute(value) && value !== path.parse(value).root,
    'Explicit absolute fixture and fresh output directories are required');
}
const sourceDir = await fs.realpath(input);
const outputDir = path.resolve(output);
assert(outputDir !== sourceDir && !outputDir.startsWith(sourceDir + path.sep), 'Output must be separate from fixtures');
const stems = ['sv', 'en', 'sv-long'].flatMap(locale =>
  ['native', 'workspace-light', 'workspace-dark'].map(theme => `${locale}-${theme}`));
assert.deepEqual((await fs.readdir(sourceDir)).sort(), stems.map(stem => stem + '.html').sort(),
  'Exactly the nine native-rendered synthetic HTML fixtures are required');
const sources = new Map();
let sourceBytes = 0;
const sha256 = data => createHash('sha256').update(data).digest('hex');
for (const stem of stems) {
  const file = path.join(sourceDir, stem + '.html');
  const info = await fs.lstat(file);
  assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 262144, 'Invalid preview fixture');
  const raw = await fs.readFile(file);
  sourceBytes += raw.length;
  assert(sourceBytes <= 1048576, 'Preview fixture input budget exceeded');
  sources.set(stem, { html: raw.toString('utf8'), sha256: sha256(raw) });
}
await fs.mkdir(outputDir, { mode: 0o700 });
const cases = [
  ...['sv-native', 'sv-workspace-light', 'sv-workspace-dark'].flatMap(stem => [320, 375, 960].map(width => [stem, width])),
  ['sv-long-native', 320], ['sv-long-workspace-dark', 375], ['en-native', 375]
];
const report = { schema: 'hash-synthetic-email-previews-v1', status: 'failed', cases: [], networkRequests: 0,
  browserClosed: false, limitations: 'Chromium HTML previews; not Gmail, iPhone mail or SMTP delivery acceptance.' };
let browser;
let artifactBytes = 0;
let failed;
const deadline = Date.now() + 120000;
const remaining = (cap = 10000) => {
  const value = Math.min(cap, deadline - Date.now());
  assert(value > 0, 'Email preview deadline exceeded');
  return value;
};
const timer = setTimeout(() => { void browser?.close().catch(() => {}); }, 120000);
try {
  browser = await chromium.launch({ headless: true, timeout: remaining(30000) });
  report.browserVersion = browser.version();
  for (const [stem, width] of cases) {
    const context = await browser.newContext({ viewport: { width, height: 2200 }, deviceScaleFactor: 1,
      javaScriptEnabled: false, serviceWorkers: 'block', locale: stem.startsWith('en-') ? 'en-US' : 'sv-SE',
      colorScheme: stem.endsWith('dark') ? 'dark' : 'light' });
    try {
      await context.route('**/*', route => { report.networkRequests++; return route.abort(); });
      const page = await context.newPage();
      page.setDefaultTimeout(remaining());
      await page.setContent(sources.get(stem).html, { waitUntil: 'load', timeout: remaining() });
      await page.evaluate(() => document.fonts.ready);
      const requestText = 'Genom att signera bekräftar deltagaren endast att han har granskat detta interna testdokument och genomfört signeringsfunktionen. Signeringen gäller ingen offert, beställning eller annat kommersiellt avtal.';
      const bodyText = await page.locator('body').textContent();
      assert.equal(bodyText.split(requestText).length - 1, 2, `${stem}/${width}: full context or marked request text lost`);
      assert.deepEqual(await page.locator('blockquote').allTextContents(), [requestText, 'Test'],
        `${stem}/${width}: marked text or comment changed`);
      const geometry = await page.evaluate(() => ({
        viewport: innerWidth, scrollWidth: document.documentElement.scrollWidth,
        contentHeight: document.documentElement.scrollHeight,
        actions: [...document.querySelectorAll('a')].map(node => {
          const box = node.getBoundingClientRect();
          return { text: node.textContent.trim(), x: box.x, y: box.y, width: box.width,
            height: box.height, right: box.right, bottom: box.bottom };
        }),
        textOverflow: [...document.querySelectorAll('h1,p,blockquote,a')].some(node =>
          node.scrollWidth > node.clientWidth + 1 || node.scrollHeight > node.clientHeight + 1)
      }));
      const actions = geometry.actions;
      assert.equal(actions.length, 3, `${stem}/${width}: missing native actions`);
      assert.deepEqual(actions.map(action => action.text), stem.startsWith('en-')
        ? ['Open document', 'Approve', 'Deny'] : ['Öppna dokumentet', 'Godkänn', 'Avvisa']);
      assert(geometry.scrollWidth <= width && geometry.contentHeight <= 2200 && !geometry.textOverflow,
        `${stem}/${width}: content overflow`);
      assert(Math.abs(actions[1].y - actions[2].y) < 1 && Math.abs(actions[1].height - actions[2].height) < 1
        && Math.abs(actions[1].width - actions[2].width) < 1, `${stem}/${width}: uneven secondary buttons`);
      assert(actions[0].bottom + 10 <= actions[1].y && actions[1].right + 10 <= actions[2].x,
        `${stem}/${width}: insufficient button spacing`);
      assert(actions.every(action => action.x >= 0 && action.right <= width + 1 && action.height >= 44),
        `${stem}/${width}: hidden or undersized action`);
      assert.equal(report.networkRequests, 0, 'Synthetic email attempted a network request');
      const png = await page.screenshot({ type: 'png', timeout: remaining() });
      artifactBytes += png.length;
      assert(artifactBytes <= 6 * 1048576 - 65536, 'Email preview artifact budget exceeded');
      const filename = `${stem}-${width}.png`;
      await fs.writeFile(path.join(outputDir, filename), png, { mode: 0o600, flag: 'wx' });
      report.cases.push({ name: stem, width, geometry, sourceSHA256: sources.get(stem).sha256,
        screenshot: filename, screenshotSHA256: sha256(png), screenshotBytes: png.length });
    } finally {
      await context.close();
    }
  }
  assert.equal(report.cases.length, 12);
  assert(Date.now() < deadline, 'Email preview deadline exceeded');
  report.status = 'passed';
} catch (error) {
  failed = error;
  report.failure = error instanceof Error ? error.message : 'Email preview failed';
} finally {
  try {
    if (browser) {
      await browser.close();
      report.browserClosed = true;
    }
  } catch {
    report.status = 'failed';
    report.failure = 'Browser close failed';
    failed ||= new Error(report.failure);
  }
  clearTimeout(timer);
  const raw = JSON.stringify(report, null, 2) + '\n';
  assert(Buffer.byteLength(raw) + artifactBytes <= 6 * 1048576, 'Email preview result budget exceeded');
  await fs.writeFile(path.join(outputDir, 'RESULT.json'), raw, { mode: 0o600, flag: 'wx' });
}
if (failed) {
  process.stderr.write('Synthetic email visual verification failed; see RESULT.json.\n');
  process.exitCode = 1;
} else {
  process.stdout.write('Synthetic email visual verification passed: 12 previews; see RESULT.json.\n');
}
