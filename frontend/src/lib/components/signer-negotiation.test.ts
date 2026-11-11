import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { signerPackageIncorporations } from '../signerPackageIncorporation';

const source = readFileSync(new URL('../../routes/sign/[token]/+page.svelte', import.meta.url), 'utf8');
const pdfSource = readFileSync(new URL('./PdfSignerView.svelte', import.meta.url), 'utf8');
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function between(text: string, start: string, end: string) {
  const offset = text.indexOf(start);
  const finish = text.indexOf(end, offset);
  if (offset < 0 || finish < 0) throw new Error('Production callback not found');
  return text.slice(offset, finish);
}
const pause = between(source, '  function pauseSigningForChanges()', '  // v1.2:');
function bind(code: string, name: string, env: Record<string, unknown>) {
  return new Function('env', `with (env) { ${transpiler.transformSync(code)}; return ${name}; }`)(env);
}
function fixture() {
  const calls: any[] = [];
  const env: any = {
    ctx: { recipient: { id: 'recipient' }, privacy: { notice_digest: 'current-notice' } },
    $page: { params: { token: 'token' } }, noticeAcknowledged: true,
    changesMessage: 'Please revise the term', changesRequested: false, requestingChanges: false,
    documentHTML: '<p>Current contract</p>', comments: [{ id: 'old', body: 'Prior question' }], commentBody: 'Unsent conversation draft',
    showAdoptModal: true, showDeclineModal: true, showChangesModal: true, showAnno: true,
    annoComment: 'Please clarify', annoProposed: 'Clear term', annoQuote: 'term', annoContext: 'Current term', annoBlockId: 'block', annoCount: 0,
    signError: null, annoError: null,
    $t: (key: string) => key, signerNoticeHeaders: (digest: string, acknowledged: boolean) => ({ digest, acknowledged }),
    window: { getSelection: () => ({ removeAllRanges() {} }) },
    fetch: (url: string, options: unknown) => new Promise((resolve, reject) => calls.push({ url, options, resolve, reject }))
  };
  env.pauseSigningForChanges = bind(pause, 'pauseSigningForChanges', env);
  const general = bind(between(source, '  async function confirmRequestChanges()', '  function fontFamilyFor('), 'confirmRequestChanges', env);
  const inline = bind(between(source, '  async function submitAnno()', '  function pauseSigningForChanges()'), 'submitAnno', env);
  return { env, calls, general, inline };
}

test('confirmed general and inline requests pause signing while retaining the document, thread and chat draft', async () => {
  for (const kind of ['general', 'inline'] as const) {
    const fixtureState = fixture();
    const { env, calls } = fixtureState;
    const pending = fixtureState[kind]();
    await fixtureState[kind]();
    expect(calls).toHaveLength(1);
    expect(calls[0].options.headers).toEqual({ digest: 'current-notice', acknowledged: true });
    expect(env.requestingChanges).toBe(true);
    calls[0].resolve({ ok: true });
    await pending;
    expect(env.changesRequested).toBe(true);
    expect(env.requestingChanges).toBe(false);
    expect(env.documentHTML).toBe('<p>Current contract</p>');
    expect(env.comments).toEqual([{ id: 'old', body: 'Prior question' }]);
    expect(env.commentBody).toBe('Unsent conversation draft');
    for (const modal of ['showAdoptModal', 'showDeclineModal', 'showChangesModal', 'showAnno']) expect(env[modal]).toBe(false);
  }
});

test('failed or unacknowledged proposals keep the ceremony state and proposal draft', async () => {
  for (const kind of ['general', 'inline'] as const) {
    const state = fixture();
    const pending = state[kind]();
    state.calls[0].resolve({ ok: false, text: async () => 'Please retry' });
    await pending;
    expect(state.env.changesRequested).toBe(false);
    expect(state.env.requestingChanges).toBe(false);
    expect(state.env.changesMessage).toBe('Please revise the term');
    expect(state.env.annoComment).toBe('Please clarify');
    expect(state.env[kind === 'general' ? 'signError' : 'annoError']).toBe('Please retry');
    const unacknowledged = fixture();
    unacknowledged.env.noticeAcknowledged = false;
    await unacknowledged[kind]();
    expect(unacknowledged.calls).toHaveLength(0);
    expect(unacknowledged.env.changesRequested).toBe(false);
  }
});

test('late proposal responses cannot pause a different recipient or release its pending state', async () => {
  for (const kind of ['general', 'inline'] as const) {
    const state = fixture();
    const pending = state[kind]();
    state.env.$page.params.token = 'other-token';
    state.env.ctx.recipient.id = 'other-recipient';
    state.env.signError = 'Current error';
    state.calls[0].resolve({ ok: true });
    await pending;
    expect(state.env.changesRequested).toBe(false);
    expect(state.env.requestingChanges).toBe(true);
    expect(state.env.signError).toBe('Current error');
    expect(state.env.showAdoptModal).toBe(true);
  }
});

test('paused or pending proposals prevent signature, acceptance and decline callbacks from starting', async () => {
  const callbacks = [
    ['adopt', '  async function adopt()', '  function acknowledgeCurrentNotice()'],
    ['confirmSign', '  async function confirmSign()', '  async function decline()'],
    ['decline', '  async function decline()', '  async function accept()'],
    ['accept', '  async function accept()', '  async function confirmDecline()'],
    ['confirmDecline', '  async function confirmDecline()', '  function requestChanges()']
  ];
  for (const gate of ['changesRequested', 'requestingChanges']) {
    for (const [name, start, end] of callbacks) {
      const { env, calls } = fixture();
      env[gate] = true;
      env.showAdoptModal = false;
      env.showDeclineModal = false;
      await bind(between(source, start, end), name, env)();
      expect(calls).toHaveLength(0);
      expect(env.showAdoptModal).toBe(false);
      expect(env.showDeclineModal).toBe(false);
    }
  }
});

test('paused document still permits further inline proposals without re-enabling signing', async () => {
  const { env, calls, inline } = fixture();
  env.changesRequested = true;
  const pending = inline();
  expect(calls).toHaveLength(1);
  calls[0].resolve({ ok: true });
  await pending;
  expect(env.changesRequested).toBe(true);
  expect(env.annoCount).toBe(1);
});

test('PDF read-only mode independently rejects field writes', async () => {
  let writes = 0;
  const env = { readOnly: true, fetch: () => { writes++; throw new Error('Unexpected field write'); } };
  const save = bind(between(pdfSource, '  async function saveField(', '  function fieldsOnPage('), 'saveField', env);
  await save({ id: 'field', type: 'text' });
  expect(writes).toBe(0);
});

// Compile the actual page fragments, not a second hand-written set of controls.
// This is localized SSR coverage only; it grants no recipient or ceremony proof.
let localizedRoomRenderer: Promise<any> | undefined;
function localizedRoomControls() {
  return localizedRoomRenderer ??= (async () => {
    const view = between(source, '        {#if viewState.error}', '        {#if changesRequested}');
    const pausedStart = source.indexOf('<section class="negotiation-status"');
    const pausedEnd = source.indexOf('</section>', pausedStart);
    if (pausedStart < 0 || pausedEnd < 0) throw new Error('Actual paused signer guidance missing');
    const paused = source.slice(pausedStart, pausedEnd + '</section>'.length);
    const history = between(source, '          <nav aria-label={$t(\'comments.history\')}', '          {#if comments.length}');
    const languageStart = source.indexOf('<span class="ceremony-language">');
    const languageEnd = source.indexOf('</span>', languageStart);
    if (languageStart < 0 || languageEnd < 0) throw new Error('Actual signer interface-language label missing');
    const languageLabel = source.slice(languageStart, languageEnd + '</span>'.length);
    const noticeSource = readFileSync(new URL('./A13Notice.svelte', import.meta.url), 'utf8');
    const packageSource = readFileSync(new URL('./SignerPackageReview.svelte', import.meta.url), 'utf8');
    const noticeTitle = between(noticeSource, '<h2 id="a13-title">', '</h2>') + '</h2>';
    const incorporation = '<span>{value.incorporation.text}</span>';
    if (!packageSource.includes(incorporation)) throw new Error('Actual verbatim incorporation slot changed');
    const lib = fileURLToPath(new URL('../', import.meta.url));
    const catalog = resolve(lib, 'i18n.ts');
    const incorporations = resolve(lib, 'signerPackageIncorporation.ts');
    const fragment = `<script>
      import { t } from ${JSON.stringify(catalog)};
      import { signerPackageIncorporations } from ${JSON.stringify(incorporations)};
      let { loading = false, hasError = true, canonicalPrivacy = '', privacyLocale, packageLocale, packageVersion = 'hash-package-incorporation-v1', reviewKey = 'current', reviewSettled = true } = $props();
      const ctx = { privacy: { copy_locale: privacyLocale } };
      const packageReview = { key: reviewKey, settled: reviewSettled, canonicalLocale: packageLocale };
      const currentCeremonyKey = () => 'current';
      const viewState = { error: hasError ? 'Internal view diagnostic' : null, pending: false };
      const documentDisplayed = () => true;
      const noticeAcknowledged = true;
      const viewRecorder = { retry() {} };
      const commentLoading = loading, postingComment = false;
      const olderCommentCursor = 'A'.repeat(76), newerCommentCursor = 'B'.repeat(76);
      const commentRefreshError = hasError ? 'Internal message diagnostic' : null;
      const loadComments = () => {}, commentHistory = { retry() {} };
      const privacy = { copy: { title: canonicalPrivacy } }, value = { incorporation: { version: packageVersion, ...signerPackageIncorporations[packageVersion] } };
    </script>${languageLabel}${view}${paused}${history}${noticeTitle}${incorporation}`;
    const result = await Bun.build({ entrypoints: ['signer-room-localized-controls'], target: 'bun', plugins: [{ name: 'actual-signer-localized-controls', setup(build) {
      build.onResolve({ filter: /^signer-room-localized-controls$/ }, () => ({ path: 'entry', namespace: 'signer-copy' }));
      build.onResolve({ filter: /^signer-room-localized-view$/ }, () => ({ path: 'view', namespace: 'signer-copy' }));
      build.onLoad({ filter: /.*/, namespace: 'signer-copy' }, args => args.path === 'view'
        ? { contents: compile(fragment, { filename: 'signer-room-controls.svelte', generate: 'server' }).js.code, loader: 'js', resolveDir: process.cwd() }
        : { contents: `import View from 'signer-room-localized-view'; import { render } from 'svelte/server'; import { get } from 'svelte/store'; import { locale, t } from ${JSON.stringify(catalog)}; export { View, render, get, locale, t };`, loader: 'ts', resolveDir: process.cwd() });
      build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!result.success) throw new Error(result.logs.map(String).join('\n'));
    const directory = mkdtempSync(join(tmpdir(), 'hash-signer-copy-'));
    try {
      const file = join(directory, 'view.mjs');
      writeFileSync(file, await result.outputs[0].text());
      return await import(pathToFileURL(file).href);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  })();
}

test('actual signer retry, history and paused-guidance fragments render selected EN/SV copy without exposing internal errors', async () => {
  const m = await localizedRoomControls();
  try {
    for (const language of ['en', 'sv']) {
      m.locale.set(language);
      const html = m.render(m.View, { props: { loading: true, hasError: true } }).body;
      const expected = language === 'sv'
        ? ['Svenskt gränssnitt.', 'Integritetsinformation: engelska.', 'Försök bekräfta visningen igen', 'Meddelandehistorik', 'Äldre', 'Nyare', 'Senaste', 'Läser in meddelanden…', 'Försök läsa in meddelandena igen', 'Signering och ändringar i fälten är pausade.']
        : ['English interface.', 'Privacy notice: English.', 'Retry view confirmation', 'Message history', 'Older', 'Newer', 'Latest', 'Loading messages…', 'Retry message refresh', 'Signing and field changes are paused.'];
      for (const copy of expected) expect(html).toContain(copy);
      expect(html).not.toContain('Internal view diagnostic');
      expect(html).not.toContain('Internal message diagnostic');
      if (language === 'sv') expect(html).not.toContain('Retry view confirmation');
    }
  } finally { m.locale.set('en'); }
});

test('Swedish interface labels the actual server privacy language and frozen package version without translating canonical slots', async () => {
  const m = await localizedRoomControls();
  try {
    m.locale.set('sv');
    for (const privacyLocale of [undefined, 'en', 'sv']) {
      for (const packageVersion of ['hash-package-incorporation-v1', 'hash-package-incorporation-sv-v1'] as const) {
        const incorporation = signerPackageIncorporations[packageVersion];
        const canonicalPrivacy = privacyLocale === 'sv'
          ? 'Innan du svarar: så hanterar vi dina personuppgifter'
          : 'Before you respond: how your data is handled';
        const html = m.render(m.View, { props: { canonicalPrivacy, privacyLocale, packageVersion, packageLocale: incorporation.locale } }).body;
        expect(html).toContain(privacyLocale === 'sv' ? 'Integritetsinformation: svenska.' : 'Integritetsinformation: engelska.');
        expect(html).toContain(incorporation.locale === 'sv' ? 'Godkännande av avtalspaketet: svenska.' : 'Godkännande av avtalspaketet: engelska.');
        expect(html).toContain(canonicalPrivacy);
        expect(html).toContain(incorporation.text);
        expect(html).not.toContain(signerPackageIncorporations[packageVersion === 'hash-package-incorporation-v1' ? 'hash-package-incorporation-sv-v1' : 'hash-package-incorporation-v1'].text);
      }
    }
  } finally { m.locale.set('en'); }
});

test('package-language label requires settled current validated metadata and never follows the interface language', async () => {
  const m = await localizedRoomControls();
  try {
    m.locale.set('sv');
    for (const props of [{}, { packageLocale: 'en', reviewSettled: false }, { packageLocale: 'en', reviewKey: 'stale' }]) {
      const html = m.render(m.View, { props }).body;
      expect(html).not.toContain('Godkännande av avtalspaketet:');
      expect(html).toContain('Svenskt gränssnitt.');
    }
    m.locale.set('en');
    const html = m.render(m.View, { props: { privacyLocale: 'sv', packageLocale: 'sv', packageVersion: 'hash-package-incorporation-sv-v1' } }).body;
    expect(html).toContain('Privacy notice: Swedish.'); expect(html).toContain('Package consent: Swedish.');
    expect(html).toContain(signerPackageIncorporations['hash-package-incorporation-sv-v1'].text);
  } finally { m.locale.set('en'); }
});

test('every existing signer-page catalog lookup has explicit distinct Swedish copy as well as English', async () => {
  const m = await localizedRoomControls();
  const keys = [...new Set([...source.matchAll(/\$t\('([^']+)'/g)].map(match => match[1]))];
  try {
    m.locale.set('en'); const en = m.get(m.t);
    m.locale.set('sv'); const sv = m.get(m.t);
    for (const key of keys) {
      expect(en(key)).not.toBe(key);
      expect(sv(key)).not.toBe(key);
      expect(sv(key)).not.toBe(en(key));
    }
  } finally { m.locale.set('en'); }
});
