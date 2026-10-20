import { expect, test } from 'bun:test';
import { signerCeremonyKey, signerPDFScopeKey, validateSignerPDFObservation } from '../signerPDF';
import { createSignerViewRecorder } from '../signerView';
import { completionArtifactLinks } from '../completionArtifacts';
import { checkedSignerPackage, signerPackageResponse } from '../signerPackage';

const source = await Bun.file(new URL('../../routes/sign/[token]/+page.svelte', import.meta.url)).text();
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function bind(start: string, end: string, name: string, env: any) {
  const offset = source.indexOf(start);
  const finish = source.indexOf(end, offset);
  if (offset < 0 || finish < 0) throw new Error('Production callback not found');
  return new Function('env', `with (env) { ${transpiler.transformSync(source.slice(offset, finish))}; return ${name}; }`)(env);
}
function fixture(kind = 'pdf', packageObserved = true) {
  const calls: any[] = [];
  const documentID = '10000000-0000-4000-8000-000000000001';
  const recipientID = '20000000-0000-4000-8000-000000000001';
  const env: any = {
    ctx: { document_id: documentID, source_kind: kind, status: 'sent', recipient: { id: recipientID, status: 'pending' },
      privacy: { notice_digest: 'current-notice' }, pdf_observation: kind === 'pdf' ? { document_id: documentID, recipient_id: recipientID, pdf_sha256: 'a'.repeat(64) } : undefined },
    $page: { params: { token: 'original-token' } }, loadedToken: 'original-token', routeDisposed: false,
    fieldsFilled: true, documentReady: kind === 'blocks', viewerScopeKey: '', noticeAcknowledged: true,
    ceremonyEpoch: 1, acknowledgedSourceKind: kind, acknowledgedScopeKey: '',
    packageReview: { key: '', ready: false, settled: false }, commentLoading: false, initialCommentKey: '',
    viewState: { pending: false, confirmed: false, error: null },
    signing: false, accepting: false, declining: false, requestingChanges: false, changesRequested: false,
    completed: null, accepted: false, declined: false, typedName: 'Current signer', chosenFont: 'Caveat', showAdoptModal: false,
    signError: null, loadError: null, documentHTML: '',
    signerCeremonyKey, signerPDFScopeKey, validateSignerPDFObservation, completionArtifactLinks,
    signerNoticeHeaders: (digest: string, acknowledged: boolean) => ({ digest, acknowledged }),
    setLocale() {}, loadComments() {}, synchronizeCommentScope() {}, tick: async () => {},
    fetch: (url: string, options: unknown) => new Promise((resolve, reject) => calls.push({ url, options, resolve, reject }))
  };
  const gateFunctions = source.slice(source.indexOf('  function currentCeremonyKey()'), source.indexOf('  $effect.pre('));
  const helpers = new Function('env', `with (env) { ${transpiler.transformSync(gateFunctions)}; return {currentCeremonyKey, documentDisplayed, viewerReady, packageReady, packageCanLoad, updatePackageReview, updatePDFGate, updatePDFReady, adoptPDF, currentViewScope, viewScopeCurrent}; }`)(env);
  Object.assign(env, helpers);
  env.viewRecorder = createSignerViewRecorder({ fetch: env.fetch, current: env.viewScopeCurrent, changed: state => { env.viewState = state; } });
  env.acknowledgedScopeKey = env.currentCeremonyKey();
  if (kind === 'pdf') {
    const scope = { token: env.loadedToken, noticeDigest: env.ctx.privacy.notice_digest, observation: { ...env.ctx.pdf_observation } };
    env.updatePDFGate(true, scope);
    env.updatePDFReady(true, scope);
  }
  const observeNoPackage = () => {
    const scope = { token: env.loadedToken, key: env.currentCeremonyKey(), documentID: env.ctx.document_id,
      recipientID: env.ctx.recipient.id, noticeDigest: env.ctx.privacy.notice_digest, observation: env.ctx.pdf_observation };
    expect(checkedSignerPackage({ package: null }, scope)).toBeNull();
    env.updatePackageReview({ key: scope.key, ready: true }, env.ceremonyEpoch);
  };
  if (packageObserved) observeNoPackage();
  const adopt = bind('  async function adopt()', '  function acknowledgeCurrentNotice()', 'adopt', env);
  env.adopt = adopt;
  const sign = bind('  async function confirmSign()', '  async function decline()', 'confirmSign', env);
  const accept = bind('  async function accept()', '  async function confirmDecline()', 'accept', env);
  const load = bind('  async function load(', '  onMount(', 'load', env);
  return { env, calls, adopt, sign, accept, load, observeNoPackage };
}

test('ordinary no-package ceremonies wait for the actual current metadata review callback', async () => {
  for (const kind of ['pdf', 'blocks']) {
    const f = fixture(kind, false);
    expect(f.env.viewerReady()).toBe(true);
    expect(f.env.packageReady()).toBe(false);
    await f.adopt(); await f.sign(); await f.accept();
    expect(f.calls).toHaveLength(0); expect(f.env.showAdoptModal).toBe(false);
    f.observeNoPackage();
    expect(f.env.packageReady()).toBe(true);
    await f.adopt(); expect(f.env.showAdoptModal).toBe(true);
    const pending = f.accept();
    expect(f.calls).toHaveLength(1);
    expect(JSON.parse(f.calls[0].options.body)).toEqual({});
    f.calls[0].resolve({ ok: true, json: async () => ({ completed: false }) }); await pending;
    expect(f.env.accepted).toBe(true);
  }
});

test('adopt, sign and accept independently refuse missing, stale, unconsented or reset package review', async () => {
  for (const condition of ['missing', 'stale-key', 'stale-epoch', 'unconsented', 'reset-after-consent']) {
    for (const action of ['adopt', 'sign', 'accept'] as const) {
      const f = fixture('pdf', false);
      const key = f.env.currentCeremonyKey(), epoch = f.env.ceremonyEpoch;
      if (condition === 'stale-key') {
        f.observeNoPackage();
        f.env.ctx.pdf_observation.pdf_sha256 = 'b'.repeat(64);
        const freshPDFScope = { token: f.env.loadedToken, noticeDigest: f.env.ctx.privacy.notice_digest,
          observation: { ...f.env.ctx.pdf_observation } };
        f.env.updatePDFReady(true, freshPDFScope); f.env.updatePDFGate(true, freshPDFScope);
        f.env.updatePackageReview({ key, ready: true }, epoch);
      }
      if (condition === 'stale-epoch') f.env.updatePackageReview({ key, ready: true }, epoch - 1);
      if (condition === 'unconsented') f.env.updatePackageReview({ key, ready: false }, epoch);
      if (condition === 'reset-after-consent') {
        f.env.updatePackageReview({ key, ready: true }, epoch);
        f.env.updatePackageReview({ key, ready: false }, epoch);
      }
      expect(f.env.viewerReady()).toBe(true); expect(f.env.packageReady()).toBe(false);
      await f[action]();
      expect(f.calls).toHaveLength(0); expect(f.env.showAdoptModal).toBe(false);
    }
  }
});

test('package review callbacks cannot reopen or close a later generation after A to B to A', () => {
  const f = fixture('pdf', false), key = f.env.currentCeremonyKey(), firstEpoch = f.env.ceremonyEpoch;
  f.env.ceremonyEpoch += 2;
  f.env.updatePackageReview({ key, ready: true }, firstEpoch);
  expect(f.env.packageReady()).toBe(false);
  f.env.updatePackageReview({ key, ready: true }, f.env.ceremonyEpoch);
  expect(f.env.packageReady()).toBe(true);
  f.env.updatePackageReview({ key, ready: false }, firstEpoch);
  expect(f.env.packageReady()).toBe(true);
});

test('only current whole-package consent dispatches the exact observed package response for sign and accept', async () => {
  for (const action of ['sign', 'accept'] as const) {
    const f = fixture('pdf', false);
    const key = f.env.currentCeremonyKey(), epoch = f.env.ceremonyEpoch;
    const scope = { token: f.env.loadedToken, key, documentID: f.env.ctx.document_id,
      recipientID: f.env.ctx.recipient.id, noticeDigest: f.env.ctx.privacy.notice_digest, observation: f.env.ctx.pdf_observation };
    // The component's transport/hash and all-pages review have their own
    // tests. This fixture exercises its callback boundary and the real route.
    const value = checkedSignerPackage({ package: {
      schema: 'hash-recipient-package-v1', package_id: '30000000-0000-4000-8000-000000000001', revision: '7',
      manifest_sha256: 'b'.repeat(64), legal_commitment_sha256: 'c'.repeat(64),
      main: { title: 'Main agreement', category: '', pdf_sha256: 'a'.repeat(64), bytes: 100, pages: 1 },
      annexes: [{ title: 'DPA', category: 'Data protection', pdf_sha256: 'd'.repeat(64), bytes: 80, pages: 1 }],
      incorporation: { version: 'hash-package-incorporation-v1', sha256: 'e'.repeat(64), text: 'Synthetic package consent copy' }
    } }, scope);
    if (!value) throw new Error('Expected the observed package fixture');
    const response = signerPackageResponse(value), expectedResponse = { ...response };
    f.env.updatePackageReview({ key, ready: false }, epoch);
    await f[action](); expect(f.calls).toHaveLength(0);
    f.env.updatePackageReview({ key, ready: true, response }, epoch);
    // The production callback owns its copy; a component's later mutation
    // cannot silently change the observation that the route will submit.
    response.manifest_sha256 = 'f'.repeat(64);
    f.env.updatePackageReview({ key, ready: false }, epoch - 1);
    expect(f.env.packageReady()).toBe(true);
    await f.adopt(); expect(f.env.showAdoptModal).toBe(true);
    const pending = f[action]();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0].url).toBe(`/sign/original-token/${action}`);
    const body = JSON.parse(f.calls[0].options.body);
    expect(body).toEqual(action === 'sign' ? { typed_name: 'Current signer', font: 'Caveat', package_response: expectedResponse }
      : { package_response: expectedResponse });
    f.calls[0].resolve({ ok: true, json: async () => ({ completed: false }) }); await pending;
  }
});

test('PDF adoption, confirmation and acknowledgement refuse unrendered, stale, failed or busy ceremonies programmatically', async () => {
  for (const condition of ['not-rendered', 'missing-observation', 'unsaved-fields', 'navigation', 'disposed', 'signing', 'accepting', 'declining', 'requestingChanges', 'changesRequested', 'not-acknowledged']) {
    for (const action of ['adopt', 'sign', 'accept'] as const) {
      const state = fixture();
      if (condition === 'not-rendered') state.env.viewerScopeKey = '';
      else if (condition === 'missing-observation') state.env.ctx.pdf_observation = undefined;
      else if (condition === 'unsaved-fields') state.env.fieldsFilled = false;
      else if (condition === 'navigation') state.env.$page.params.token = 'next-token';
      else if (condition === 'disposed') state.env.routeDisposed = true;
      else if (condition === 'not-acknowledged') state.env.noticeAcknowledged = false;
      else state.env[condition] = true;
      await state[action]();
      expect(state.calls).toHaveLength(0);
      expect(state.env.showAdoptModal).toBe(false);
    }
  }
});

test('a current complete PDF gate allows adoption and only one signing dispatch', async () => {
  const state = fixture();
  await state.adopt(); expect(state.env.showAdoptModal).toBe(true);
  const pending = state.sign(); await state.sign();
  expect(state.calls).toHaveLength(1);
  expect(state.calls[0].url).toBe('/sign/original-token/sign');
  expect(state.calls[0].options.headers).toEqual({ digest: 'current-notice', acknowledged: true });
  state.calls[0].resolve({ ok: true, json: async () => ({ completed: false }) }); await pending;
  expect(state.env.completed).toEqual({ terminal: false, links: null });
  expect(state.env.signing).toBe(false);
});

test('the real PDF readiness callback enables adoption for the exact observed context and closes it on false or drift', async () => {
  for (const extra of [{}, { html_source_commitment: 'b'.repeat(64) },
    { html_source_commitment: 'b'.repeat(64), page_count: 3, materialization_revision: 2 }]) {
    const state = fixture();
    state.env.ctx.pdf_observation = { ...state.env.ctx.pdf_observation, ...extra };
    state.observeNoPackage();
    const observed = { token: state.env.loadedToken, noticeDigest: state.env.ctx.privacy.notice_digest,
      observation: { ...state.env.ctx.pdf_observation } };
    state.env.fieldsFilled = false; state.env.viewerScopeKey = '';
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(false);
    state.env.updatePDFGate(true, observed);
    expect(state.env.fieldsFilled).toBe(true);
    expect(state.env.viewerReady()).toBe(false);
    state.env.updatePDFReady(true, observed);
    expect(state.env.viewerScopeKey).toBe(state.env.currentCeremonyKey());
    expect(state.env.viewerReady()).toBe(true);
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(true);
    state.env.showAdoptModal = false;
    state.env.updatePDFGate(false, observed);
    expect(state.env.viewerReady()).toBe(false);
    expect(state.env.documentDisplayed()).toBe(true);
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(false);
    state.env.ctx.pdf_observation.pdf_sha256 = 'c'.repeat(64);
    state.env.updatePDFGate(true, observed);
    state.env.updatePDFReady(true, observed);
    expect(state.env.viewerReady()).toBe(false);
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(false);
    expect(state.calls).toHaveLength(0);
  }
});

test('PDF callbacks cannot open the gate after any token, notice, party or artifact drift', () => {
  for (const part of ['token', 'notice', 'document', 'recipient', 'pdf', 'revision']) {
    const state = fixture();
    const original = { token: state.env.loadedToken, noticeDigest: state.env.ctx.privacy.notice_digest, observation: { ...state.env.ctx.pdf_observation } };
    state.env.fieldsFilled = false; state.env.viewerScopeKey = '';
    if (part === 'token') state.env.$page.params.token = 'next-token';
    if (part === 'notice') state.env.ctx.privacy.notice_digest = 'next-notice';
    if (part === 'document') state.env.ctx.pdf_observation.document_id = state.env.ctx.recipient.id;
    if (part === 'recipient') state.env.ctx.pdf_observation.recipient_id = state.env.ctx.document_id;
    if (part === 'pdf') state.env.ctx.pdf_observation.pdf_sha256 = 'b'.repeat(64);
    if (part === 'revision') state.env.ctx.pdf_observation.materialization_revision = 2;
    state.env.updatePDFGate(true, original);
    expect(state.env.fieldsFilled).toBe(false);
    expect(state.env.viewerReady()).toBe(false);
  }
});

test('block ceremony keys retain document and recipient identity independently of the notice digest', () => {
  const state = fixture('blocks');
  const original = state.env.currentCeremonyKey();
  state.env.ctx.document_id = '40000000-0000-4000-8000-000000000001';
  expect(state.env.currentCeremonyKey()).not.toBe(original);
  const changedDocument = state.env.currentCeremonyKey();
  state.env.ctx.recipient.id = '50000000-0000-4000-8000-000000000001';
  expect(state.env.currentCeremonyKey()).not.toBe(changedDocument);
});

test('a changed block ceremony immediately loses the document and notice readiness before another callback can adopt', async () => {
  const state = fixture('blocks');
  let callback!: () => void;
  state.env.$effect = { pre: (fn: () => void) => { callback = fn; } };
  state.env.untrack = (fn: () => void) => fn();
  state.env.acknowledgedScopeKey = state.env.currentCeremonyKey();
  const start = source.indexOf('  $effect.pre(() => {');
  const end = source.indexOf('  $effect(() => {', start);
  new Function('env', `with (env) { ${transpiler.transformSync(source.slice(start, end))}; }`)(state.env);
  state.env.ctx.recipient.id = '50000000-0000-4000-8000-000000000001';
  callback();
  expect(state.env.documentReady).toBe(false);
  expect(state.env.noticeAcknowledged).toBe(false);
  expect(state.env.viewerScopeKey).toBe('');
  await state.adopt(); expect(state.env.showAdoptModal).toBe(false); expect(state.calls).toHaveLength(0);
});

test('token load effect resets and starts async work untracked, then aborts its original load on cleanup', () => {
  const start = source.indexOf('  $effect(() => {\n    const token = $page.params.token;');
  const end = source.indexOf('  async function adopt()', start);
  let callback!: () => () => void;
  let tracking = true;
  const dependencies: string[] = [];
  const calls: any[] = [];
  const env: any = {
    $effect: (fn: typeof callback) => { callback = fn; },
    $page: { params: { get token() { if (tracking) dependencies.push('token'); return 'original-token'; } } },
    untrack: (fn: () => void) => { const previous = tracking; tracking = false; try { fn(); } finally { tracking = previous; } },
    invalidateCommentScope: () => calls.push('invalidate-chat'),
    viewRecorder: { invalidate: () => calls.push('invalidate-view') },
    resetRouteState: () => { if (tracking) dependencies.push('commentLoadRevision'); calls.push('reset'); },
    clearLegacyA13Acknowledgement: (token: string) => calls.push(['legacy-delete', token]),
    load: (token: string, signal: AbortSignal) => { if (tracking) dependencies.push('load-state'); calls.push(['load', token, signal]); }
  };
  new Function('env', `with (env) { ${transpiler.transformSync(source.slice(start, end))}; }`)(env);
  const cleanup = callback();
  expect(dependencies).toEqual(['token']);
  expect(calls[0]).toBe('reset'); expect(calls[1]).toEqual(['legacy-delete', 'original-token']);
  expect(calls[2][1]).toBe('original-token'); expect(calls[2][2].aborted).toBe(false);
  cleanup(); expect(calls[2][2].aborted).toBe(true);
});

test('late sign and accept bodies cannot complete a changed notice or artifact', async () => {
  for (const action of ['sign', 'accept'] as const) {
    for (const drift of ['notice', 'artifact', 'navigation']) {
      const state = fixture(); const pending = state[action]();
      if (drift === 'notice') state.env.ctx.privacy.notice_digest = 'next-notice';
      if (drift === 'artifact') state.env.ctx.pdf_observation.pdf_sha256 = 'b'.repeat(64);
      if (drift === 'navigation') state.env.$page.params.token = 'next-token';
      state.calls[0].resolve({ ok: true, json: async () => ({ completed: true, final_pdf_url: '/sign/' + 'A'.repeat(43) + '/final-pdf', audit_cert_url: '/sign/' + 'A'.repeat(43) + '/audit-cert' }) }); await pending;
      expect(state.env.completed).toBe(null);
      expect(state.env.accepted).toBe(false);
      expect(state.env[action === 'sign' ? 'signing' : 'accepting']).toBe(true);
    }
  }
});

test('missing PDF observation and failed or empty block documents remain closed', async () => {
  const pdf = fixture(); pdf.env.ctx.pdf_observation = undefined;
  const pendingPDF = pdf.load('original-token', new AbortController().signal);
  pdf.calls[0].resolve({ ok: true, json: async () => pdf.env.ctx }); await pendingPDF;
  expect(pdf.env.loadError).toBeTruthy(); expect(pdf.env.fieldsFilled).toBe(false); expect(pdf.env.viewerReady()).toBe(false);
  for (const result of [{ ok: false }, { ok: true, text: async () => '   ' }]) {
    const state = fixture('blocks'); state.env.documentReady = false;
    const pending = state.load('original-token', new AbortController().signal);
    state.calls[0].resolve({ ok: true, json: async () => state.env.ctx });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(state.calls).toHaveLength(2);
    state.calls[1].resolve(result); await pending;
    expect(state.env.loadError).toBeTruthy(); expect(state.env.documentReady).toBe(false);
    for (const action of ['adopt', 'sign', 'accept'] as const) { await state[action](); }
    expect(state.calls).toHaveLength(2);
  }
});

test('a successful nonempty block document restores only its existing field gate', async () => {
  const state = fixture('blocks'); state.env.documentReady = false;
  const pending = state.load('original-token', new AbortController().signal);
  state.calls[0].resolve({ ok: true, json: async () => state.env.ctx });
  await new Promise(resolve => setTimeout(resolve, 0));
  state.calls[1].resolve({ ok: true, text: async () => '<p>Current agreement</p>' }); await pending;
  expect(state.env.documentReady).toBe(true); expect(state.env.viewerReady()).toBe(true);
  state.env.fieldsFilled = false; await state.sign(); expect(state.calls).toHaveLength(2);
});

function installViewEffect(env: any) {
  const start = source.indexOf('  $effect(() => {\n    const scope = currentViewScope();');
  const end = source.indexOf('  $effect(() => {', start + 1);
  let effect!: () => void;
  env.$effect = (callback: () => void) => { effect = callback; };
  env.untrack = (callback: () => void) => callback();
  new Function('env', `with(env) { ${transpiler.transformSync(source.slice(start, end))}; }`)(env);
  return effect;
}

for (const kind of ['pdf', 'blocks']) {
  for (const first of ['notice', 'render']) {
    test(`actual ${kind} view effect waits for ${first} and the other prerequisite without requiring completed fields`, async () => {
      const f = fixture(kind);
      f.env.ctx.privacy.notice_digest = 'e'.repeat(64);
      f.env.viewerScopeKey = ''; f.env.documentReady = false; f.env.fieldsFilled = false; f.env.noticeAcknowledged = false;
      const effect = installViewEffect(f.env);
      const acknowledge = bind('  function acknowledgeCurrentNotice()', '  async function confirmSign()', 'acknowledgeCurrentNotice', f.env);
      const render = () => {
        if (kind === 'pdf') f.env.updatePDFReady(true, { token: f.env.loadedToken, noticeDigest: f.env.ctx.privacy.notice_digest, observation: { ...f.env.ctx.pdf_observation } }, f.env.ceremonyEpoch);
        else f.env.documentReady = true;
      };
      if (first === 'notice') acknowledge(); else render();
      effect(); expect(f.calls).toHaveLength(0);
      if (first === 'notice') render(); else acknowledge();
      effect(); effect(); expect(f.calls).toHaveLength(1);
      expect(f.env.documentDisplayed()).toBe(true); expect(f.env.fieldsFilled).toBe(false);
      await f.adopt(); await f.sign(); if (kind === 'pdf') await f.accept();
      expect(f.calls).toHaveLength(1); expect(f.env.showAdoptModal).toBe(false);
      f.calls[0].resolve(new Response(JSON.stringify({ ok: true, status: 'viewed' })));
      await new Promise(resolve => setTimeout(resolve, 0));
      expect(f.env.viewState.confirmed).toBe(true); effect(); expect(f.calls).toHaveLength(1);
    });
  }
}

test('hidden terminal or failed document branches never record views', () => {
  for (const kind of ['blocks', 'pdf']) for (const hidden of ['completed', 'accepted', 'declined', 'loadError']) {
    const f = fixture(kind); f.env.ctx.privacy.notice_digest = 'e'.repeat(64);
    f.env.viewerScopeKey = f.env.currentCeremonyKey();
    f.env[hidden] = hidden === 'completed' ? { url: null } : hidden === 'loadError' ? 'Failed' : true;
    installViewEffect(f.env)(); expect(f.calls).toHaveLength(0); expect(f.env.documentDisplayed()).toBe(false);
  }
});

test('old PDF completion and teardown callbacks cannot affect the same ceremony after A to B to A', () => {
  const f = fixture(); const firstEpoch = f.env.ceremonyEpoch;
  const oldScope = { token: f.env.loadedToken, noticeDigest: f.env.ctx.privacy.notice_digest, observation: { ...f.env.ctx.pdf_observation } };
  f.env.ceremonyEpoch += 2;
  f.env.updatePDFReady(true, oldScope, f.env.ceremonyEpoch);
  f.env.updatePDFGate(true, oldScope, f.env.ceremonyEpoch);
  f.env.updatePDFReady(false, oldScope, firstEpoch); f.env.updatePDFGate(false, oldScope, firstEpoch);
  expect(f.env.viewerReady()).toBe(true);
  f.env.viewerScopeKey = ''; f.env.fieldsFilled = false;
  f.env.updatePDFReady(true, oldScope, firstEpoch); f.env.updatePDFGate(true, oldScope, firstEpoch); f.env.adoptPDF(oldScope, firstEpoch);
  expect(f.env.viewerReady()).toBe(false); expect(f.env.fieldsFilled).toBe(false); expect(f.env.showAdoptModal).toBe(false);
});

test('block rendering waits for DOM mounting and rejects generation drift after the tick', async () => {
  for (const drift of [false, true]) {
    const f = fixture('blocks'); f.env.documentReady = false;
    let context = f.env.ctx;
    Object.defineProperty(f.env, 'ctx', { configurable: true, get: () => context, set: value => { context = new Proxy(value, {}); } });
    const ticks: (() => void)[] = [];
    f.env.tick = () => new Promise<void>(resolve => ticks.push(resolve));
    const pending = f.load('original-token', new AbortController().signal);
    f.calls[0].resolve({ ok: true, json: async () => context });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(ticks).toHaveLength(1); expect(f.calls).toHaveLength(1);
    ticks[0](); await new Promise(resolve => setTimeout(resolve, 0));
    expect(f.calls).toHaveLength(2);
    f.calls[1].resolve({ ok: true, text: async () => '<p>Current agreement</p>' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(ticks).toHaveLength(2); expect(f.env.documentReady).toBe(false);
    if (drift) f.env.ceremonyEpoch++;
    ticks[1](); await pending;
    expect(f.env.documentReady).toBe(!drift);
  }
});

test('terminal block recipients do not load a hidden document after installing context', async () => {
  for (const status of ['signed', 'accepted', 'declined']) {
    const f = fixture('blocks'); f.env.documentReady = false;
    const loaded = { ...f.env.ctx, recipient: { ...f.env.ctx.recipient, status } };
    const pending = f.load('original-token', new AbortController().signal);
    f.calls[0].resolve({ ok: true, json: async () => loaded }); await pending;
    expect(f.calls).toHaveLength(1); expect(f.env.documentDisplayed()).toBe(false);
  }
});

test('a late block HTML body or failure cannot replace the current same-token context', async () => {
  for (const failure of [false, true]) {
    const f = fixture('blocks'); f.env.documentReady = false;
    const pending = f.load('original-token', new AbortController().signal);
    f.calls[0].resolve({ ok: true, json: async () => f.env.ctx });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(f.calls).toHaveLength(2);
    f.env.ceremonyEpoch++;
    f.env.documentHTML = '<p>New document</p>'; f.env.loadError = 'New context error';
    if (failure) f.calls[1].reject(new Error('Old failure'));
    else f.calls[1].resolve({ ok: true, text: async () => '<p>Old document</p>' });
    await pending;
    expect(f.env.documentHTML).toBe('<p>New document</p>'); expect(f.env.loadError).toBe('New context error');
    expect(f.env.documentReady).toBe(false);
  }
});

test('terminal sign and accept responses expose only a complete validated artifact pair', async () => {
  const token = 'A'.repeat(43);
  const pair = { final_pdf_url: `/sign/${token}/final-pdf`, audit_cert_url: `/sign/${token}/audit-cert` };
  for (const action of ['sign', 'accept'] as const) {
    for (const links of [pair, { ...pair, audit_cert_url: 'https://example.test/audit' }, { final_pdf_url: pair.final_pdf_url }]) {
      const state = fixture(); const pending = state[action]();
      state.calls[0].resolve({ ok: true, json: async () => ({ completed: true, ...links }) });
      await pending;
      expect(state.env.completed).toEqual({ terminal: true, links: links === pair
        ? { finalPDFURL: pair.final_pdf_url, auditCertURL: pair.audit_cert_url } : null });
      expect(state.env.signError).toBeNull();
    }
  }
});

test('terminal context reload never manufactures completion download credentials', async () => {
  const state = fixture();
  const pending = state.load('original-token', new AbortController().signal);
  state.calls[0].resolve({ ok: true, json: async () => ({ ...state.env.ctx, status: 'completed',
    recipient: { ...state.env.ctx.recipient, status: 'signed' } }) });
  await pending;
  expect(state.env.completed).toEqual({ terminal: true, links: null });
});


test('terminal Sign and Accept retain their dispatched package requirement across later review callbacks',async()=>{
 const fresh='A'.repeat(43),wrong='B'.repeat(43);
 const pair={final_pdf_url:`/sign/${fresh}/final-pdf`,audit_cert_url:`/sign/${fresh}/audit-cert`};
 const observed={manifest_sha256:'b'.repeat(64),legal_commitment_sha256:'c'.repeat(64),incorporation_version:'hash-package-incorporation-v1',incorporation_sha256:'d'.repeat(64),consent:true as const};
 for(const action of ['sign','accept'] as const){
  for(const initiallyPackaged of [false,true]){
   for(const portal of [undefined,`/completed/${wrong}`,`/completed/${fresh}`]){
    const state=fixture('pdf',false),key=state.env.currentCeremonyKey(),epoch=state.env.ceremonyEpoch;
    state.env.updatePackageReview({key,ready:true,...(initiallyPackaged?{response:observed}:{})},epoch);
    const pending=state[action]();expect(state.calls).toHaveLength(1);
    const submitted=JSON.parse(state.calls[0].options.body);
    expect(!!submitted.package_response).toBe(initiallyPackaged);
    // A later callback cannot relax an already dispatched package's mandatory
    // download contract, or retroactively change an ordinary response contract.
    state.env.updatePackageReview({key,ready:true,...(!initiallyPackaged?{response:observed}:{})},epoch);
    state.calls[0].resolve({ok:true,json:async()=>({completed:true,...pair,...(portal===undefined?{}:{package_portal_url:portal})})});
    await pending;
    const valid=portal===`/completed/${fresh}`||(!initiallyPackaged&&portal===undefined);
    expect(state.env.completed).toEqual({terminal:true,links:valid?{finalPDFURL:pair.final_pdf_url,auditCertURL:pair.audit_cert_url,...(portal?{packagePortalURL:portal}:{})}:null});
   }
  }
 }
});


test('actual package loading waits for the current acknowledged view confirmation for PDF and legacy blocks', async () => {
  for (const kind of ['pdf', 'blocks']) {
    const f = fixture(kind, false);
    f.env.ctx.privacy.notice_digest = 'e'.repeat(64);
    if (kind === 'pdf') f.env.updatePDFReady(true, { token: f.env.loadedToken, noticeDigest: f.env.ctx.privacy.notice_digest, observation: { ...f.env.ctx.pdf_observation } }, f.env.ceremonyEpoch);
    bind('  function acknowledgeCurrentNotice()', '  async function confirmSign()', 'acknowledgeCurrentNotice', f.env)();
    const effect = installViewEffect(f.env);
    expect(f.env.packageCanLoad()).toBe(false); effect(); expect(f.calls).toHaveLength(1);
    expect(f.env.packageCanLoad()).toBe(false);
    f.calls[0].resolve(new Response(JSON.stringify({ ok: true, status: 'viewed' })));
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(f.env.packageCanLoad()).toBe(true);
    f.env.loadError = 'current document unavailable'; expect(f.env.packageCanLoad()).toBe(false);
  }
});

test('actual current descriptor settlement starts comments once and gates signing until the initial read settles', async () => {
  for (const kind of ['pdf', 'blocks']) {
    const f = fixture(kind, false); f.env.viewState.confirmed = true; let reads = 0; let finish!: () => void;
    f.env.loadComments = async (token: string) => {
      expect(token).toBe(f.env.loadedToken); reads++; f.env.commentLoading = true;
      await new Promise<void>(resolve => { finish = resolve; }); f.env.commentLoading = false;
    };
    const next = { key: f.env.currentCeremonyKey(), ready: true, settled: false };
    f.env.updatePackageReview(next, f.env.ceremonyEpoch); expect(reads).toBe(0);
    f.env.updatePackageReview({ ...next, settled: true }, f.env.ceremonyEpoch);
    expect(reads).toBe(1); expect(f.env.packageReady()).toBe(true); expect(f.env.viewerReady()).toBe(false);
    await f.adopt(); await f.sign(); await f.accept(); expect(f.calls).toHaveLength(0); expect(f.env.showAdoptModal).toBe(false);
    f.env.updatePackageReview({ ...next, settled: true }, f.env.ceremonyEpoch); expect(reads).toBe(1);
    finish(); await new Promise(resolve => setTimeout(resolve, 0)); expect(f.env.viewerReady()).toBe(true);
    f.env.updatePackageReview(next, f.env.ceremonyEpoch); f.env.updatePackageReview({ ...next, settled: true }, f.env.ceremonyEpoch);
    expect(reads).toBe(1);
  }
});

test('actual stale descriptor callbacks never start comments or replace the new ceremony readiness', () => {
  const f = fixture('pdf', false); f.env.viewState.confirmed = true; let reads = 0;
  f.env.loadComments = () => { reads++; };
  const oldEpoch = f.env.ceremonyEpoch, oldKey = f.env.currentCeremonyKey(); f.env.ceremonyEpoch++;
  f.env.updatePackageReview({ key: oldKey, ready: true, settled: true }, oldEpoch);
  expect(reads).toBe(0); expect(f.env.packageReady()).toBe(false);
  f.env.ctx.privacy.notice_digest = 'd'.repeat(64); f.env.viewerScopeKey = f.env.currentCeremonyKey();
  f.env.updatePackageReview({ key: oldKey, ready: true, settled: true }, f.env.ceremonyEpoch); expect(reads).toBe(0);
  f.env.updatePackageReview({ key: f.env.currentCeremonyKey(), ready: false, settled: true }, f.env.ceremonyEpoch);
  expect(reads).toBe(1); expect(f.env.packageReady()).toBe(false);
});

const packageReviewSource417 = await Bun.file(new URL('./SignerPackageReview.svelte', import.meta.url)).text();
function packageSettlementFixture417() {
  const env: any = { original: { key: 'current-key', token: 'current-token' }, scope: { key: 'current-key', token: 'current-token' },
    disposed: false, disabled: false, revision: 0, abort: null, value: null, loaded: false, busy: true, error: null, consent: false,
    preview: { opening: false, closing: false, blocked: false, error: null }, canConsent: false,
    controller: { close: async () => {} }, signerPackageResponse: () => { throw new Error('unexpected consent response'); },
    untrack: (run: () => unknown) => run(), onChange: (value: unknown) => frames.push(value) };
  const frames: any[] = [], calls: { resolve(value: unknown): void; reject(reason: unknown): void }[] = [];
  env.fetchSignerPackage = () => new Promise((resolve, reject) => calls.push({ resolve, reject }));
  const currentStart = packageReviewSource417.indexOf('  const current = () =>'), currentEnd = packageReviewSource417.indexOf('  const controller =', currentStart);
  if (currentStart < 0 || currentEnd <= currentStart) throw new Error('Actual package scope callback missing');
  env.current = new Function('env', `with(env) { ${transpiler.transformSync(packageReviewSource417.slice(currentStart, currentEnd))}; return current; }`)(env);
  const start = packageReviewSource417.indexOf('  async function refresh()'), end = packageReviewSource417.indexOf('  async function open(', start);
  if (start < 0 || end <= start) throw new Error('Actual package refresh callback missing');
  const refresh = new Function('env', `with(env) { ${transpiler.transformSync(packageReviewSource417.slice(start, end))}; return refresh; }`)(env);
  const effectStart = packageReviewSource417.indexOf('  $effect(() => {\n    const ready ='), effectEnd = packageReviewSource417.indexOf('\n\n  async function refresh()', effectStart);
  if (effectStart < 0 || effectEnd <= effectStart) throw new Error('Actual package readiness effect missing');
  let publish!: () => void; env.$effect = (effect: () => void) => { publish = effect; };
  new Function('env', `with(env) { ${transpiler.transformSync(packageReviewSource417.slice(effectStart, effectEnd))}; }`)(env);
  return { env, frames, calls, refresh, publish };
}

test('actual descriptor producer distinguishes pending, legacy-null completion and failed completion from consent readiness', async () => {
  for (const result of ['legacy-null', 'failed'] as const) {
    const f = packageSettlementFixture417(), pending = f.refresh();
    await new Promise(resolve => setTimeout(resolve, 0)); f.publish();
    expect(f.calls).toHaveLength(1); expect(f.frames.at(-1)).toMatchObject({ settled: false, ready: false });
    if (result === 'legacy-null') f.calls[0].resolve(null); else f.calls[0].reject(new Error('private synthetic response failure'));
    await pending; f.publish();
    expect(f.frames.at(-1)).toMatchObject({ settled: true, ready: result === 'legacy-null' });
    expect(f.frames.at(-1)).not.toHaveProperty('response');
  }
});

test('actual stale or disposed descriptor completion cannot publish settled readiness', async () => {
  for (const drift of ['scope', 'disposed'] as const) {
    const f = packageSettlementFixture417(), pending = f.refresh(); await new Promise(resolve => setTimeout(resolve, 0));
    if (drift === 'scope') f.env.scope = { key: 'new-key', token: 'new-token' }; else f.env.disposed = true;
    f.calls[0].resolve(null); await pending; f.publish(); expect(f.frames.at(-1)).toMatchObject({ settled: false, ready: false });
    expect(f.env.loaded).toBe(false);
  }
});
