import { expect, test } from 'bun:test';
import { signerCeremonyKey, signerPDFScopeKey, validateSignerPDFObservation } from '../signerPDF';

const source = await Bun.file(new URL('../../routes/sign/[token]/+page.svelte', import.meta.url)).text();
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function bind(start: string, end: string, name: string, env: any) {
  const offset = source.indexOf(start);
  const finish = source.indexOf(end, offset);
  if (offset < 0 || finish < 0) throw new Error('Production callback not found');
  return new Function('env', `with (env) { ${transpiler.transformSync(source.slice(offset, finish))}; return ${name}; }`)(env);
}
function fixture(kind = 'pdf') {
  const calls: any[] = [];
  const documentID = '10000000-0000-4000-8000-000000000001';
  const recipientID = '20000000-0000-4000-8000-000000000001';
  const env: any = {
    ctx: { document_id: documentID, source_kind: kind, status: 'sent', recipient: { id: recipientID, status: 'pending' },
      privacy: { notice_digest: 'current-notice' }, pdf_observation: kind === 'pdf' ? { document_id: documentID, recipient_id: recipientID, pdf_sha256: 'a'.repeat(64) } : undefined },
    $page: { params: { token: 'original-token' } }, loadedToken: 'original-token', routeDisposed: false,
    fieldsFilled: true, documentReady: kind === 'blocks', viewerScopeKey: '', noticeAcknowledged: true,
    signing: false, accepting: false, declining: false, requestingChanges: false, changesRequested: false,
    completed: null, accepted: false, declined: false, typedName: 'Current signer', chosenFont: 'Caveat', showAdoptModal: false,
    signError: null, loadError: null, documentHTML: '',
    signerCeremonyKey, signerPDFScopeKey, validateSignerPDFObservation,
    signerNoticeHeaders: (digest: string, acknowledged: boolean) => ({ digest, acknowledged }),
    setLocale() {}, loadComments() {},
    fetch: (url: string, options: unknown) => new Promise((resolve, reject) => calls.push({ url, options, resolve, reject }))
  };
  const gateFunctions = source.slice(source.indexOf('  function currentCeremonyKey()'), source.indexOf('  $effect.pre('));
  const helpers = new Function('env', `with (env) { ${transpiler.transformSync(gateFunctions)}; return {currentCeremonyKey, viewerReady, updatePDFGate, adoptPDF}; }`)(env);
  Object.assign(env, helpers);
  if (kind === 'pdf') env.updatePDFGate(true, { token: env.loadedToken, noticeDigest: env.ctx.privacy.notice_digest, observation: { ...env.ctx.pdf_observation } });
  const adopt = bind('  async function adopt()', '  function acknowledgeCurrentNotice()', 'adopt', env);
  env.adopt = adopt;
  const sign = bind('  async function confirmSign()', '  async function decline()', 'confirmSign', env);
  const accept = bind('  async function accept()', '  async function confirmDecline()', 'accept', env);
  const load = bind('  async function load(', '  onMount(', 'load', env);
  return { env, calls, adopt, sign, accept, load };
}

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
  expect(state.env.completed).toEqual({ url: null });
  expect(state.env.signing).toBe(false);
});

test('the real PDF readiness callback enables adoption for the exact observed context and closes it on false or drift', async () => {
  for (const extra of [{}, { html_source_commitment: 'b'.repeat(64) },
    { html_source_commitment: 'b'.repeat(64), page_count: 3, materialization_revision: 2 }]) {
    const state = fixture();
    state.env.ctx.pdf_observation = { ...state.env.ctx.pdf_observation, ...extra };
    const observed = { token: state.env.loadedToken, noticeDigest: state.env.ctx.privacy.notice_digest,
      observation: { ...state.env.ctx.pdf_observation } };
    state.env.fieldsFilled = false; state.env.viewerScopeKey = '';
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(false);
    state.env.updatePDFGate(true, observed);
    expect(state.env.fieldsFilled).toBe(true);
    expect(state.env.viewerScopeKey).toBe(state.env.currentCeremonyKey());
    expect(state.env.viewerReady()).toBe(true);
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(true);
    state.env.showAdoptModal = false;
    state.env.updatePDFGate(false, observed);
    expect(state.env.viewerReady()).toBe(false);
    state.env.adoptPDF(observed);
    expect(state.env.showAdoptModal).toBe(false);
    state.env.ctx.pdf_observation.pdf_sha256 = 'c'.repeat(64);
    state.env.updatePDFGate(true, observed);
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
      state.calls[0].resolve({ ok: true, json: async () => ({ completed: true, final_pdf_url: '/old-final' }) }); await pending;
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
    await Promise.resolve(); await Promise.resolve();
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
  await Promise.resolve(); await Promise.resolve();
  state.calls[1].resolve({ ok: true, text: async () => '<p>Current agreement</p>' }); await pending;
  expect(state.env.documentReady).toBe(true); expect(state.env.viewerReady()).toBe(true);
  state.env.fieldsFilled = false; await state.sign(); expect(state.calls).toHaveLength(2);
});
