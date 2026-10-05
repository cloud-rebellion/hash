import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

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
