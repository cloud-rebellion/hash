import { expect, test } from 'bun:test';
import { chatFixture, message, messages, signerSource, staffSource } from './commentHistory-fixture.test-support';
for (const drift of ['token', 'recipient', 'document', 'notice', 'source', 'artifact']) {
  test(`signer read and send ignore late ${drift} context`, async () => {
    for (const send of [false, true]) {
      const f = chatFixture(true); await f.seed(); const pending = send ? f.send() : f.load();
      if (drift === 'token') f.env.$page.params.token = 'different';
      if (drift === 'recipient') f.env.ctx.recipient.id = 'different';
      if (drift === 'document') f.env.ctx.document_id = 'different';
      if (drift === 'notice') f.env.ctx.privacy.notice_digest = 'different';
      if (drift === 'source') f.env.ctx.source_kind = 'pdf';
      if (drift === 'artifact') f.env.ctx.pdf_observation = { document_id: 'doc', recipient_id: 'recipient', pdf_sha256: 'a'.repeat(64) };
      f.env.commentBody = 'new draft'; f.env.signError = 'current error'; f.env.postingComment = true;
      if (send) f.calls[0].resolve({ ok: true }); else f.resolvePage(f.calls[0], messages('wrong'));
      await pending; expect(f.env.comments).toEqual([message('retained')]); expect(f.env.commentBody).toBe('new draft');
      expect(f.env.signError).toBe('current error'); expect(f.env.postingComment).toBe(true); expect(f.calls).toHaveLength(1);
    }
  });
}

function installPreEffect(source: string, env: any, staff = false) {
  const start = source.indexOf('  $effect.pre(() => {');
  const end = source.indexOf(staff ? '  beforeNavigate(' : '  $effect(() => {', start);
  let effect!: () => void;
  env.$effect = { pre: (callback: () => void) => { effect = callback; } };
  env.untrack = (callback: () => void) => callback();
  new Function('env', `with(env) { ${new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end))} }`)(env);
  return effect;
}
test('signer first history GET survives the actual ceremony-establishing preeffect', async () => {
  const f = chatFixture(true); f.env.acknowledgedScopeKey = '';
  const pending = f.load(); const effect = installPreEffect(signerSource, f.env); effect();
  expect(f.calls).toHaveLength(1); expect(f.calls[0].options.signal.aborted).toBe(false); expect(f.env.commentLoading).toBe(true);
  f.resolvePage(f.calls[0], messages('first')); await pending;
  expect(f.env.comments).toEqual([message('first')]); expect(f.env.commentLoading).toBe(false);
});
test('signer notice and source preeffect cancels stale work, clears old thread and keeps draft', async () => {
  for (const drift of ['notice', 'source']) {
    const f = chatFixture(true); await f.seed(); const pending = f.load();
    if (drift === 'notice') f.env.ctx.privacy.notice_digest = 'new'; else f.env.ctx.source_kind = 'pdf';
    const effect = installPreEffect(signerSource, f.env); effect();
    expect(f.calls[0].options.signal.aborted).toBe(true); expect(f.env.commentLoading).toBe(false); expect(f.env.commentBody).toBe('first');
    f.resolvePage(f.calls[0], messages('stale')); await pending; expect(f.env.comments).toEqual([]); expect(f.env.noticeAcknowledged).toBe(false);
  }
});
test('staff organisation preeffect retires old reads and pending sends without discarding a draft', async () => {
  for (const send of [false, true]) {
    const f = chatFixture(); await f.seed(); const effect = installPreEffect(staffSource, f.env, true); effect();
    const pending = send ? f.send() : f.load(); f.env.doc.org_id = 'new'; effect();
    expect(f.env.commentLoading).toBe(false); expect(f.env.postingComment).toBe(false); expect(f.env.commentBody).toBe('first');
    f.calls[0].reject(new Error('stale')); await pending; expect(f.env.comments).toEqual([]); expect(f.env.error).toBeNull();
  }
});
