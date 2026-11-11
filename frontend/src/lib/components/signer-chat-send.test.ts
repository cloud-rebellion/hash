import { expect, test } from 'bun:test';
import { chatFixture } from './commentHistory-fixture.test-support';
import { get } from 'svelte/store';
import { locale, t, type Locale } from '../i18n';

function signerCopyForLocale(value: Locale) {
  const previous = get(locale);
  try { locale.set(value); return get(t); }
  finally { locale.set(previous); }
}
test('signer chat requires acknowledgement bound to current ceremony', async () => {
  for (const condition of ['not-acknowledged', 'old-scope', 'notice-drift']) {
    const f = chatFixture(true);
    if (condition === 'not-acknowledged') f.env.noticeAcknowledged = false;
    if (condition === 'old-scope') f.env.acknowledgedScopeKey = 'old';
    if (condition === 'notice-drift') f.env.ctx.privacy.notice_digest = 'new';
    await f.send(); expect(f.calls).toHaveLength(0); expect(f.env.commentBody).toBe('first'); expect(f.env.signError).toContain('privacy notice');
  }
});
test('staff history and send responses are scoped to organisation as well as document', async () => {
  for (const send of [false, true]) {
    const f = chatFixture(); const pending = send ? f.send() : f.load(); f.env.doc.org_id = 'different'; f.env.commentBody = 'new';
    f.calls[0].reject(new Error('foreign failure')); await pending;
    expect(f.env.commentBody).toBe('new'); expect(f.env.error).toBeNull(); expect(f.env.commentRefreshError).toBeNull(); expect(f.calls).toHaveLength(1);
  }
});

test('actual signer chat acknowledgement refusal uses the selected EN/SV catalog without posting or losing the draft', async () => {
  for (const language of ['en', 'sv'] as const) {
    const f = chatFixture(true);
    f.env.$t = signerCopyForLocale(language);
    f.env.noticeAcknowledged = false;
    await f.send();
    expect(f.calls).toHaveLength(0);
    expect(f.env.commentBody).toBe('first');
    expect(f.env.signError).toBe(language === 'sv'
      ? 'Bekräfta den aktuella integritetsinformationen innan du fortsätter.'
      : 'Acknowledge the current privacy notice before continuing.');
  }
});

test('actual failed signer chat POST retains original scope, notice and draft while localizing the HTTP fallback', async () => {
  for (const language of ['en', 'sv'] as const) {
    const f = chatFixture(true);
    f.env.$t = signerCopyForLocale(language);
    const pending = f.send();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0].options.headers).toEqual({ digest: 'digest', accepted: true });
    expect(JSON.parse(f.calls[0].options.body)).toEqual({ body: 'first' });
    f.calls[0].resolve({ ok: false, status: 503 });
    await pending;
    expect(f.env.commentBody).toBe('first');
    expect(f.env.postingComment).toBe(false);
    expect(f.env.signError).toBe(language === 'sv'
      ? 'Meddelandet kunde inte skickas (HTTP 503). Ditt utkast finns kvar.'
      : 'Message could not be sent (HTTP 503). Your draft has been kept.');
    expect(f.calls).toHaveLength(1);
  }
});
