import { expect, test } from 'bun:test';
import { chatFixture } from './commentHistory-fixture.test-support';
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
