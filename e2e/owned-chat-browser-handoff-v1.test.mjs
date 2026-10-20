import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateOwnedChatHandoffV1, ownedChatResponseJSONV1 } from './owned-comment-history-browser-v1.mjs';
const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  return { donePath: '/owned/done.json', artifacts: '/owned/artifacts', packet: {
    base: 'https://127.0.0.1:8443', documentID: id(1), orgID: id(2), ownerID: id(3), recipientID: id(4), token: 'A'.repeat(64),
    cookie: { name: 'hash_session', value: 'B'.repeat(64), httpOnly: true, secure: true, sameSite: 'Strict', expires: Math.floor(Date.now() / 1000) + 3600 },
    rendererImageID: 'sha256:' + 'a'.repeat(64), rendererVersion: '8.36.0-hash.5',
    comments: Array.from({ length: 105 }, (_, i) => ({ id: id(i + 10), body: `Owned seeded comment ${String(i + 1).padStart(3, '0')} ÅÄÖ` })),
  } };
}
test('accepts exact bounded private native chat handoff without dispatch', () => { const f = fixture(); assert.equal(validateOwnedChatHandoffV1(f), f); });
test('rejects native errors before awaiting a body that never completes', async () => {
  let parsed = 0;
  const failed = { status: () => 503, json: () => { parsed++; return new Promise(() => {}); } };
  for (const [kind, status] of [['identity', 200], ['comment-post', 201], ['history', 200], ['view', 200]]) {
    await assert.rejects(ownedChatResponseJSONV1(failed, status, kind), new RegExp(`native ${kind} status 503`));
  }
  assert.equal(parsed, 0);
  const value = { comments: [] };
  assert.equal(await ownedChatResponseJSONV1({ status: () => 200, json: async () => value }, 200, 'history'), value);
});
test('rejects foreign/non-loopback origins and embedded credentials', () => {
  for (const base of ['https://example.test', 'http://127.0.0.1:8443', 'https://localhost:8443', 'https://u:p@127.0.0.1:8443', 'https://127.0.0.1:8443/sign/x']) {
    const f = fixture(); f.packet.base = base; assert.throws(() => validateOwnedChatHandoffV1(f));
  }
});
test('requires actual secure HttpOnly Strict current session attributes', () => {
  for (const delta of [{ secure: false }, { httpOnly: false }, { sameSite: 'Lax' }, { expires: 0 }, { value: 'bad;value' }]) {
    const f = fixture(); Object.assign(f.packet.cookie, delta); assert.throws(() => validateOwnedChatHandoffV1(f));
  }
});
test('rejects partial or duplicate native history and mismatched text', () => {
  for (const mutate of [f => f.packet.comments.pop(), f => { f.packet.comments[1].id = f.packet.comments[0].id; }, f => { f.packet.comments[0].body = 'different'; }]) {
    const f = fixture(); mutate(f); assert.throws(() => validateOwnedChatHandoffV1(f));
  }
});
test('rejects missing identities, expired credentials and unsafe output paths', () => {
  for (const mutate of [f => { f.packet.documentID = ''; }, f => { f.packet.token = ''; }, f => { f.donePath = '/'; }, f => { f.artifacts = f.donePath; }, f => { f.artifacts = '/owned/../tmp'; }]) {
    const f = fixture(); mutate(f); assert.throws(() => validateOwnedChatHandoffV1(f));
  }
});
