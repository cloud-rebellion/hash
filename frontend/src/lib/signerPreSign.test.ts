import { expect, test } from 'bun:test';
import { validateSignerPreSignContext } from './signerPreSign';
import { signerCeremonyKey, validateSignerPDFObservation } from './signerPDF';
import { validateSignerAmendmentContext } from './signerAmendment';

const documentID = '11111111-1111-4111-8111-111111111111', executionID = '22222222-2222-4222-8222-222222222222', recipientID = '33333333-3333-4333-8333-333333333333', sha = 'a'.repeat(64);
const observation = { document_id: documentID, recipient_id: recipientID, pdf_sha256: sha };
const disclosure = () => ({ schema_version: 1, execution_id: executionID, execution_sha256: sha, visible_pdf_sha256: sha, disclosure_version: 1, disclosure_sha256: sha, disclosure_text: 'The provider pre-signed its part.\nThe customer signs explicitly.', provider_name: 'Provider Example', executed_at: '2026-10-23T12:00:00.123456Z', document_id: documentID });
test('customer disclosure binds exact published visible PDF and document without any storage locator', () => {
  expect(validateSignerPreSignContext(disclosure(), documentID, true, 'pdf', observation)).toEqual(disclosure());
  for (const value of [null, {}, { ...disclosure(), storage_key: 'private' }, { ...disclosure(), schema_version: 2 }, { ...disclosure(), disclosure_version: true }, { ...disclosure(), document_id: executionID }, { ...disclosure(), visible_pdf_sha256: 'b'.repeat(64) }, { ...disclosure(), provider_name: '' }, { ...disclosure(), disclosure_text: '\u0000secret' }, { ...disclosure(), executed_at: '2026-02-30T12:00:00Z' }]) expect(() => validateSignerPreSignContext(value, documentID, true, 'pdf', observation)).toThrow();
  expect(() => validateSignerPreSignContext(disclosure(), documentID, false, 'pdf', observation)).toThrow();
  expect(() => validateSignerPreSignContext(disclosure(), documentID, true, 'blocks', observation)).toThrow();
  expect(() => validateSignerPreSignContext(disclosure(), documentID, true, 'pdf')).toThrow();
});
const source = await Bun.file(new URL('../routes/sign/[token]/+page.svelte', import.meta.url)).text();
const start = source.indexOf('  async function load('), end = source.indexOf('  onMount(', start);
if (start < 0 || end <= start) throw new Error('Actual signer load callback missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
function fixture(context: unknown) {
  const response = { document_id: documentID, document_name: 'Agreement', status: 'sent', source_kind: 'pdf', requires_signature: true, recipient: { id: recipientID, status: 'pending' }, privacy: { notice_digest: sha }, pdf_observation: observation, ...(context === undefined ? {} : { pre_sign_context: context }) };
  let calls = 0;
  const env: any = { ctx: null, loadError: null, fieldsFilled: false, documentReady: false, viewerScopeKey: '', loadedToken: '', routeDisposed: false, ceremonyEpoch: 1, completed: null, accepted: false, declined: false, changesRequested: false, noticeAcknowledged: false, packageReview: { ready: false }, $page: { params: { token: 'original-token' } }, validateSignerAmendmentContext, validateSignerPreSignContext, validateSignerPDFObservation, setLocale() {}, tick: async () => {}, fetch: async () => { calls++; return Response.json(response); } };
  env.currentCeremonyKey = () => env.ctx ? signerCeremonyKey(env.loadedToken, env.ctx.privacy.notice_digest, env.ctx.document_id, env.ctx.recipient.id, env.ctx.pdf_observation) : '';
  const load = new Function('env', `with(env){${code};return load;}`)(env);
  return { env, calls: () => calls, load: () => load('original-token', new AbortController().signal) };
}
test('actual customer load validates pre-sign disclosure before any viewer or signing proof is installed', async () => {
  const valid = fixture(disclosure()); await valid.load(); expect(valid.env.ctx.pre_sign_context).toEqual(disclosure()); expect(valid.env.fieldsFilled).toBe(false); expect(valid.env.documentReady).toBe(false); expect(valid.env.noticeAcknowledged).toBe(false); expect(valid.calls()).toBe(1);
  for (const value of [{ ...disclosure(), object_version: 'private' }, { ...disclosure(), document_id: executionID }, { ...disclosure(), visible_pdf_sha256: 'b'.repeat(64) }]) {
    const f = fixture(value); await f.load(); expect(f.env.ctx).toBeNull(); expect(f.env.loadedToken).toBe(''); expect(f.env.viewerScopeKey).toBe(''); expect(f.env.documentReady).toBe(false); expect(f.calls()).toBe(1);
  }
});
test('ordinary absent or null context stays ordinary and never manufactures provider signing proof', async () => {
  for (const value of [undefined, null]) { const f = fixture(value); await f.load(); expect(f.env.ctx).not.toBeNull(); expect(Object.hasOwn(f.env.ctx, 'pre_sign_context')).toBe(false); expect(f.env.documentReady).toBe(false); expect(f.env.fieldsFilled).toBe(false); }
});
