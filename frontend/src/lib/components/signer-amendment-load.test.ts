import { expect, test } from 'bun:test';
import { validateSignerAmendmentContext } from '../signerAmendment';
import { validateSignerPDFObservation, signerCeremonyKey } from '../signerPDF';
const source = await Bun.file(new URL('../../routes/sign/[token]/+page.svelte', import.meta.url)).text();
const start = source.indexOf('  async function load('), end = source.indexOf('  onMount(', start); if (start < 0 || end <= start) throw Error('Actual signer load callback missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const candidate = '11111111-1111-4111-8111-111111111111', original = '22222222-2222-4222-8222-222222222222', amendment = '33333333-3333-4333-8333-333333333333', recipient = '44444444-4444-4444-8444-444444444444';
function disclosure(signature = true) { return { schema: 'hash-signer-amendment-context-v1', amendment_id: amendment, revision: '1', document_id: candidate, original_document_id: original, original_name: 'Original agreement', original_final_pdf_sha256: 'a'.repeat(64), original_report_sha256: 'b'.repeat(64), original_report_pdf_sha256: 'c'.repeat(64), mode: signature ? 'signature' : 'acknowledgement', file_commitment_sha256: 'd'.repeat(64) }; }
function fixture(amendmentContext: unknown, signature = true) {
 const response = { document_id: candidate, document_name: 'Amendment', status: 'sent', source_kind: 'pdf', requires_signature: signature, recipient: { id: recipient, status: 'pending' }, privacy: { notice_digest: 'e'.repeat(64) }, pdf_observation: { document_id: candidate, recipient_id: recipient, pdf_sha256: 'f'.repeat(64) }, ...(amendmentContext === undefined ? {} : { amendment_context: amendmentContext }) };
 let calls = 0; const env: any = { ctx: null, loadError: null, fieldsFilled: false, documentReady: false, viewerScopeKey: '', loadedToken: '', routeDisposed: false, ceremonyEpoch: 1, completed: null, accepted: false, declined: false, changesRequested: false, noticeAcknowledged: false, packageReview: { ready: false }, $page: { params: { token: 'current-token' } }, validateSignerAmendmentContext, validateSignerPDFObservation, setLocale() {}, tick: async () => {}, fetch: async () => { calls++; return Response.json(response); } };
 env.currentCeremonyKey = () => env.ctx ? signerCeremonyKey(env.loadedToken, env.ctx.privacy.notice_digest, env.ctx.document_id, env.ctx.recipient.id, env.ctx.pdf_observation) : '';
 const load = new Function('env', 'with(env){' + code + ';return load;}')(env); return { env, load: () => load('current-token', new AbortController().signal), calls: () => calls };
}
test('actual signer load installs exact signature or acknowledgement context without granting PDF/package/privacy proof', async () => {
 for (const signature of [true, false]) { const f = fixture(disclosure(signature), signature); await f.load(); expect(f.env.ctx.amendment_context.mode).toBe(signature ? 'signature' : 'acknowledgement'); expect(f.env.ctx.amendment_context.original_report_pdf_sha256).toBe('c'.repeat(64)); expect(f.env.fieldsFilled).toBe(false); expect(f.env.documentReady).toBe(false); expect(f.env.viewerScopeKey).toBe(''); expect(f.env.packageReview.ready).toBe(false); expect(f.env.noticeAcknowledged).toBe(false); expect(f.calls()).toBe(1); }
});
test('actual signer load refuses malformed or wrong-process relation before installing a viewer context', async () => {
 for (const context of [{ ...disclosure(), original_pdf_url: '/completed/private' }, { ...disclosure(), mode: 'agreed_notice' }, disclosure(false), { ...disclosure(), document_id: original }]) { const f = fixture(context); await f.load(); expect(f.env.ctx).toBeNull(); expect(f.env.loadedToken).toBe(''); expect(f.env.loadError).toContain('amendment reference'); expect(f.env.fieldsFilled).toBe(false); expect(f.env.documentReady).toBe(false); expect(f.calls()).toBe(1); }
});
test('actual signer load preserves absent or null ordinary context without fabricating an original agreement', async () => {
 for (const context of [undefined, null]) { const f = fixture(context); await f.load(); expect(f.env.ctx).not.toBeNull(); expect(Object.hasOwn(f.env.ctx, 'amendment_context')).toBe(false); expect(f.env.fieldsFilled).toBe(false); expect(f.env.viewerScopeKey).toBe(''); }
});
