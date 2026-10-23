import { expect, test } from 'bun:test';
const source = await Bun.file(new URL('./HtmlTemplateEditor.svelte', import.meta.url)).text();
const start = source.indexOf('  function changeAmendmentPolicy('), end = source.indexOf('  function changeSigningPage(', start);
if (start < 0 || end <= start) throw Error('Actual policy authoring callbacks missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
function fixture(owner = true, confirm = true) {
 const env: any = { canApprove: owner, busy: null, draft: { contract_profile: {} }, window: { confirm: () => confirm } };
 const callbacks = new Function('env', 'with(env){' + code + ';return {changeAmendmentPolicy,changeAmendmentMode};}')(env); return { env, callbacks };
}
test('actual owner enable supplies no generated clause or default permission and preserves existing policy on cancelled removal', () => {
 const f = fixture(); f.callbacks.changeAmendmentPolicy({ currentTarget: { checked: true } }); expect(f.env.draft.contract_profile.amendment_policy).toEqual({ term: '', clause_reference: '', allowed_modes: [], allowed_channels: [], effective_condition: '' });
 const refused = fixture(true, false); const policy = { term: 'terms', allowed_modes: ['signature'], allowed_channels: [] }; refused.env.draft.contract_profile.amendment_policy = policy; const input = { checked: false }; refused.callbacks.changeAmendmentPolicy({ currentTarget: input }); expect(input.checked).toBe(true); expect(refused.env.draft.contract_profile.amendment_policy).toBe(policy);
 const sender = fixture(false); sender.callbacks.changeAmendmentPolicy({ currentTarget: { checked: true } }); expect(sender.env.draft.contract_profile.amendment_policy).toBeUndefined();
});
test('actual mode changes canonicalize selected permissions without granting email implicitly and disabled policy is omitted', () => {
 const f = fixture(); f.callbacks.changeAmendmentPolicy({ currentTarget: { checked: true } }); f.callbacks.changeAmendmentMode('signature', true); f.callbacks.changeAmendmentMode('agreed_notice', true); const policy = f.env.draft.contract_profile.amendment_policy; expect(policy.allowed_modes).toEqual(['agreed_notice', 'signature']); expect(policy.allowed_channels).toEqual([]); policy.allowed_channels = ['email']; f.callbacks.changeAmendmentMode('agreed_notice', false); expect(policy.allowed_modes).toEqual(['signature']); expect(policy.allowed_channels).toEqual([]); f.callbacks.changeAmendmentPolicy({ currentTarget: { checked: false } }); expect(Object.hasOwn(f.env.draft.contract_profile, 'amendment_policy')).toBe(false);
});
