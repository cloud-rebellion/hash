import { expect, test } from 'bun:test';
import { checkedHTMLAmendmentPolicy, htmlAmendmentClause, htmlAmendmentPolicyIssues, htmlContractProfile, htmlProfileIssues } from './htmlTemplate';
import { draftFromHTMLTemplate, htmlAuthorFingerprint, htmlAuthorInput } from './htmlAuthor';
import { contractTemplateFixture } from './htmlTemplateFixtures';
const clause = 'Section 12. Later changes may follow the agreed process. They take effect after 30 days.';
function fixture(value = false) {
 const template = contractTemplateFixture(), master = template.html_master_json!;
 if (value) { master.values!.push({ name: 'later_change_clause', required: true, max_chars: 8192 }); (template.variables_json as Record<string, string>).later_change_clause = clause; master.contract_profile!.terms.push({ name: 'later_changes', value: 'later_change_clause' }); }
 else { master.sections!.push({ name: 'later_change_text', default_text: clause, max_chars: 8192 }); master.contract_profile!.terms.push({ name: 'later_changes', section: 'later_change_text' }); }
 master.contract_profile!.amendment_policy = { term: 'later_changes', clause_reference: 'Section 12.', allowed_modes: ['signature', 'agreed_notice', 'acknowledgement'], allowed_channels: ['email'], effective_condition: 'after 30 days' };
 const values = { ...(template.variables_json as Record<string, string>) }, sections = Object.fromEntries(master.sections!.map(section => [section.name, section.default_text])); return { template, master, values, sections };
}
test('optional declaration is omitted when disabled and old approved profile roundtrips unchanged', () => {
 const template = contractTemplateFixture(), original = JSON.stringify(template.html_master_json!.contract_profile), author = draftFromHTMLTemplate(template), input = htmlAuthorInput(author);
 expect(JSON.stringify(input.html_master_json.contract_profile)).toBe(original); expect(Object.hasOwn(input.html_master_json.contract_profile!, 'amendment_policy')).toBe(false); expect(htmlAuthorFingerprint(draftFromHTMLTemplate({ ...template, ...input }))).toBe(htmlAuthorFingerprint(author));
});
test('owner policy roundtrip canonicalizes copied modes and preserves explicit signature-only empty channels', () => {
 const f = fixture(), profile = htmlContractProfile(f.master)!; expect(profile.amendment_policy!.allowed_modes).toEqual(['acknowledgement', 'agreed_notice', 'signature']); expect(f.master.contract_profile!.amendment_policy!.allowed_modes).toEqual(['signature', 'agreed_notice', 'acknowledgement']);
 f.master.contract_profile!.amendment_policy!.allowed_modes = ['signature']; f.master.contract_profile!.amendment_policy!.allowed_channels = [];
 const author = draftFromHTMLTemplate(f.template); author.contract_profile = new Proxy(author.contract_profile!, {}); const input = htmlAuthorInput(author); expect(input.html_master_json.contract_profile!.amendment_policy!.allowed_channels).toEqual([]);
 input.html_master_json.contract_profile!.amendment_policy!.allowed_modes.push('acknowledgement'); expect(author.contract_profile.amendment_policy!.allowed_modes).toEqual(['signature']);
 const reloaded = draftFromHTMLTemplate({ ...f.template, ...htmlAuthorInput(author) }); expect(reloaded.contract_profile!.amendment_policy).toEqual(author.contract_profile.amendment_policy);
});
test('policy declaration refuses missing or hidden fields, unprinted names and invalid channel/mode combinations', () => {
 const f = fixture(), profile = f.master.contract_profile!, original = structuredClone(profile.amendment_policy!);
 for (const policy of [null, { ...original, allowed_channels: undefined }, { ...original, allowed_channels: null }, { ...original, term: 'unmapped_term' }, { ...original, allowed_modes: [] }, { ...original, allowed_modes: ['signature', 'signature'], allowed_channels: [] }, { ...original, allowed_modes: ['signature'], allowed_channels: ['email'] }, { ...original, allowed_channels: [] }, { ...original, inferred_legal_permission: true }]) expect(() => checkedHTMLAmendmentPolicy({ ...profile, amendment_policy: policy as any })).toThrow();
});
test('actual materialized values and sections must contain the exact selected printed reference and condition', () => {
 for (const value of [false, true]) { const f = fixture(value), profile = htmlContractProfile(f.master)!; expect(htmlAmendmentClause(profile, f.values, f.sections)).toBe(clause); expect(htmlAmendmentPolicyIssues(profile, f.values, f.sections)).toEqual([]); expect(htmlProfileIssues(profile, f.values, f.sections)).toEqual([]);
  const changedValues = { ...f.values }, changedSections = { ...f.sections }; if (value) changedValues.later_change_clause = 'Different actual document text.'; else changedSections.later_change_text = 'Different actual document text.'; expect(htmlAmendmentPolicyIssues(profile, changedValues, changedSections)).toHaveLength(1); expect(htmlProfileIssues(profile, changedValues, changedSections).length).toBeGreaterThan(0);
 }
});
test('policy text matches UTF8 byte bounds and refuses hidden formatting, control text and altered quotations', () => {
 const f = fixture(), profile = htmlContractProfile(f.master)!;
 for (const text of [' ' + clause, clause + ' ', clause + '\u200b', clause + '\u0085', clause + '\ud800', 'é'.repeat(4097), '   ']) expect(htmlAmendmentPolicyIssues(profile, f.values, { ...f.sections, later_change_text: text })).toHaveLength(1);
 const p = profile.amendment_policy!; for (const changed of [{ ...p, clause_reference: 'é'.repeat(257) }, { ...p, effective_condition: 'é'.repeat(1025) }, { ...p, clause_reference: 'Section\u200b 12.' }]) expect(() => checkedHTMLAmendmentPolicy({ ...profile, amendment_policy: changed })).toThrow();
 expect(htmlAmendmentPolicyIssues({ ...profile, amendment_policy: { ...p, effective_condition: 'after 31 days' } }, f.values, f.sections)).toHaveLength(1);
});
test('policy edits participate in actual author dirty-state and saved source instead of a hidden local setting', () => {
 const f = fixture(), author = draftFromHTMLTemplate(f.template), baseline = htmlAuthorFingerprint(author); author.contract_profile!.amendment_policy!.effective_condition = 'after 31 days'; expect(htmlAuthorFingerprint(author)).not.toBe(baseline); expect(htmlAuthorInput(author).html_master_json.contract_profile!.amendment_policy!.effective_condition).toBe('after 31 days'); delete author.contract_profile!.amendment_policy; expect(Object.hasOwn(htmlAuthorInput(author).html_master_json.contract_profile!, 'amendment_policy')).toBe(false);
});
