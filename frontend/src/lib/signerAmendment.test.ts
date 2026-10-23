import { expect, test } from 'bun:test';
import { signerAmendmentUnavailable, validateSignerAmendmentContext, type SignerAmendmentDisclosure } from './signerAmendment';
const candidate = '11111111-1111-4111-8111-111111111111', original = '22222222-2222-4222-8222-222222222222', amendment = '33333333-3333-4333-8333-333333333333';
export function signerAmendmentFixture(signature = true): SignerAmendmentDisclosure { return { schema: 'hash-signer-amendment-context-v1', amendment_id: amendment, revision: '1', document_id: candidate, original_document_id: original, original_name: 'Original services agreement', original_final_pdf_sha256: 'a'.repeat(64), original_report_sha256: 'b'.repeat(64), original_report_pdf_sha256: 'c'.repeat(64), mode: signature ? 'signature' : 'acknowledgement', file_commitment_sha256: 'd'.repeat(64) }; }
test('signer relation disclosure preserves the distinct original PDF, canonical report and report PDF domains', () => {
 const input = signerAmendmentFixture(), result = validateSignerAmendmentContext(input, candidate, true, 'pdf'); expect(result).toEqual(input); expect(result).not.toBe(input); expect(result.original_report_sha256).not.toBe(result.original_report_pdf_sha256); expect(result.original_final_pdf_sha256).not.toBe(result.file_commitment_sha256); result.original_name = 'Changed copy'; expect(input.original_name).toBe('Original services agreement');
});
test('signer disclosure refuses missing, unknown, foreign, noncanonical and notice-purpose fields', () => {
 const input = signerAmendmentFixture();
 for (const value of [{ ...input, mode: 'agreed_notice' }, { ...input, document_id: original }, { ...input, original_document_id: candidate }, { ...input, revision: '01' }, { ...input, revision: '65' }, { ...input, revision: 1 }, { ...input, original_report_pdf_sha256: undefined }, { ...input, original_final_pdf_sha256: 'invalid' }, { ...input, original_pdf_url: '/completed/not-a-grant' }, null]) expect(() => validateSignerAmendmentContext(value, candidate, true, 'pdf')).toThrow(signerAmendmentUnavailable);
 expect(validateSignerAmendmentContext({ ...input, revision: '64' }, candidate, true, 'pdf').revision).toBe('64');
});
test('only matching ordinary PDF signature or acknowledgement ceremonies accept a relation disclosure', () => {
 expect(validateSignerAmendmentContext(signerAmendmentFixture(false), candidate, false, 'pdf').mode).toBe('acknowledgement'); expect(() => validateSignerAmendmentContext(signerAmendmentFixture(false), candidate, true, 'pdf')).toThrow(); expect(() => validateSignerAmendmentContext(signerAmendmentFixture(), candidate, true, 'blocks')).toThrow();
});
test('saved original name preserves exact bytes and obeys the native512 UTF8/no-control bound', () => {
 const input = signerAmendmentFixture(); expect(validateSignerAmendmentContext({ ...input, original_name: '  Original name  ' }, candidate, true, 'pdf').original_name).toBe('  Original name  '); expect(validateSignerAmendmentContext({ ...input, original_name: 'é'.repeat(256) }, candidate, true, 'pdf').original_name.length).toBe(256);
 for (const original_name of ['é'.repeat(257), ' ', 'Name\nOther', 'Name\u0085Other', '\ud800']) expect(() => validateSignerAmendmentContext({ ...input, original_name }, candidate, true, 'pdf')).toThrow();
});
