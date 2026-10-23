// Saved relation disclosure only. This grants no original-file access and does
// not replace current PDF/package proof, recipient authority or submission gates.
export type SignerAmendmentDisclosure = {
 schema: 'hash-signer-amendment-context-v1'; amendment_id: string; revision: string; document_id: string;
 original_document_id: string; original_name: string; original_final_pdf_sha256: string;
 original_report_sha256: string; original_report_pdf_sha256: string;
 mode: 'signature' | 'acknowledgement'; file_commitment_sha256: string;
};
const ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const validID = (value: unknown): value is string => typeof value === 'string' && ID.test(value) && value !== '00000000-0000-0000-0000-000000000000';
export const signerAmendmentUnavailable = 'The amendment reference could not be verified. Reopen your link before continuing.';
export function validateSignerAmendmentContext(value: unknown, documentID: string, requiresSignature: boolean, sourceKind: string): SignerAmendmentDisclosure {
 const keys = ['schema', 'amendment_id', 'revision', 'document_id', 'original_document_id', 'original_name', 'original_final_pdf_sha256', 'original_report_sha256', 'original_report_pdf_sha256', 'mode', 'file_commitment_sha256'];
 if (!value || typeof value !== 'object' || Array.isArray(value) || !keys.every(key => Object.hasOwn(value, key)) || Object.keys(value).some(key => !keys.includes(key))) throw new Error(signerAmendmentUnavailable);
 const context = value as SignerAmendmentDisclosure;
 if (context.schema !== 'hash-signer-amendment-context-v1' || !validID(context.amendment_id) || !validID(documentID) || context.document_id !== documentID || !validID(context.original_document_id) || context.original_document_id === documentID || typeof context.revision !== 'string' || !/^[1-9][0-9]?$/.test(context.revision) || BigInt(context.revision) > 64n || typeof context.original_name !== 'string' || !context.original_name.trim() || new TextEncoder().encode(context.original_name).length > 512 || /[\p{Cc}\p{Cs}]/u.test(context.original_name) || [context.original_final_pdf_sha256, context.original_report_sha256, context.original_report_pdf_sha256, context.file_commitment_sha256].some(hash => typeof hash !== 'string' || !SHA.test(hash)) || sourceKind !== 'pdf' || typeof requiresSignature !== 'boolean' || context.mode !== (requiresSignature ? 'signature' : 'acknowledgement')) throw new Error(signerAmendmentUnavailable);
 return { schema: context.schema, amendment_id: context.amendment_id, revision: context.revision, document_id: context.document_id, original_document_id: context.original_document_id, original_name: context.original_name, original_final_pdf_sha256: context.original_final_pdf_sha256, original_report_sha256: context.original_report_sha256, original_report_pdf_sha256: context.original_report_pdf_sha256, mode: context.mode, file_commitment_sha256: context.file_commitment_sha256 };
}
export const signerAmendmentProcess = (mode: SignerAmendmentDisclosure['mode']) => mode === 'signature' ? 'New signature' : 'Explicit acknowledgement';
