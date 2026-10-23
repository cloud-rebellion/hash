import { htmlSHA256, htmlUUID } from './htmlRevision';
import type { SignerPDFObservation } from './signerPDF';

export interface SignerPreSignDisclosure {
  schema_version: 1; execution_id: string; execution_sha256: string; visible_pdf_sha256: string;
  disclosure_version: 1; disclosure_sha256: string; disclosure_text: string;
  provider_name: string; executed_at: string; document_id: string;
}
export function validateSignerPreSignContext(value: unknown, documentID: string, requiresSignature: boolean, sourceKind: string, observation?: SignerPDFObservation): SignerPreSignDisclosure {
  const invalid = 'The provider pre-signing evidence could not be verified. Reopen your original signing link.';
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(invalid);
  const r = value as Record<string, unknown>;
  const fields = ['schema_version', 'execution_id', 'execution_sha256', 'visible_pdf_sha256', 'disclosure_version', 'disclosure_sha256', 'disclosure_text', 'provider_name', 'executed_at', 'document_id'];
  const text = (v: unknown, max: number, multiline = false): v is string => typeof v === 'string' && !!v.trim() && new TextEncoder().encode(v).length <= max && !(multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u : /[\u0000-\u001f\u007f]/u).test(v);
  if (fields.some(key => !Object.hasOwn(r, key)) || Object.keys(r).some(key => !fields.includes(key))
      || r.schema_version !== 1 || r.disclosure_version !== 1 || requiresSignature !== true || sourceKind !== 'pdf'
      || !htmlUUID(r.document_id) || r.document_id !== documentID || !htmlUUID(r.execution_id) || r.execution_id === '00000000-0000-0000-0000-000000000000'
      || !htmlSHA256(r.execution_sha256) || !htmlSHA256(r.visible_pdf_sha256) || !htmlSHA256(r.disclosure_sha256)
      || !observation || observation.document_id !== documentID || observation.pdf_sha256 !== r.visible_pdf_sha256
      || !text(r.provider_name, 800) || !text(r.disclosure_text, 32768, true)
      || !text(r.executed_at, 40) || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(r.executed_at) || !Number.isFinite(Date.parse(r.executed_at))
      || new Date(Date.parse(`${r.executed_at.slice(0, 19)}Z`)).toISOString().slice(0, 19) !== r.executed_at.slice(0, 19)) throw new Error(invalid);
  return { ...r } as unknown as SignerPreSignDisclosure;
}
