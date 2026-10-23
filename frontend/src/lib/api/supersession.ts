import { APIError } from './client';
import { signingAuthorityRequest } from './signingRegistry';
import { checkedSupersessionClosure, checkedSupersessionContext, checkedSupersessionMarker, checkedSupersessionResult, type SupersessionActor, type SupersessionMarker, type SupersessionOutcome, type SupersessionReady, supersessionCommand } from '../supersession';
const base = '/api/v1/presign/supersessions';
export async function getSupersessionContext(documentID: string, actor: SupersessionActor, signal: AbortSignal) {
  if (!/^[a-f0-9-]{36}$/.test(documentID)) throw new Error('Invalid original document.');
  return checkedSupersessionContext(await signingAuthorityRequest(`${base}/documents/${encodeURIComponent(documentID)}/context`, signal, undefined, 1 << 20), actor, documentID);
}
export async function createSupersession(context: SupersessionReady, name: string, values: Record<string, string>, sections: Record<string, string>, marker: SupersessionMarker, signal: AbortSignal) {
  const m = checkedSupersessionMarker(marker);
  if (m.org_id !== context.org_id || m.user_id !== context.user_id || m.prior_document_id !== context.prior.document_id || m.prior_execution_id !== context.prior.execution_id || m.template_id !== context.template.id) throw new Error('The original supersession actor changed.');
  const result = checkedSupersessionResult(await signingAuthorityRequest(base, signal, supersessionCommand(context, name, values, sections, m.request_id), 16384), m);
  if (result.source_commitment === context.prior.source_commitment) throw new Error('The linked draft reused the original source. Keep this request for inspection.');
  return result;
}
const originalPath = (m: SupersessionMarker) => `/api/v1/templates/${m.template_id}/html/document-requests/${m.request_id}`;
export async function inspectSupersession(marker: SupersessionMarker, signal: AbortSignal): Promise<SupersessionOutcome> {
  const m = checkedSupersessionMarker(marker);
  try { return checkedSupersessionResult(await signingAuthorityRequest(`${base}/requests/${m.request_id}`, signal, undefined, 16384), m); }
  catch (error) { if (!(error instanceof APIError) || error.status !== 404) throw error; }
  // Reuse the actual original M79 tombstone. A generic committed creation is
  // never adopted as a linked result when the exact supersession is absent.
  try { const original = await signingAuthorityRequest(originalPath(m), signal, undefined, 1 << 20); if (checkedSupersessionClosure(original, m)) return { state: 'closed' }; throw new Error('The original source exists without a verified supersession link. Keep this request for inspection.'); }
  catch (error) { if (error instanceof APIError && error.status === 404) return { state: 'unconfirmed' }; throw error; }
}
export async function closeSupersession(marker: SupersessionMarker, signal: AbortSignal): Promise<SupersessionOutcome> {
  const m = checkedSupersessionMarker(marker);
  const original = await signingAuthorityRequest(`${originalPath(m)}/close`, signal, { expected_org_id: m.org_id, expected_user_id: m.user_id, confirmed: true }, 1 << 20);
  if (checkedSupersessionClosure(original, m)) return { state: 'closed' };
  return inspectSupersession(m, signal);
}
