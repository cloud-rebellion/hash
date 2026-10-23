import { checkedSigningActor } from '../signingRegistry';
import { checkedPreSignEligibility, checkedPreSignIntent, checkedPreSignMarker, checkedPreSignPreview, checkedPreSignView, type PreSignIntent, type PreSignMarker, type PreSignTransport } from '../presignExecution';
import { getSigningContext, getSigningGrants, getSigningWorkflows, signingAuthorityRequest } from './signingRegistry';
import { htmlUUID } from '../htmlRevision';

const base = '/api/v1/presign/executions';
const id = (value: string) => { if (!htmlUUID(value) || value !== value.toLowerCase()) throw new Error('Invalid pre-signing identity.'); return encodeURIComponent(value); };
export async function getPreSignEligibility(documentID: string, signal: AbortSignal) {
  return checkedPreSignEligibility(await signingAuthorityRequest(`${base}/documents/${id(documentID)}/eligibility`, signal, undefined, 16384));
}
export async function previewPreSignExecution(intent: PreSignIntent, signal: AbortSignal) {
  return checkedPreSignPreview(await signingAuthorityRequest(`${base}/preview`, signal, checkedPreSignIntent(intent), 65536));
}
export async function executePreSign(input: { intent: PreSignIntent; receipt: string; confirmed: true }, signal: AbortSignal) {
  if (!input || input.confirmed !== true || typeof input.receipt !== 'string' || !input.receipt || input.receipt.length > 16384 || /\s/u.test(input.receipt)) throw new Error('Review and explicitly confirm this exact pre-signing request.');
  const body = { intent: checkedPreSignIntent(input.intent), receipt: input.receipt, confirmed: true };
  return checkedPreSignView(await signingAuthorityRequest(base, signal, body, 16384));
}
export async function inspectPreSignExecution(marker: PreSignMarker, signal: AbortSignal) {
  const original = checkedPreSignMarker(marker);
  return checkedPreSignView(await signingAuthorityRequest(`${base}/requests/${id(original.request_id)}`, signal, undefined, 16384));
}
export async function closePreSignExecution(marker: PreSignMarker, signal: AbortSignal) {
  const original = checkedPreSignMarker(marker);
  return checkedPreSignView(await signingAuthorityRequest(`${base}/requests/${id(original.request_id)}/close`, signal,
    { request_id: original.request_id, expected_org_id: original.org_id, expected_user_id: original.user_id, confirmed: true }, 16384));
}
export const preSignTransport: PreSignTransport = {
  identity: async signal => checkedSigningActor(await signingAuthorityRequest('/api/v1/me', signal, undefined, 16384)),
  context: getSigningContext, grants: signal => getSigningGrants(signal), workflows: getSigningWorkflows,
  eligibility: getPreSignEligibility, preview: previewPreSignExecution, execute: executePreSign,
  inspect: inspectPreSignExecution, close: closePreSignExecution,
};
