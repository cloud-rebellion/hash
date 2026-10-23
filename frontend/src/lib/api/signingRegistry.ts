import { APIError } from './client';
import { checkedGrantIntent, checkedSigningActor, checkedSigningCollection, checkedSigningContext, checkedSigningGrant, checkedSigningMarker, checkedSigningOutcome, checkedSigningPreview, checkedSigningReference, checkedSigningTemplates, checkedSigningWorkflow, checkedWorkflowIntent, signingOperations,
  type SigningGrantIntent, type SigningMarker, type SigningOperation, type SigningRegistryTransport, type SigningStyle, type SigningWorkflowIntent } from '../signingRegistry';
import { htmlSHA256, htmlUUID } from '../htmlRevision';

const base = '/api/v1/presign';
export { request as signingAuthorityRequest };
async function boundedBytes(response: Response, signal: AbortSignal, max: number) {
  const length = response.headers.get('Content-Length');
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > max)) { await response.body?.cancel().catch(() => {}); throw new Error('Invalid signing authority response.'); }
  const reader = response.body?.getReader(); if (!reader) throw new Error('Invalid signing authority response.');
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) { if (signal.aborted) throw new Error('Signing request aborted.'); const r = await reader.read(); if (signal.aborted) throw new Error('Signing request aborted.'); if (r.done) break; size += r.value.byteLength; if (size > max) throw new Error('Invalid signing authority response.'); chunks.push(r.value); }
    const data = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; } return data;
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function request(path: string, signal: AbortSignal, body?: unknown, max = 1024 * 1024): Promise<unknown> {
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'include', cache: 'no-store', signal,
    headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'The signing authority request was refused.'); }
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) { await response.body?.cancel().catch(() => {}); throw new Error('Invalid signing authority response.'); }
  const data = await boundedBytes(response, signal, max);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); } catch { throw new Error('Invalid signing authority response.'); }
}
const id = (v: string) => { if (!htmlUUID(v)) throw new Error('Invalid signing authority identity.'); return v; };
export async function getSigningContext(signal: AbortSignal) { return checkedSigningContext(await request(`${base}/context`, signal, undefined, 65536)); }
export async function getSigningTemplates(signal: AbortSignal) { return checkedSigningTemplates(await request(`${base}/templates`, signal, undefined, 4 * 1024 * 1024)); }
export async function getSigningWorkflows(signal: AbortSignal) { return checkedSigningCollection(await request(`${base}/workflows`, signal, undefined, 32 * 1024 * 1024), checkedSigningWorkflow); }
export async function getSigningGrants(signal: AbortSignal, owner = false) { return checkedSigningCollection(await request(`${base}/${owner ? 'grants' : 'self-grants'}`, signal, undefined, 1024 * 1024), checkedSigningGrant); }
export async function previewSigningAuthority(kind: 'workflow' | 'grant', intent: SigningWorkflowIntent | SigningGrantIntent, signal: AbortSignal) {
  const input = kind === 'workflow' ? checkedWorkflowIntent(intent) : checkedGrantIntent(intent);
  return checkedSigningPreview(await request(`${base}/${kind === 'workflow' ? 'workflows' : 'self-grants'}/preview`, signal, input), kind);
}
export async function mutateSigningAuthority(operation: SigningOperation, input: unknown, signal: AbortSignal) {
  if (!signingOperations.includes(operation)) throw new Error('Invalid signing authority operation.');
  let path: string, body: unknown;
  if (['workflow.approve', 'grant.create', 'grant.revise'].includes(operation)) {
    const r = input as { intent: SigningWorkflowIntent | SigningGrantIntent; receipt: string; confirmed: boolean };
    if (!r || r.confirmed !== true || typeof r.receipt !== 'string' || !r.receipt || r.receipt.length > 16384 || /\s/u.test(r.receipt)) throw new Error('Review and confirm this exact authority first.');
    const intent = operation === 'workflow.approve' ? checkedWorkflowIntent(r.intent) : checkedGrantIntent(r.intent);
    path = operation === 'workflow.approve' ? `${base}/workflows/approve` : operation === 'grant.create' ? `${base}/self-grants/create` : `${base}/self-grants/${id((intent as SigningGrantIntent).grant_id)}/revise`;
    body = { intent, receipt: r.receipt, confirmed: true };
  } else {
    const r = input as { request_id: string; expected_org_id: string; expected_user_id: string; reference: unknown; confirmed: boolean };
    if (!r || !htmlUUID(r.request_id) || !htmlUUID(r.expected_org_id) || !htmlUUID(r.expected_user_id) || r.confirmed !== true) throw new Error('Invalid signing authority confirmation.');
    const reference = checkedSigningReference(r.reference);
    path = operation === 'workflow.retire' || operation === 'workflow.archive' ? `${base}/workflows/${id(reference.id)}/${operation === 'workflow.retire' ? 'retire' : 'archive'}` : `${base}/${operation === 'grant.self_revoke' ? 'self-grants' : 'grants'}/${id(reference.id)}/revoke`;
    body = { request_id: r.request_id, expected_org_id: r.expected_org_id, expected_user_id: r.expected_user_id, reference, confirmed: true };
  }
  return checkedSigningOutcome(await request(path, signal, body, 16384));
}
export async function getSigningRequest(marker: SigningMarker, signal: AbortSignal) { const m = checkedSigningMarker(marker); return checkedSigningOutcome(await request(`${base}/requests/${id(m.request_id)}`, signal, undefined, 16384)); }
export async function closeSigningRequest(marker: SigningMarker, signal: AbortSignal) {
  const m = checkedSigningMarker(marker);
  return checkedSigningOutcome(await request(`${base}/requests/${id(m.request_id)}/close`, signal, { request_id: m.request_id, expected_org_id: m.org_id, expected_user_id: m.user_id, confirmed: true }, 16384));
}
const loadedFonts = new Map<string, string>();
export async function loadSigningFont(style: SigningStyle, signal: AbortSignal): Promise<string> {
  if (!htmlSHA256(style.font_sha256) || typeof style.font !== 'string' || !style.font || style.font.length > 100) throw new Error('Invalid signature font.');
  const family = `HashAuthority_${style.font_sha256}`;
  if (loadedFonts.get(style.font_sha256) === family) return family;
  const response = await fetch(`${base}/fonts/${encodeURIComponent(style.font)}`, { credentials: 'include', cache: 'no-store', signal });
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'The signature font could not be loaded.'); }
  if (!/^font\/woff2(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) { await response.body?.cancel().catch(() => {}); throw new Error('Invalid signature font.'); }
  const data = await boundedBytes(response, signal, 2 * 1024 * 1024);
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))].map(x => x.toString(16).padStart(2, '0')).join('');
  if (signal.aborted || digest !== style.font_sha256) throw new Error('The signature font could not be verified.');
  const face = new FontFace(family, data); await face.load(); if (signal.aborted || face.status !== 'loaded') throw new Error('The signature font could not be loaded.');
  document.fonts.add(face); loadedFonts.set(style.font_sha256, family); return family;
}
export const signingRegistryTransport: SigningRegistryTransport = {
  identity: async signal => checkedSigningActor(await request('/api/v1/me', signal, undefined, 16384)),
  context: getSigningContext, templates: getSigningTemplates, workflows: getSigningWorkflows, grants: getSigningGrants,
  preview: previewSigningAuthority, mutate: mutateSigningAuthority, outcome: getSigningRequest, close: closeSigningRequest, signatureFont: loadSigningFont,
};
