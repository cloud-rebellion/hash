import { APIError, type HTMLDocumentInput, type HTMLDocumentSource, type TemplateResponse } from './client';
import { htmlSHA256, htmlUUID } from '../htmlRevision';
import { checkedCRMDocumentActor, crmMappings } from '../crmDocument';
import { CRM_KINDS, checkedCreationMarker, checkedTemplateCandidate, checkedTemplateContext, checkedTemplateExpected, checkedTemplateObservation,
  checkedTemplateSearch, validCRMSearch, type CRMTemplateExpected, type CRMKind, type CRMMapping, type CRMTemplateCandidate,
  type HTMLCreationMarker, type CRMTemplateTransport } from '../crmTemplatePopulation';

const maxBytes = 8 * 1024 * 1024;
async function json(response: Response, signal: AbortSignal): Promise<unknown> {
  const size = response.headers.get('Content-Length');
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || (size !== null && (!/^\d+$/.test(size) || Number(size) > maxBytes))) {
    await response.body?.cancel().catch(() => {}); throw new Error('Invalid template creation response.');
  }
  const reader = response.body?.getReader(); if (!reader) throw new Error('Invalid template creation response.');
  let length = 0; const chunks: Uint8Array[] = [];
  try {
    while (true) {
      if (signal.aborted) throw new Error('Template request aborted.');
      const chunk = await reader.read(); if (signal.aborted) throw new Error('Template request aborted.'); if (chunk.done) break;
      length += chunk.value.byteLength; if (length > maxBytes) throw new Error('Invalid template creation response.'); chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('Invalid template creation response.'); }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function request(path: string, signal: AbortSignal, input?: unknown, limit = 262144, creation = false): Promise<unknown> {
  if (signal.aborted) throw new Error('Template request aborted.');
  const body = input === undefined ? undefined : JSON.stringify(input);
  if (body !== undefined && new TextEncoder().encode(body).length > limit) throw new Error('The entered information exceeds this request limit. Reduce it before continuing.');
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'include', cache: 'no-store', signal,
    headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body }) });
  if (!response.ok || (creation && ![200, 201].includes(response.status))) {
    await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'The template request was refused.');
  }
  const result = await json(response, signal);
  if (creation && (!(result && typeof result === 'object') || (result as { replayed?: unknown }).replayed !== (response.status === 200))) throw new Error('Invalid template creation response.');
  return result;
}
const route = (id: string) => { if (!htmlUUID(id)) throw new Error('Invalid template identity.'); return `/api/v1/templates/${id}/html`; };
export async function getCRMTemplateContext(template: TemplateResponse, signal: AbortSignal) {
  if (!Number.isInteger(template.version) || template.version < 1 || !htmlSHA256(template.content_sha256)) throw new Error('Invalid approved design.');
  return checkedTemplateContext(await request(`${route(template.id)}/crm/context?expected_template_version=${template.version}&expected_template_content_sha256=${template.content_sha256}`, signal));
}
export async function searchCRMTemplateRecords(id: string, input: CRMTemplateExpected & { kind: CRMKind; query: string; offset: number }, signal: AbortSignal) {
  if (!CRM_KINDS.includes(input.kind) || !validCRMSearch(input.query, input.offset)) throw new Error('Invalid CRM search.');
  return checkedTemplateSearch(await request(`${route(id)}/crm/records/search`, signal,
    { ...checkedTemplateExpected(input), kind: input.kind, query: input.query, offset: input.offset }, 16384));
}
export async function observeCRMTemplate(id: string, input: CRMTemplateExpected & { candidate: CRMTemplateCandidate; mappings: CRMMapping[] }, signal: AbortSignal) {
  return checkedTemplateObservation(await request(`${route(id)}/crm/observations`, signal,
    { ...checkedTemplateExpected(input), candidate: checkedTemplateCandidate(input.candidate), mappings: crmMappings(input.mappings) }));
}
export async function createCRMTemplateDocument(id: string, input: HTMLDocumentInput, signal: AbortSignal) {
  if (!htmlUUID(input.request_id) || !htmlUUID(input.expected_org_id) || !htmlUUID(input.expected_user_id) || !Number.isInteger(input.expected_template_version) || input.expected_template_version < 1 || !htmlSHA256(input.expected_template_content_sha256)) throw new Error('Invalid creation identity.');
  const c = checkedTemplateCandidate({ name: input.name, values: input.values, ...(input.sections === undefined ? {} : { sections: input.sections }), ...(input.expires_at === undefined ? {} : { expires_at: input.expires_at }) });
  let population = input.crm_population;
  if (population) {
    const expected = checkedTemplateExpected(population);
    if (!htmlSHA256(population.reviewed_digest) || typeof population.review_receipt !== 'string' || !population.review_receipt || population.review_receipt.length > 8192 || /[\s\x00-\x1f\x7f]/.test(population.review_receipt) || population.confirmed !== true
      || expected.expected_org_id !== input.expected_org_id || expected.expected_user_id !== input.expected_user_id || expected.expected_template_version !== input.expected_template_version || expected.expected_template_content_sha256 !== input.expected_template_content_sha256) throw new Error('Confirm the exact reviewed template values first.');
    population = { ...expected, mappings: crmMappings(population.mappings), reviewed_digest: population.reviewed_digest, review_receipt: population.review_receipt, confirmed: true };
  }
  return request(`${route(id)}/documents`, signal, { ...c, expected_template_version: input.expected_template_version, expected_template_content_sha256: input.expected_template_content_sha256,
    request_id: input.request_id, expected_org_id: input.expected_org_id, expected_user_id: input.expected_user_id, ...(population === undefined ? {} : { crm_population: population }) }, 1048576, true);
}
export async function getHTMLCreationRequest(marker: HTMLCreationMarker, signal: AbortSignal) {
  const m = checkedCreationMarker(marker); return request(`${route(m.template_id)}/document-requests/${m.request_id}`, signal);
}
export async function stopHTMLCreationRequest(marker: HTMLCreationMarker, signal: AbortSignal) {
  const m = checkedCreationMarker(marker); return request(`${route(m.template_id)}/document-requests/${m.request_id}/close`, signal,
    { expected_org_id: m.org_id, expected_user_id: m.user_id, confirmed: true }, 2048);
}
export const crmTemplateTransport: CRMTemplateTransport = {
  identity: async (signal) => checkedCRMDocumentActor(await request('/api/v1/me', signal)),
  context: getCRMTemplateContext, search: searchCRMTemplateRecords, observe: observeCRMTemplate, create: createCRMTemplateDocument,
  readback: getHTMLCreationRequest, stop: stopHTMLCreationRequest,
  source: async (id, signal) => { if (!htmlUUID(id)) throw new Error('Invalid document identity.'); return await request(`/api/v1/documents/${id}/html/source`, signal) as HTMLDocumentSource; },
};
