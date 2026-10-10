import { APIError, type DocumentResponse, type HTMLDocumentSource } from './client';
import { htmlUUID } from '../htmlRevision';
import { CRM_KINDS, checkedCRMApply, checkedCRMContext, checkedCRMDocumentActor, checkedCRMExpected, checkedCRMObservation, checkedCRMSearch,
  crmMappings, validCRMSearch, type CRMExpected, type CRMKind, type CRMMapping, type CRMDocumentTransport } from '../crmDocument';

const maxResponseBytes = 8 * 1024 * 1024;
async function boundedJSON(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) {
    await response.body?.cancel().catch(() => {}); throw new Error('Invalid CRM document response.');
  }
  const size = response.headers.get('Content-Length');
  if (size !== null && (!/^[0-9]+$/.test(size) || Number(size) > maxResponseBytes)) {
    await response.body?.cancel().catch(() => {}); throw new Error('Invalid CRM document response.');
  }
  const reader = response.body?.getReader(); if (!reader) throw new Error('Invalid CRM document response.');
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error('CRM document request aborted.');
      const chunk = await reader.read();
      if (signal.aborted) throw new Error('CRM document request aborted.');
      if (chunk.done) break;
      length += chunk.value.byteLength; if (length > maxResponseBytes) throw new Error('Invalid CRM document response.'); chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('Invalid CRM document response.'); }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function request(path: string, signal: AbortSignal, input?: unknown): Promise<unknown> {
  if (signal.aborted) throw new Error('CRM document request aborted.');
  const response = await fetch(path, { method: input === undefined ? 'GET' : 'POST', credentials: 'include', cache: 'no-store', signal,
    headers: { Accept: 'application/json', ...(input === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(input === undefined ? {} : { body: JSON.stringify(input) }) });
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'The CRM document request was refused.'); }
  return boundedJSON(response, signal);
}
function documentRoute(id: string): string { if (!htmlUUID(id)) throw new Error('Invalid document identity.'); return `/api/v1/documents/${id}`; }
export async function getCRMDocumentContext(id: string, signal: AbortSignal) { return checkedCRMContext(await request(`${documentRoute(id)}/crm/context`, signal)); }
export async function searchCRMDocumentRecords(id: string, input: CRMExpected & { kind: CRMKind; query: string; offset: number }, signal: AbortSignal) {
  const expected = checkedCRMExpected(input);
  if (!CRM_KINDS.includes(input.kind) || !validCRMSearch(input.query, input.offset)) throw new Error('Invalid CRM search.');
  return checkedCRMSearch(await request(`${documentRoute(id)}/crm/records/search`, signal, { ...expected, kind: input.kind, query: input.query, offset: input.offset }));
}
export async function observeCRMDocument(id: string, input: CRMExpected & { mappings: CRMMapping[] }, signal: AbortSignal) {
  return checkedCRMObservation(await request(`${documentRoute(id)}/crm/observations`, signal, { ...checkedCRMExpected(input), mappings: crmMappings(input.mappings) }));
}
export async function applyCRMDocument(id: string, input: CRMExpected & { mappings: CRMMapping[]; reviewed_digest: string; confirmed: true }, signal: AbortSignal) {
  if (!/^[a-f0-9]{64}$/.test(input.reviewed_digest) || input.confirmed !== true) throw new Error('Confirm the exact CRM observation before applying.');
  return checkedCRMApply(await request(`${documentRoute(id)}/crm/apply`, signal, { ...checkedCRMExpected(input), mappings: crmMappings(input.mappings), reviewed_digest: input.reviewed_digest, confirmed: true }));
}
export const crmDocumentTransport: CRMDocumentTransport = {
  identity: async (signal) => checkedCRMDocumentActor(await request('/api/v1/me', signal)),
  context: getCRMDocumentContext, search: searchCRMDocumentRecords, observe: observeCRMDocument, apply: applyCRMDocument,
  document: async (id, signal) => await request(documentRoute(id), signal) as DocumentResponse,
  source: async (id, signal) => await request(`${documentRoute(id)}/html/source`, signal) as HTMLDocumentSource,
};
