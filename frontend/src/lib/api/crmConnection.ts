import { APIError } from './client';
import { checkedCRMConnection, checkedCRMOwner, crmGeneration, crmOpaqueID, crmToken, type CRMActorExpectation, type CRMConnectionResponse, type CRMConnectionTransport } from '../crmConnection';

const route = '/api/v1/settings/crm/connection';
const maxResponseBytes = 16 * 1024;
// Strict byte cap before JSON parsing. Raw upstream/error bodies are never exposed.
async function boundedJSON(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) {
    await response.body?.cancel().catch(() => {}); throw new Error('Invalid connection response.');
  }
  const size = response.headers.get('Content-Length');
  if (size !== null && (!/^[0-9]+$/.test(size) || Number(size) > maxResponseBytes)) {
    await response.body?.cancel().catch(() => {}); throw new Error('Invalid connection response.');
  }
  const reader = response.body?.getReader(); if (!reader) throw new Error('Invalid connection response.');
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error('Connection request aborted.');
      const chunk = await reader.read();
      if (signal.aborted) throw new Error('Connection request aborted.');
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > maxResponseBytes) throw new Error('Invalid connection response.');
      chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new Error('Invalid connection response.'); }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function request(method: string, path: string, signal: AbortSignal, body?: unknown): Promise<unknown> {
  const response = await fetch(path, { method, credentials: 'include', cache: 'no-store', signal,
    headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new APIError(response.status, 'The CRM connection request was refused.');
  }
  return boundedJSON(response, signal);
}
function generation(value: string) { if (!crmGeneration(value, true)) throw new Error('Invalid expected connection generation.'); }
export async function getCRMConnection(signal: AbortSignal): Promise<CRMConnectionResponse> {
  return checkedCRMConnection(await request('GET', route, signal));
}
function actor(input: CRMActorExpectation) {
  checkedCRMOwner({ org_id: input.expected_org_id, user_id: input.expected_user_id, role: 'owner' });
  return { expected_org_id: input.expected_org_id, expected_user_id: input.expected_user_id };
}
export async function configureCRMConnection(input: CRMActorExpectation & { expected_generation: string; token: string }, signal: AbortSignal): Promise<CRMConnectionResponse> {
  generation(input.expected_generation); if (!crmToken(input.token)) throw new Error('Invalid CRM key.');
  return checkedCRMConnection(await request('PUT', route, signal, { ...actor(input), expected_generation: input.expected_generation, token: input.token }));
}
export async function enableCRMConnection(input: CRMActorExpectation & { expected_generation: string; crm_team_id: string; crm_user_id: string }, signal: AbortSignal): Promise<CRMConnectionResponse> {
  generation(input.expected_generation);
  if (input.expected_generation === '0' || !crmOpaqueID(input.crm_team_id) || !crmOpaqueID(input.crm_user_id)) throw new Error('Invalid CRM account confirmation.');
  return checkedCRMConnection(await request('POST', `${route}/enable`, signal, { ...actor(input), expected_generation: input.expected_generation, crm_team_id: input.crm_team_id, crm_user_id: input.crm_user_id }));
}
export async function revokeCRMConnection(input: CRMActorExpectation & { expected_generation: string }, signal: AbortSignal): Promise<CRMConnectionResponse> {
  generation(input.expected_generation); if (input.expected_generation === '0') throw new Error('Invalid expected connection generation.');
  return checkedCRMConnection(await request('DELETE', route, signal, { ...actor(input), expected_generation: input.expected_generation }));
}
export const crmConnectionTransport: CRMConnectionTransport = {
  identity: async (signal) => checkedCRMOwner(await request('GET', '/api/v1/me', signal)),
  read: getCRMConnection, configure: configureCRMConnection, enable: enableCRMConnection, revoke: revokeCRMConnection,
};
