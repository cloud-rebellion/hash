import { APIError } from './client';
import { normalizedSMTPHost, smtpBytes, type SMTPTestReceipt, type SMTPSaveInput, type WorkspaceSMTP } from '../workspaceSMTP';

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: Record<string, unknown>, expected: string[]) => Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key));
const revision = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value < Number.MAX_SAFE_INTEGER;
const text = (value: unknown, limit: number): value is string => typeof value === 'string' && smtpBytes(value) <= limit && !/[\u0000-\u001f\u007f]/.test(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== '00000000-0000-0000-0000-000000000000';
export function checkedWorkspaceSMTP(value: unknown): WorkspaceSMTP {
  if (!object(value) || !keys(value, ['schema_version', 'revision', 'mode', 'configured', 'host', 'port', 'tls_mode', 'sender_name', 'sender_email', 'username_set', 'password_set', 'updated_at'])
      || value.schema_version !== 1 || !revision(value.revision) || !['unconfigured', 'installation_legacy', 'configured', 'disabled'].includes(value.mode as string)
      || typeof value.configured !== 'boolean' || typeof value.username_set !== 'boolean' || value.password_set !== value.username_set
      || !text(value.host, 253) || !text(value.sender_name, 200) || !text(value.sender_email, 254)
      || !(value.updated_at === null || typeof value.updated_at === 'string' && value.updated_at.length <= 64 && /^\d{4}-\d\d-\d\dT/.test(value.updated_at) && Number.isFinite(Date.parse(value.updated_at)))) throw new Error('Delivery metadata contract rejected');
  if (value.mode === 'configured') {
    if (!value.configured || value.revision < 1 || !value.host || normalizedSMTPHost(value.host) !== value.host || !value.sender_name || !value.sender_email
        || !(value.port === 587 && value.tls_mode === 'starttls' || value.port === 465 && value.tls_mode === 'tls')) throw new Error('Configured delivery metadata rejected');
  } else if (value.configured || value.host !== '' || value.port !== 0 || value.tls_mode !== '' || value.sender_name !== '' || value.sender_email !== '' || value.username_set || value.password_set
      || (value.mode === 'disabled' ? value.revision < 1 : value.revision !== 0)) throw new Error('Inactive delivery metadata rejected');
  return value as unknown as WorkspaceSMTP;
}
export function checkedSMTPTest(value: unknown, expectedID?: string): SMTPTestReceipt {
  if (!object(value) || !keys(value, ['delivery_id', 'status', 'smtp_accepted', 'inbox_delivery_confirmed']) || !id(value.delivery_id)
      || expectedID !== undefined && value.delivery_id !== expectedID || !['pending', 'retrying', 'sent', 'failed'].includes(value.status as string)
      || value.smtp_accepted !== (value.status === 'sent') || value.inbox_delivery_confirmed !== false) throw new Error('Delivery test receipt rejected');
  return value as unknown as SMTPTestReceipt;
}
function saveInput(value: SMTPSaveInput) {
  const plain = value as unknown as Record<string, unknown>;
  const required = ['expected_revision', 'host', 'port', 'tls_mode', 'sender_name', 'sender_email', 'credentials_action'];
  if (!object(plain) || !keys(plain, value.credentials_action === 'keep' ? required : [...required, 'username', 'password']) || !revision(value.expected_revision)
      || !text(value.host, 253) || !value.host || normalizedSMTPHost(value.host) !== value.host || !text(value.sender_name, 200) || !value.sender_name
      || !text(value.sender_email, 254) || !value.sender_email || !(value.port === 587 && value.tls_mode === 'starttls' || value.port === 465 && value.tls_mode === 'tls')
      || !['keep', 'replace'].includes(value.credentials_action)) throw new Error('Delivery input rejected');
  if (value.credentials_action === 'replace' && (!text(value.username, 256) || !text(value.password, 4096) || (value.username === '') !== (value.password === ''))) throw new Error('Delivery authentication input rejected');
  return value;
}
async function jsonResponse(method: string, path: string, signal: AbortSignal, expectedStatus: number, body?: unknown): Promise<unknown> {
  const response = await fetch(path, { method, signal, credentials: 'include', cache: 'no-store', redirect: 'error', headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new APIError(response.status, 'Delivery request rejected.'); }
  if (response.status !== expectedStatus || !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) { await response.body?.cancel().catch(() => {}); throw new Error('Unexpected delivery response'); }
  const reader = response.body?.getReader(); if (!reader) throw new Error('Missing delivery response');
  const chunks: Uint8Array[] = []; let size = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > 32 * 1024) { await reader.cancel(); throw new Error('Delivery response exceeded its bound'); } chunks.push(part.value); } }
  finally { reader.releaseLock(); }
  const raw = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
}
export async function loadWorkspaceSMTP(signal: AbortSignal) { return checkedWorkspaceSMTP(await jsonResponse('GET', '/api/v1/workspace-smtp', signal, 200)); }
export async function saveWorkspaceSMTP(input: SMTPSaveInput, signal: AbortSignal) { return checkedWorkspaceSMTP(await jsonResponse('PUT', '/api/v1/workspace-smtp', signal, 200, saveInput(input))); }
export async function disableWorkspaceSMTP(expected_revision: number, signal: AbortSignal) { if (!revision(expected_revision)) throw new Error('Invalid delivery revision'); return checkedWorkspaceSMTP(await jsonResponse('DELETE', '/api/v1/workspace-smtp', signal, 200, { expected_revision })); }
export async function startWorkspaceSMTPTest(expected_revision: number, signal: AbortSignal) {
  if (!revision(expected_revision)) throw new Error('Invalid delivery revision'); const value = checkedSMTPTest(await jsonResponse('POST', '/api/v1/workspace-smtp/test', signal, 202, { expected_revision }));
  if (value.status !== 'pending') throw new Error('New delivery test is not pending'); return value;
}
export async function readWorkspaceSMTPTest(deliveryID: string, signal: AbortSignal) { if (!id(deliveryID)) throw new Error('Invalid delivery test identity'); return checkedSMTPTest(await jsonResponse('GET', `/api/v1/workspace-smtp/test/${encodeURIComponent(deliveryID)}`, signal, 200), deliveryID); }
