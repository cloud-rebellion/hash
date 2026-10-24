export type StaffAuthAction = 'login' | 'register' | 'verify-email' | 'forgot-password' | 'reset-password';
export type StaffAuthStatus = { password_enabled: true; oidc_enabled: boolean };

const base = '/api/v1/auth/';
const unavailable = 'Hash could not complete this request. Please try again.';

export class StaffAuthError extends Error {}

export function staffAuthErrorMessage(error: unknown): string {
  return error instanceof StaffAuthError ? error.message : unavailable;
}

function refusal(action: StaffAuthAction, status: number): string {
  if (status === 429) return 'Too many attempts. Please wait a moment before trying again.';
  if (action === 'login' && (status === 401 || status === 403)) return 'Check your email and password, and make sure your email address is verified.';
  if (action === 'verify-email' && [400, 401, 403, 404, 410].includes(status)) return 'Verification was refused. Check the password you chose when creating your workspace and open the latest verification email.';
  if (action === 'reset-password' && [400, 401, 403, 404, 410].includes(status)) return 'This reset link is invalid or has expired. Request a new password reset email.';
  if (action === 'register' && status === 400) return 'Check your details and use a password of at least 12 characters.';
  return unavailable;
}

async function request(action: StaffAuthAction | 'status', signal: AbortSignal, body?: object): Promise<Response> {
  try {
    if (signal.aborted) throw new Error('aborted');
    return await fetch(base + action, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'include', cache: 'no-store',
      redirect: 'error', mode: 'cors', signal,
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
  } catch { throw new StaffAuthError(unavailable); }
}

export async function getStaffAuthStatus(signal: AbortSignal): Promise<StaffAuthStatus> {
  const response = await request('status', signal);
  if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) {
    await response.body?.cancel().catch(() => {});
    throw new StaffAuthError(unavailable);
  }
  const reader = response.body?.getReader();
  if (!reader) throw new StaffAuthError(unavailable);
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error('aborted');
      const chunk = await reader.read();
      if (signal.aborted) throw new Error('aborted');
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > 1024) throw new Error('oversize');
      chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 2 || value.password_enabled !== true || typeof value.oidc_enabled !== 'boolean') throw new Error('invalid');
    return { password_enabled: true, oidc_enabled: value.oidc_enabled };
  } catch { throw new StaffAuthError(unavailable); }
  finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

async function post(action: StaffAuthAction, body: object, signal: AbortSignal): Promise<void> {
  const response = await request(action, signal, body);
  // The session is an HttpOnly cookie; no token or upstream error body is read.
  await response.body?.cancel().catch(() => {});
  const expected = action === 'register' || action === 'forgot-password' ? 202 : 200;
  if (response.status !== expected || signal.aborted) throw new StaffAuthError(refusal(action, response.status));
}

export const loginWithPassword = (email: string, password: string, signal: AbortSignal) => post('login', { email, password }, signal);
export const registerWorkspace = (email: string, name: string, company_name: string, password: string, signal: AbortSignal) => post('register', { email, name, company_name, password }, signal);
export const verifyStaffEmail = (token: string, password: string, signal: AbortSignal) => post('verify-email', { token, password }, signal);
export const forgotStaffPassword = (email: string, signal: AbortSignal) => post('forgot-password', { email }, signal);
export const resetStaffPassword = (token: string, password: string, signal: AbortSignal) => post('reset-password', { token, password }, signal);
