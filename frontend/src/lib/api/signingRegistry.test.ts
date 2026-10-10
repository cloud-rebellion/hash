import { expect, test } from 'bun:test';
import { closeSigningRequest, getSigningContext, getSigningRequest, mutateSigningAuthority, previewSigningAuthority } from './signingRegistry';
import { signingNilUUID, type SigningGrantIntent, type SigningMarker } from '../signingRegistry';

const org = '11111111-1111-4111-8111-111111111111', user = '22222222-2222-4222-8222-222222222222', resource = '33333333-3333-4333-8333-333333333333', requestID = '44444444-4444-4444-8444-444444444444', sha = 'a'.repeat(64);
const marker: SigningMarker = { version: 1, org_id: org, user_id: user, request_id: requestID, operation: 'grant.create', resource_id: resource, resource_revision: 1 };
const intent: SigningGrantIntent = { request_id: requestID, expected_org_id: org, expected_user_id: user, grant_id: resource, expected_revision: 0, policy: { id: resource, revision: 1, sha256: sha }, company_name: 'Example AB', company_id: '556000-0000', authority_basis: 'Declared authority', font: 'Caveat', not_before: '0001-01-01T00:00:00Z', expires_at: '2026-10-11T12:00:00Z', max_uses: 1 };
const outcome = { org_id: org, user_id: user, request_id: requestID, state: 'committed', operation: 'grant.create', command_sha256: sha, resource_kind: 'grant', reference: { id: resource, revision: 1, sha256: sha }, occurred_at: '2026-10-10T12:00:00Z' };
const context = { org_id: org, user_id: user, self: { id: user, name: 'Owner Name', email: 'owner@example.test', role: 'owner' }, execution_available: false, fonts: [{ font: 'Caveat', font_sha256: sha }], disclosure: { version: 1, sha256: sha, text: 'Future delegation disclosure.' } };
const json = (v: unknown, init?: ResponseInit) => new Response(JSON.stringify(v), { ...init, headers: { 'Content-Type': 'application/json' } });

test('registry transport uses same-origin bounded no-store session requests and exact actor/request confirmation payloads', async () => {
  const previous = globalThis.fetch, calls: { path: string; init: RequestInit }[] = [], signal = new AbortController().signal;
  try {
    globalThis.fetch = (async (path: string | URL | Request, init?: RequestInit) => { calls.push({ path: String(path), init: init! }); return json(outcome); }) as typeof fetch;
    await mutateSigningAuthority('grant.create', { intent, receipt: 'signed.receipt', confirmed: true }, signal);
    expect(calls[0].path).toBe('/api/v1/presign/self-grants/create');
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ intent, receipt: 'signed.receipt', confirmed: true });
    await getSigningRequest(marker, signal); expect(calls[1].path).toBe(`/api/v1/presign/requests/${requestID}`);
    globalThis.fetch = (async (path: string | URL | Request, init?: RequestInit) => { calls.push({ path: String(path), init: init! }); return json({ org_id: org, user_id: user, request_id: requestID, state: 'closed', operation: 'request.close', reference: { id: signingNilUUID, revision: 0, sha256: '' }, occurred_at: '2026-10-10T12:00:01Z' }); }) as typeof fetch;
    await closeSigningRequest(marker, signal); expect(calls[2].path).toBe(`/api/v1/presign/requests/${requestID}/close`);
    expect(JSON.parse(calls[2].init.body as string)).toEqual({ request_id: requestID, expected_org_id: org, expected_user_id: user, confirmed: true });
    for (const call of calls) { expect(call.init.credentials).toBe('include'); expect(call.init.cache).toBe('no-store'); expect(call.init.signal).toBe(signal); }
  } finally { globalThis.fetch = previous; }
});
test('400/404/409 and non-JSON/oversize/malformed payloads are rejected without exposing error bodies', async () => {
  const previous = globalThis.fetch, signal = new AbortController().signal;
  try {
    for (const status of [400, 401, 403, 404, 409, 503]) {
      globalThis.fetch = (async () => new Response('provider secret cookie and token', { status })) as typeof fetch;
      try { await getSigningRequest(marker, signal); throw new Error('Expected refusal.'); } catch (e) { expect((e as { status: number }).status).toBe(status); expect(String(e)).not.toContain('secret'); }
    }
    for (const response of [new Response('{}', { headers: { 'Content-Type': 'text/html' } }), new Response(JSON.stringify(context), { headers: { 'Content-Type': 'application/json', 'Content-Length': '65537' } }), json({ ...context, execution_available: true }), json({ ...context, private_key: 'forbidden' }), new Response('{', { headers: { 'Content-Type': 'application/json' } })]) {
      globalThis.fetch = (async () => response) as typeof fetch; expect(await getSigningContext(signal).then(() => false, () => true)).toBe(true);
    }
  } finally { globalThis.fetch = previous; }
});
test('preview and confirmation transport refuse arbitrary caller pins/unknown operation before network dispatch', async () => {
  const previous = globalThis.fetch, signal = new AbortController().signal; let writes = 0;
  try {
    globalThis.fetch = (async () => { writes++; return json(outcome); }) as typeof fetch;
    expect(await mutateSigningAuthority('grant.create', { intent, receipt: 'signed.receipt', confirmed: false }, signal).then(() => false, () => true)).toBe(true);
    expect(await previewSigningAuthority('grant', { ...intent, font_sha256: sha } as SigningGrantIntent, signal).then(() => false, () => true)).toBe(true);
    expect(await closeSigningRequest({ ...marker, request_id: '../escape' }, signal).then(() => false, () => true)).toBe(true);
    expect(writes).toBe(0);
  } finally { globalThis.fetch = previous; }
});
