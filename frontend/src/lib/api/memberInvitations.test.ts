import { expect, test } from 'bun:test';
import { APIError, inviteMember, type MemberInvitationInput } from './client';

async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, respond: () => Response | Promise<Response>) {
  const saved = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options: RequestInit = {}) => { calls.push({ path: String(path), options }); return respond(); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = saved; }
}

test('member invitation accepts only the generic202 acknowledgement and sends no owner-selected password or organization', async () => {
  const signal = new AbortController().signal;
  await mocked(async calls => {
    const input = { email: ' invitee@example.test ', name: ' Invitee ', role: 'sender', org_id: 'PRIVATE_ORG', password: 'PRIVATE_PASSWORD' } as MemberInvitationInput;
    expect(await inviteMember(input, signal)).toBeUndefined();
    expect(calls).toHaveLength(1); expect(calls[0].path).toBe('/api/v1/members');
    expect(calls[0].options).toMatchObject({ method: 'POST', credentials: 'include', cache: 'no-store', redirect: 'error', mode: 'cors', signal });
    expect(JSON.parse(calls[0].options.body as string)).toEqual({ email: 'invitee@example.test', name: 'Invitee', role: 'sender' });
    expect(String(calls[0].options.body)).not.toContain('PRIVATE');
  }, () => new Response('PRIVATE response is intentionally not read', { status: 202 }));
});

test('invitation refusals and unconfirmed responses stay generic and preserve status without leaking response data', async () => {
  for (const status of [200, 201, 400, 401, 403, 429, 503]) {
    await mocked(async () => {
      let refused = false;
      try { await inviteMember({ email: 'invitee@example.test', name: 'Invitee', role: 'viewer' }, new AbortController().signal); }
      catch (error) { refused = true; expect(error).toBeInstanceOf(APIError); expect((error as APIError).status).toBe(status); expect((error as Error).message).not.toContain('PRIVATE'); }
      expect(refused).toBe(true);
    }, () => new Response('PRIVATE existing-account organization details', { status }));
  }
  await mocked(async calls => {
    await expect(inviteMember({ email: 'i@example.test', name: 'I', role: 'administrator' as any }, new AbortController().signal)).rejects.toThrow();
    const stopped = new AbortController(); stopped.abort();
    await expect(inviteMember({ email: 'i@example.test', name: 'I', role: 'owner' }, stopped.signal)).rejects.toThrow();
    expect(calls).toHaveLength(0);
  }, () => Response.json({}, { status: 202 }));
});
