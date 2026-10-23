import { expect, test } from 'bun:test';
import { closePreSignExecution, executePreSign, getPreSignEligibility, inspectPreSignExecution, previewPreSignExecution } from './presignExecution';
import { getDocument } from './client';
import type { PreSignIntent, PreSignMarker } from '../presignExecution';

const org = '11111111-1111-4111-8111-111111111111', user = '22222222-2222-4222-8222-222222222222', doc = '33333333-3333-4333-8333-333333333333', materialization = '44444444-4444-4444-8444-444444444444';
const requestID = '55555555-5555-4555-8555-555555555555', reference = '66666666-6666-4666-8666-666666666666', sha = 'a'.repeat(64), visible = 'b'.repeat(64);
const intent: PreSignIntent = { request_id: requestID, expected_org_id: org, expected_user_id: user, document_id: doc, document_updated_at: '2026-10-23T12:00:00.123456Z', materialization_id: materialization, materialization_revision: 1, source_commitment: sha, policy: { id: reference, revision: 1, sha256: sha }, grant: { id: reference, revision: 1, sha256: sha }, lawful_basis: 'contract' };
const marker: PreSignMarker = { version: 1, org_id: org, user_id: user, request_id: requestID, document_id: doc, materialization_id: materialization, materialization_revision: 1, source_commitment: sha };
const closed = { schema_version: 1, org_id: org, user_id: user, request_id: requestID, state: 'closed' };
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
test('pre-sign transport uses exact session routes, original request closure and no credential or storage overrides', async () => {
  const old = globalThis.fetch, calls: { path: string; init: RequestInit }[] = [], signal = new AbortController().signal;
  try {
    globalThis.fetch = (async (path: string | URL | Request, init?: RequestInit) => {
      calls.push({ path: String(path), init: init! });
      if (String(path).endsWith('/eligibility')) return json({ schema_version: 1, org_id: org, user_id: user, document_id: doc, eligible: false });
      if (String(path).endsWith('/preview')) return json({ schema_version: 1, org_id: org, user_id: user, intent, receipt: 'session.preview.receipt', expires_at: '2026-10-23T12:05:00Z', provider_name: 'Provider', provider_email: 'provider@example.test', customer_name: 'Customer', customer_email: 'customer@example.test', disclosure: 'Explicit provider pre-signing.', remaining_uses: 2 });
      return json(closed);
    }) as typeof fetch;
    await getPreSignEligibility(doc, signal); await previewPreSignExecution(intent, signal); await executePreSign({ intent, receipt: 'session.preview.receipt', confirmed: true }, signal);
    await inspectPreSignExecution(marker, signal); await closePreSignExecution(marker, signal);
    expect(calls.map(call => call.path)).toEqual([`/api/v1/presign/executions/documents/${doc}/eligibility`, '/api/v1/presign/executions/preview', '/api/v1/presign/executions', `/api/v1/presign/executions/requests/${requestID}`, `/api/v1/presign/executions/requests/${requestID}/close`]);
    expect(JSON.parse(calls[2].init.body as string)).toEqual({ intent, receipt: 'session.preview.receipt', confirmed: true });
    expect(JSON.parse(calls[4].init.body as string)).toEqual({ request_id: requestID, expected_org_id: org, expected_user_id: user, confirmed: true });
    for (const call of calls) { expect(call.init.credentials).toBe('include'); expect(call.init.cache).toBe('no-store'); expect(call.init.signal).toBe(signal); expect(call.init.headers).not.toHaveProperty('Authorization'); }
  } finally { globalThis.fetch = old; }
});
test('unknown requests, malformed wire data and private error bodies never become closed outcomes', async () => {
  const old = globalThis.fetch, signal = new AbortController().signal;
  try {
    for (const status of [400, 401, 403, 404, 409, 503]) {
      globalThis.fetch = (async () => new Response('private token or path', { status })) as typeof fetch;
      try { await inspectPreSignExecution(marker, signal); throw new Error('expected refusal'); } catch (error) { expect((error as { status: number }).status).toBe(status); expect(String(error)).not.toContain('private token'); }
    }
    for (const response of [new Response('{}', { headers: { 'Content-Type': 'text/html' } }), new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '16385' } }), json({ ...closed, result: null }), json({ ...closed, storage_key: 'private' }), new Response('{', { headers: { 'Content-Type': 'application/json' } })]) {
      globalThis.fetch = (async () => response) as typeof fetch; expect(await inspectPreSignExecution(marker, signal).then(() => false, () => true)).toBe(true);
    }
  } finally { globalThis.fetch = old; }
});
test('invalid confirmation and caller data are rejected before network dispatch', async () => {
  const old = globalThis.fetch, signal = new AbortController().signal; let calls = 0;
  try {
    globalThis.fetch = (async () => { calls++; return json(closed); }) as typeof fetch;
    for (const input of [{ intent, receipt: 'valid', confirmed: false }, { intent, receipt: 'with whitespace', confirmed: true }, { intent: { ...intent, object_key: 'private' }, receipt: 'valid', confirmed: true }]) expect(await executePreSign(input as Parameters<typeof executePreSign>[0], signal).then(() => false, () => true)).toBe(true);
    expect(await closePreSignExecution({ ...marker, request_id: '../other' }, signal).then(() => false, () => true)).toBe(true); expect(calls).toBe(0);
  } finally { globalThis.fetch = old; }
});
test('staff document keeps immutable base digest and admits only a distinct closed derivative projection', async () => {
  const old = globalThis.fetch;
  const view = { schema_version: 1, execution: { id: reference, sha256: sha }, publication: 'published', visible_pdf_sha256: visible, page_count: 2 };
  try {
    globalThis.fetch = (async () => json({ id: doc, pdf_sha256: sha, pre_sign: view })) as typeof fetch;
    const document = await getDocument(doc); expect(document.pdf_sha256).toBe(sha); expect(document.pre_sign?.visible_pdf_sha256).toBe(visible);
    for (const pre_sign of [null, { ...view, storage_key: 'private' }, { ...view, page_count: 501 }, { ...view, execution: { ...view.execution, id: '../other' } }]) {
      globalThis.fetch = (async () => json({ id: doc, pdf_sha256: sha, pre_sign })) as typeof fetch; expect(await getDocument(doc).then(() => false, () => true)).toBe(true);
    }
  } finally { globalThis.fetch = old; }
});
