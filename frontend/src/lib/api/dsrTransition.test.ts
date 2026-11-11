import { afterEach, expect, test } from 'bun:test';
import { DSRTransitionError, requestDSRTransition } from './dsrTransition';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });
const preview = { subject_email: 'subject@example.test', document_status: 'completed', pdf_revision_documents: 2, pdf_revisions: 7 };
const envelope = (receipt = 'opaque.receipt.first') => ({ code: 'confirmation_required', error: 'A different translated message', confirmation_receipt: receipt, will_erase: preview });

test('stable code returns exact subject and counts without relying on message wording', async () => {
  const calls: Array<{ path: string; body: Record<string, unknown>; init: RequestInit }> = [];
  globalThis.fetch = (async (path, init) => { calls.push({ path: String(path), body: JSON.parse(String(init?.body)), init: init! }); return Response.json(envelope(), { status: 409 }); }) as typeof fetch;
  const result = await requestDSRTransition('request/../x', 'fulfilled', 'reviewed');
  expect(calls).toHaveLength(1); expect(calls[0].path).toBe('/api/v1/dsr/request%2F..%2Fx');
  expect(calls[0].body).toEqual({ status: 'fulfilled', resolution_note: 'reviewed' });
  expect(calls[0].init.credentials).toBe('include'); expect(calls[0].init.cache).toBe('no-store');
  expect(result).toEqual({ state: 'confirmation', confirmation: { receipt: 'opaque.receipt.first', preview, stale: false } });
});

test('explicit confirmation submits exactly its observed opaque receipt, and a fresh receipt is never auto-submitted', async () => {
  const bodies: unknown[] = [];
  globalThis.fetch = (async (_path, init) => { bodies.push(JSON.parse(String(init?.body))); return Response.json(envelope('opaque.receipt.new'), { status: 409 }); }) as typeof fetch;
  const result = await requestDSRTransition('request', 'fulfilled', '', 'opaque.receipt.old');
  expect(bodies).toEqual([{ status: 'fulfilled', resolution_note: '', confirm: true, confirmation_receipt: 'opaque.receipt.old' }]);
  expect(result).toEqual({ state: 'confirmation', confirmation: { receipt: 'opaque.receipt.new', preview, stale: true } });
});

test('invalid receipts and malformed erasure previews fail closed without surfacing tokens', async () => {
  for (const mutation of [
    { confirmation_receipt: '' }, { confirmation_receipt: 'bad receipt' }, { confirmation_receipt: 'x'.repeat(8193) },
    { will_erase: { ...preview, pdf_revisions: -1 } }, { will_erase: { ...preview, pdf_revision_documents: 1.5 } },
    { will_erase: { ...preview, pdf_revision_documents: 8, pdf_revisions: 7 } },
    { will_erase: { ...preview, pdf_revisions: '7' } }, { will_erase: { ...preview, subject_email: 'x\ny' } },
    { will_erase: { ...preview, document_status: '<script>' } },
  ]) {
    globalThis.fetch = (async () => Response.json({ ...envelope(), ...mutation }, { status: 409 })) as typeof fetch;
    const failure = await requestDSRTransition('request', 'fulfilled').catch(error => error);
    expect(failure).toBeInstanceOf(DSRTransitionError); expect(failure.outcome).toBe('refused');
    expect(failure.message).not.toContain('opaque.receipt'); expect(JSON.stringify(failure)).not.toContain('opaque.receipt');
  }
  let writes = 0; globalThis.fetch = (async () => { writes++; return Response.json({}); }) as typeof fetch;
  await expect(requestDSRTransition('request', 'denied', '', 'receipt')).rejects.toBeInstanceOf(DSRTransitionError);
  await expect(requestDSRTransition('request', 'fulfilled', '', 'bad receipt')).rejects.toBeInstanceOf(DSRTransitionError);
  expect(writes).toBe(0);
});

test('message text alone never authorizes erasure, even when it asks for confirm true', async () => {
  globalThis.fetch = (async () => Response.json({ ...envelope(), code: 'different_conflict', error: 'retry with "confirm": true' }, { status: 409 })) as typeof fetch;
  const result = await requestDSRTransition('request', 'fulfilled').catch(error => error);
  expect(result).toBeInstanceOf(DSRTransitionError); expect(result.outcome).toBe('refused');
});

test('network loss, server faults and invalid successful identity fence repeated writes as outcome unknown', async () => {
  for (const response of [null, Response.json({ error: 'private db text' }, { status: 500 }), Response.json({ code: 'dsr_commit_outcome_unknown' }, { status: 500 }), Response.json({ id: 'other', status: 'fulfilled' })]) {
    globalThis.fetch = (async () => { if (!response) throw new Error('connection lost'); return response; }) as typeof fetch;
    const error = await requestDSRTransition('request', 'fulfilled').catch(error => error);
    expect(error).toBeInstanceOf(DSRTransitionError); expect(error.outcome).toBe('unknown'); expect(error.message).not.toContain('private db text');
  }
});

test('a matching acknowledged transition is committed and the caller abort signal is forwarded', async () => {
  const controller = new AbortController();
  globalThis.fetch = (async (_path, init) => { expect(init?.signal).toBe(controller.signal); return Response.json({ id: 'request', status: 'in_progress' }); }) as typeof fetch;
  expect(await requestDSRTransition('request', 'in_progress', '', undefined, controller.signal)).toEqual({ state: 'committed', request: { id: 'request', status: 'in_progress' } });
});
