import { expect, test } from 'bun:test';
import { proxy, snapshot, untrack } from 'svelte/internal/client';
import { AmendmentWorkflow, type AmendmentTransport } from '../amendmentWorkflow';
import { amendmentInvalid, type AmendmentActor } from '../amendments';
import { actor, candidateID, document, originalID, orgID } from '../amendmentFixtures';
import type { DocumentResponse } from '../api/client';

// Exercise the actual component boundary, rather than restating the fixed
// expression in a test helper. These are the real runtime implementations that
// Svelte compiles $state and $state.snapshot to; there is no fake Proxy/clone.
const source = await Bun.file(new URL('./DocumentAmendmentsPanel.svelte', import.meta.url)).text();
const prefix = 'const workflow = new AmendmentWorkflow(';
const suffix = ', untrack(() => actor), amendmentTransport,';
const start = source.indexOf(prefix);
const end = source.indexOf(suffix, start + prefix.length);
if (start < 0 || end < 0 || source.indexOf(prefix, start + prefix.length) >= 0) {
  throw Error('The actual amendment workflow constructor boundary is missing or ambiguous.');
}
const expression = source.slice(start + prefix.length, end);
const capture = new Function('doc', 'untrack', '$state', '"use strict"; return (' + expression + ');') as
  (doc: DocumentResponse, untrackRuntime: typeof untrack, stateRuntime: { snapshot: typeof snapshot }) => DocumentResponse;
const captureActual = (doc: DocumentResponse) => capture(doc, untrack, { snapshot });

function transport(identity: () => AmendmentActor = () => ({ ...actor })) {
  const lookedUp: string[] = [];
  let writes = 0;
  const unexpectedRead = async (): Promise<never> => { throw Error('Unexpected amendment transport read.'); };
  const unexpectedWrite = async (): Promise<never> => { writes++; throw Error('Unexpected amendment transport write.'); };
  const value: AmendmentTransport = {
    identity: async () => identity(),
    link: async id => { lookedUp.push(id); return null; },
    inventory: unexpectedRead,
    choices: unexpectedRead,
    document: unexpectedRead,
    create: unexpectedWrite,
    issue: unexpectedWrite,
    revoke: unexpectedWrite,
  };
  return { value, lookedUp, writes: () => writes };
}

function workflow(doc: DocumentResponse, identity = actor, io = transport()) {
  return { owned: new AmendmentWorkflow(captureActual(doc), identity, io.value, () => {}), io };
}

test('actual amendment component snapshots a real Svelte proxy before the workflow clone', async () => {
  const plain = document(candidateID);
  const reactive = proxy(plain);
  expect(reactive).not.toBe(plain);
  let oldError: unknown;
  try { new AmendmentWorkflow(reactive, actor, transport().value, () => {}); }
  catch (error) { oldError = error; }
  // This negative control recreates the pre-fix browser failure using the
  // original class, the actual Svelte proxy and the platform clone operation.
  expect((oldError as Error | undefined)?.name).toBe('DataCloneError');

  const { owned, io } = workflow(reactive);
  await owned.refresh();
  expect(owned.state.fresh).toBe(true);
  expect(owned.state.error).toBeNull();
  expect(io.lookedUp).toEqual([candidateID]);
  expect(io.writes()).toBe(0);
});

test('actual snapshot and workflow capture isolate later reactive and captured-document edits', async () => {
  const reactive = proxy({ ...document(candidateID), variables_json: { customer: 'Reviewed company' }, metadata: { company: { name: 'Reviewed company' } } });
  const captured = captureActual(reactive);
  const io = transport();
  const owned = new AmendmentWorkflow(captured, actor, io.value, () => {});
  reactive.id = originalID;
  reactive.org_id = '99999999-9999-4999-8999-999999999999';
  reactive.variables_json.customer = 'Unreviewed company';
  reactive.metadata.company = { name: 'Unreviewed company' };
  expect(captured.id).toBe(candidateID);
  expect(captured.org_id).toBe(orgID);
  expect(captured.variables_json.customer).toBe('Reviewed company');
  expect(captured.metadata.company).toEqual({ name: 'Reviewed company' });
  // The workflow must also retain its own clone after the component snapshot.
  captured.id = originalID;
  captured.org_id = '99999999-9999-4999-8999-999999999999';
  await owned.refresh();
  expect(owned.state.fresh).toBe(true);
  expect(io.lookedUp).toEqual([candidateID]);
  expect(io.writes()).toBe(0);
});

test('the actual snapshot boundary preserves malformed actor, document and tenant refusal', () => {
  const foreign = '99999999-9999-4999-8999-999999999999';
  const cases = [
    { doc: document(candidateID), identity: { ...actor, user_id: 'invalid' } },
    { doc: document(candidateID), identity: { ...actor, org_id: 'invalid' } },
    { doc: document(candidateID), identity: { ...actor, role: '' } },
    { doc: { ...document(candidateID), id: 'invalid' }, identity: actor },
    { doc: { ...document(candidateID), org_id: foreign }, identity: actor },
    { doc: document(candidateID), identity: { ...actor, org_id: foreign } },
  ];
  for (const item of cases) {
    const io = transport();
    expect(() => workflow(proxy(item.doc), item.identity, io)).toThrow(amendmentInvalid);
    expect(io.lookedUp).toHaveLength(0);
    expect(io.writes()).toBe(0);
  }
});

test('an identity change after actual capture still refuses before link lookup or mutation', async () => {
  const io = transport(() => ({ ...actor, role: 'sender' }));
  const { owned } = workflow(proxy(document(candidateID)), actor, io);
  await owned.refresh();
  expect(owned.state.fresh).toBe(false);
  expect(owned.state.error).toContain('account or permissions changed');
  expect(io.lookedUp).toHaveLength(0);
  expect(io.writes()).toBe(0);
});
