import { expect, test } from 'bun:test';
import { AmendmentWorkflow, type AmendmentTransport } from './amendmentWorkflow';
import { amendmentAllows, amendmentCandidate, checkedAmendmentCreate, checkedAmendmentInventory, checkedAmendmentIssue, type AmendmentMode, type AmendmentOutcome } from './amendments';
import { accessID, actor, candidateID, clone, deferred, deliveryID, document, input, inventory, later, noticeID, orgID, originalID, record, requestID, time, userID } from './amendmentFixtures';
function fixture(mode: AmendmentMode = 'signature', candidatePage = false) {
 let saved = inventory(candidatePage ? [record(mode)] : []), candidate = document(candidateID, mode === 'signature'), writes = 0;
 const transport: AmendmentTransport = { identity: async () => clone(actor), link: async () => candidatePage ? { schema: 'hash-later-amendments-v1', original_document_id: originalID, amendment: clone(saved.amendments[0]) } : null, inventory: async () => clone(saved), choices: async offset => ({ documents: [clone(candidate)], offset, total: 1 }), document: async () => clone(candidate), revoke: async (_id, _row, id) => ({ schema: 'hash-later-amendments-v1', state: 'committed', access_id: id, revoked_at: later }), create: async (_id, payload) => { writes++; saved = inventory([{ ...record(mode), request_id: payload.request_id }]); return { state: 'committed', request_id: payload.request_id, amendment: clone(saved.amendments[0]) }; }, issue: async (_id, _row, payload) => { writes++; const notice = { id: noticeID, request_id: payload.request_id, subject: payload.subject, text: payload.text, sha256: 'f'.repeat(64), file_commitment_sha256: record(mode).file_commitment_sha256, issued_at: later, issued_by: userID, deliveries: payload.recipient_emails.map((recipient_email, i) => ({ access_id: i ? noticeID : accessID, email_delivery_id: i ? requestID : deliveryID, recipient_email, state: 'queued' as const, attempts: 0 })), verified_receipts: [] }; saved = inventory([{ ...saved.amendments[0], notice }]); return { state: 'committed', request_id: payload.request_id, notice }; } };
 const workflow = new AmendmentWorkflow(candidatePage ? candidate : document(originalID), actor, transport, () => {});
 return { workflow, transport, writes: () => writes, setCandidate: (value: typeof candidate) => { candidate = value; }, setSaved: (value: typeof saved) => { saved = value; } };
}
async function choose(f: ReturnType<typeof fixture>) { await f.workflow.refresh(); await f.workflow.loadChoices(); await f.workflow.choose(candidateID); }
test('amendment inventory requires the exact complete proposed chain, original artifact pins and no private fields', () => {
 const good = inventory([record()]); expect(checkedAmendmentInventory(good, originalID)).toEqual(good);
 for (const value of [{ ...good, head_id: null }, { ...good, head_revision: '01' }, { ...good, amendments: [{ ...record(), revision: '2' }] }, { ...good, amendments: [record(), record()] }, { ...good, private_key: 'hidden' }, { ...good, original: { ...good.original, final_pdf_sha256: 'invalid' } }]) expect(() => checkedAmendmentInventory(value, originalID)).toThrow();
});
test('all three optional processes require a compatible prepared draft and allowed agreement basis', async () => {
 for (const mode of ['signature', 'acknowledgement', 'agreed_notice'] as const) { const f = fixture(mode); await choose(f); expect(amendmentAllows(f.workflow.state.candidate!, mode)).toBe(true); await f.workflow.create(input(mode)); expect(f.writes()).toBe(1); expect(f.workflow.state.inventory?.amendments[0].mode).toBe(mode); expect(f.workflow.state.pending).toBeNull(); }
 expect(() => checkedAmendmentCreate({ ...input('agreed_notice'), basis: { ...input().basis, allowed_modes: ['signature'] } })).toThrow();
 expect(() => checkedAmendmentCreate({ ...input(), cover_reviewed: false })).toThrow();
 expect(() => checkedAmendmentCreate({ ...input(), basis: { kind: 'frozen_agreement_policy', frozen_policy_id: noticeID, reviewed_clause: 'caller supplied policy' } })).toThrow();
});
test('the direct candidate lookup independently blocks ordinary notice Send and permits fresh sign or ack review', async () => {
 for (const mode of ['signature', 'acknowledgement', 'agreed_notice'] as const) { const f = fixture(mode, true); expect(f.workflow.ordinarySendBlocked()).toBe(true); await f.workflow.refresh(); expect(f.workflow.state.link?.original_document_id).toBe(originalID); expect(f.workflow.ordinarySendBlocked()).toBe(mode === 'agreed_notice'); }
 const f = fixture(); f.transport.link = async () => { throw Error('unavailable'); }; await f.workflow.refresh(); expect(f.workflow.ordinarySendBlocked()).toBe(true);
});
test('a changed owner or document clock refuses before dispatch and does not retain an undispatched request', async () => {
 for (const changed of ['actor', 'clock'] as const) { const f = fixture(); await choose(f); if (changed === 'actor') f.transport.identity = async () => ({ ...actor, role: 'sender' }); else f.setCandidate({ ...document(), updated_at: later }); await f.workflow.create(input()); expect(f.writes()).toBe(0); expect(f.workflow.state.pending).toBeNull(); }
});
test('an uncertain request never double-submits, retries only the exact reviewed request, and reconciles immutable saved evidence', async () => {
 const f = fixture(); await choose(f); const sent: unknown[] = []; let calls = 0;
 f.transport.create = async (_id, payload) => { sent.push(clone(payload)); calls++; if (calls === 1) throw Error('lost response'); f.setSaved(inventory([record()])); return { state: 'unchanged', request_id: payload.request_id, amendment: record() }; };
 await f.workflow.create(input()); expect(f.workflow.state.pending).not.toBeNull(); await f.workflow.create({ ...input(), request_id: noticeID }); expect(calls).toBe(1); await f.workflow.retryReviewedRequest(); expect(sent).toEqual([input(), input()]); expect(f.workflow.state.pending).toBeNull();
});
test('late completion after interruption cannot adopt state and cannot create a second request', async () => {
 const f = fixture(); await choose(f); const gate = deferred<AmendmentOutcome>(); let entered = false; f.transport.create = async () => { entered = true; return gate.promise; }; const pending = f.workflow.create(input()); while (!entered) await Promise.resolve(); f.workflow.interrupt(); gate.resolve({ state: 'committed', request_id: requestID, amendment: record() }); await pending; expect(f.workflow.state.inventory?.amendments).toHaveLength(0); expect(f.workflow.state.pending).not.toBeNull(); expect(f.workflow.state.fresh).toBe(false);
});
test('notice review freezes exact content, recipients and current document; issue uses only that original review', async () => {
 const f = fixture('agreed_notice', true); await f.workflow.refresh(); await f.workflow.reviewNotice(record('agreed_notice'), 'Changes from 1 November', 'Please read the accompanying amendment.', ['person@example.test']); const reviewed = clone(f.workflow.state.noticeReview!); expect(reviewed.expected_document_updated_at).toBe(time); expect(f.writes()).toBe(0); await f.workflow.issueNotice(); expect(f.writes()).toBe(1); expect(f.workflow.state.inventory?.amendments[0].notice?.deliveries[0].state).toBe('queued'); expect(f.workflow.state.inventory?.amendments[0].notice?.request_id).toBe(reviewed.request_id); expect(f.workflow.state.pending).toBeNull();
 expect(() => checkedAmendmentIssue({ ...reviewed, recipient_emails: ['person@example.test', 'PERSON@example.test'] })).toThrow(); expect(() => checkedAmendmentIssue({ ...reviewed, subject: 'mail\nBcc: other@example.test' })).toThrow();
});
test('mismatched saved basis or notice audience never clears the reviewed pending request', async () => {
 const f = fixture(); await choose(f); f.transport.create = async () => { f.setSaved(inventory([{ ...record(), basis: { ...record().basis, reviewed_clause: 'Different clause' } }])); return { state: 'unknown', request_id: requestID }; }; await f.workflow.create(input()); expect(f.workflow.state.pending).not.toBeNull();
 const n = fixture('agreed_notice', true); await n.workflow.refresh(); await n.workflow.reviewNotice(record('agreed_notice'), 'Subject', 'Text', ['person@example.test']); n.transport.issue = async (_id, _row, payload) => ({ state: 'committed', request_id: payload.request_id, notice: { id: noticeID, request_id: payload.request_id, subject: payload.subject, text: payload.text, sha256: 'f'.repeat(64), file_commitment_sha256: record().file_commitment_sha256, issued_at: later, issued_by: userID, deliveries: [{ access_id: accessID, email_delivery_id: deliveryID, recipient_email: 'unreviewed@example.test', state: 'provider_accepted', attempts: 1 }], verified_receipts: [] } }); await n.workflow.issueNotice(); expect(n.workflow.state.pending).not.toBeNull();
});

test('owner revocation uses exact access ID and only fresh persisted status claims access is revoked', async () => {
 const f = fixture('agreed_notice', true); await f.workflow.refresh(); await f.workflow.reviewNotice(record('agreed_notice'), 'Subject', 'Text', ['person@example.test']); await f.workflow.issueNotice(); let calls = 0;
 f.transport.revoke = async (_original, rowID, id) => { calls++; expect(id).toBe(accessID); const row = clone(f.workflow.state.inventory!.amendments[0]); expect(rowID).toBe(row.id); row.notice!.deliveries[0].revoked_at = later; f.setSaved(inventory([row])); return { schema: 'hash-later-amendments-v1', state: 'unknown', access_id: id, reconciliation_required: true }; };
 await f.workflow.revokeAccess(f.workflow.state.inventory!.amendments[0], accessID); expect(calls).toBe(1); expect(f.workflow.state.inventory!.amendments[0].notice!.deliveries[0].revoked_at).toBe(later); expect(f.workflow.state.message).toContain('Previously downloaded');
 await f.workflow.revokeAccess(f.workflow.state.inventory!.amendments[0], accessID); expect(calls).toBe(1);
});

test('late post-write readback cannot replace interruption state or restore obsolete errors', async () => {
 const f = fixture(); await choose(f); const gate = deferred<ReturnType<typeof inventory>>(); let entered = false; f.transport.inventory = async () => { entered = true; return gate.promise; }; f.transport.create = async () => { throw Error('obsolete network error'); };
 const writing = f.workflow.create(input()); while (!entered) await Promise.resolve(); f.workflow.interrupt(); gate.resolve(inventory()); await writing; expect(f.workflow.state.fresh).toBe(false); expect(f.workflow.state.error).toContain('interrupted'); expect(f.workflow.state.error).not.toContain('obsolete');
});

test('prepared amendment names obey the native frozen file-title byte bound before a link can dispatch', () => {
 expect(amendmentCandidate({ ...document(), name: 'é'.repeat(256) }, orgID, originalID).name).toBe('é'.repeat(256)); expect(() => amendmentCandidate({ ...document(), name: 'é'.repeat(257) }, orgID, originalID)).toThrow();
});
