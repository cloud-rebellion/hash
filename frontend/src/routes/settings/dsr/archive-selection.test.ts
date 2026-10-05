import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('./+page.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  async function refresh()');
const end = source.indexOf('  async function transition(', start);
if (start < 0 || end < 0) throw new Error('DSR archive handlers missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with(env){${code};return {refresh,checkArchiveAccess,reviewDocumentArchives};}`);
function fixture() {
  const calls: Array<{ kind: string; input?: string; resolve: (value: any) => void; reject: (error: Error) => void }> = [];
  const env: any = {
    disposed: false, refreshVersion: 0, statusFilter: 'open', loading: false, error: null,
    requests: [{ id: 'request', org_id: 'org', document_id: 'doc' }],
    archiveOwnerOrgID: null, archiveAccessChecked: false, selectedArchiveRequest: null,
    onMount: () => {}, onDestroy: () => {},
    listDSR: (input: string) => new Promise((resolve, reject) => calls.push({ kind: 'list', input, resolve, reject })),
    getMe: () => new Promise((resolve, reject) => calls.push({ kind: 'me', resolve, reject }))
  };
  return { env, calls, handlers: bind(env) };
}

test('selected archive document comes from the current same-tenant request and verified owner', async () => {
  const { env, calls, handlers } = fixture();
  handlers.reviewDocumentArchives('request'); expect(env.selectedArchiveRequest).toBeNull();
  const checking = handlers.checkArchiveAccess(); calls[0].resolve({ role: 'owner', org_id: 'org' }); await checking;
  handlers.reviewDocumentArchives('request');
  expect(env.selectedArchiveRequest).toEqual({ id: 'request', org_id: 'org', document_id: 'doc' });
  env.selectedArchiveRequest = null; env.requests[0].org_id = 'other';
  handlers.reviewDocumentArchives('request'); expect(env.selectedArchiveRequest).toBeNull();
  env.requests[0] = { id: 'request', org_id: 'org', document_id: null };
  handlers.reviewDocumentArchives('request'); handlers.reviewDocumentArchives('missing');
  expect(env.selectedArchiveRequest).toBeNull();
});

test('nonowner and late owner lookup cannot enable the selected archive panel', async () => {
  const first = fixture(); const checking = first.handlers.checkArchiveAccess();
  first.calls[0].resolve({ role: 'sender', org_id: 'org' }); await checking;
  first.handlers.reviewDocumentArchives('request'); expect(first.env.selectedArchiveRequest).toBeNull();
  expect(first.env.archiveAccessChecked).toBe(true);
  const second = fixture(); const late = second.handlers.checkArchiveAccess();
  second.env.disposed = true; second.calls[0].resolve({ role: 'owner', org_id: 'org' }); await late;
  expect(second.env.archiveOwnerOrgID).toBeNull(); expect(second.env.archiveAccessChecked).toBe(false);
});

test('out-of-order request filters cannot restore an older archive selection', async () => {
  const { env, calls, handlers } = fixture(); env.archiveOwnerOrgID = 'org';
  handlers.reviewDocumentArchives('request'); const first = handlers.refresh();
  env.statusFilter = 'fulfilled'; const second = handlers.refresh();
  calls[1].resolve({ requests: [{ id: 'current', org_id: 'org', document_id: 'new-doc' }] }); await second;
  expect(env.selectedArchiveRequest).toBeNull();
  calls[0].resolve({ requests: [{ id: 'request', org_id: 'org', document_id: 'doc' }] }); await first;
  expect(env.requests[0].id).toBe('current'); expect(env.selectedArchiveRequest).toBeNull();
});

test('request document changes clear the old panel and disposed refresh cannot replace rows', async () => {
  const { env, calls, handlers } = fixture(); env.archiveOwnerOrgID = 'org'; handlers.reviewDocumentArchives('request');
  const refreshing = handlers.refresh();
  calls[0].resolve({ requests: [{ id: 'request', org_id: 'org', document_id: 'new-doc' }] }); await refreshing;
  expect(env.selectedArchiveRequest).toBeNull();
  const late = handlers.refresh(); env.disposed = true; calls[1].resolve({ requests: [] }); await late;
  expect(env.requests[0].document_id).toBe('new-doc');
});
