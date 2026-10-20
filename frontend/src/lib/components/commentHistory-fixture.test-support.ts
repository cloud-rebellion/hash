import { readFileSync } from 'node:fs';
import { createCommentHistory, latestComments, commentQuery } from '../commentHistory';
import { signerCeremonyKey } from '../signerPDF';
export const staffSource = readFileSync(new URL('../../routes/documents/[id]/+page.svelte', import.meta.url), 'utf8');
export const signerSource = readFileSync(new URL('../../routes/sign/[token]/+page.svelte', import.meta.url), 'utf8');
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function bind(source: string, env: any, names: string[]) {
  return new Function('env', `with(env) { ${transpiler.transformSync(source)}; return {${names.join(',')}}; }`)(env);
}
export function attachCommentHistory(source: string, env: any) {
  const start = source.indexOf('  const commentHistory = createCommentHistory');
  const end = source.indexOf('  let commentRefreshError', start);
  if (start < 0 || end < 0) throw new Error('Actual history constructor missing');
  return new Function('env', `with(env) { ${transpiler.transformSync(source.slice(start, end))}; return commentHistory; }`)(env);
}
export function message(id: string) { return { id, author_name: 'Author', author_side: 'sender', body: id, created_at: '2026-10-16T10:00:00.123456Z' }; }
export function messages(id: string) { return { comments: [message(id)], older_cursor: 'A'.repeat(76), newer_cursor: null }; }
export function chatFixture(signer = false) {
  const calls: any[] = [];
  const env: any = { createCommentHistory, latestComments, commentQuery, commentSendRevision: 0, commentRouteEpoch: 0, commentScopeKey: '',
    commentDocumentKey: '', viewerScopeKey: '', documentReady: false, showAdoptModal: false,
    ceremonyEpoch: 1, acknowledgedSourceKind: 'blocks', fieldsFilled: false, viewRecorder: { invalidate() {} },
    commentBody: 'first', postingComment: false, comments: [message('retained')], commentRefreshError: null,
    commentLoading: false, olderCommentCursor: null, newerCommentCursor: null, error: null, signError: null,
    routeRevision: 1, documentRevision: 1, disposed: false, routeDisposed: false, loadedToken: 'token',
    doc: { id: 'd', org_id: 'org' }, $page: { params: { id: 'd', token: 'token' } }, noticeAcknowledged: true,
    ctx: { document_id: 'doc', recipient: { id: 'recipient' }, privacy: { notice_digest: 'digest' }, source_kind: 'blocks' },
    signerCeremonyKey, signerNoticeHeaders: (digest: string, accepted: boolean) => ({ digest, accepted }),
    listComments: (id: string, selection: unknown, signal: AbortSignal) => new Promise((resolve, reject) => calls.push({ method: 'GET', id, selection, signal, resolve, reject })),
    postComment: (id: string, body: string) => new Promise((resolve, reject) => calls.push({ method: 'POST', id, body, resolve, reject })),
    fetch: (url: string, options: any) => new Promise((resolve, reject) => calls.push({ method: options.method ?? 'GET', url, options, resolve, reject })),
  };
  const source = signer ? signerSource : staffSource;
  const guardStart = source.indexOf(signer ? '  type CommentScope' : '  function isCurrentRoute(');
  const guardEnd = source.indexOf(signer ? '  async function loadComments(' : '  async function toggleSignatureMode()', guardStart);
  const start = source.indexOf('  async function loadComments('), end = source.indexOf(signer ? '  function onDocMouseUp()' : '  async function loadChangeRequests', start);
  const ceremony = signer ? source.slice(source.indexOf('  function currentCeremonyKey()'), source.indexOf('  function viewerReady()')) : '';
  const actions = bind(ceremony + source.slice(guardStart, guardEnd) + source.slice(start, end), env,
    ['loadComments', 'sendComment', ...(!signer ? ['receiveStatus'] : []), 'captureCommentScope', 'isCurrentCommentScope', ...(signer ? ['invalidateCommentScope', 'synchronizeCommentScope', 'currentCeremonyKey'] : [])]);
  Object.assign(env, actions);
  env.commentHistory = attachCommentHistory(source, env);
  if (signer) env.acknowledgedScopeKey = actions.currentCeremonyKey();
  function resolvePage(call: any, data: any) { call.resolve(signer ? { ok: true, json: async () => data } : data); }
  function reset() {
    if (signer) actions.invalidateCommentScope();
    else { env.routeRevision++; env.documentRevision++; env.commentSendRevision++; env.commentHistory.reset(); env.postingComment = false; }
  }
  async function seed(id = 'retained') {
    const pending = actions.loadComments(signer ? 'token' : 'd');
    resolvePage(calls[calls.length - 1], messages(id));
    await pending;
    calls.length = 0;
  }
  return { env, calls, actions, resolvePage, reset, seed, load: () => actions.loadComments(signer ? 'token' : 'd'), send: actions.sendComment as () => Promise<void> };
}
