import { expect, test } from 'bun:test';
import { preSignDocumentMatchesResult, type PreSignResult } from '../presignExecution';

const source = await Bun.file(new URL('../../routes/documents/[id]/+page.svelte', import.meta.url)).text();
const names = ['isCurrentRoute', 'captureDocument', 'isCurrentDocument', 'receiveDocument', 'receivePreSignCommit'];
function callback(name: string) {
  let start = source.indexOf(`function ${name}(`); if (source.slice(start - 6, start) === 'async ') start -= 6;
  const opening = source.indexOf('{', start); let end = opening, depth = 1;
  while (depth && ++end < source.length) { if (source[end] === '{') depth++; if (source[end] === '}') depth--; }
  if (start < 0 || opening < 0 || depth) throw new Error(`Actual document callback missing: ${name}`);
  return source.slice(start, end + 1);
}
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(names.map(callback).join('\n'));
const documentID = '11111111-1111-4111-8111-111111111111', org = '22222222-2222-4222-8222-222222222222', executionID = '33333333-3333-4333-8333-333333333333', materialization = '44444444-4444-4444-8444-444444444444';
const baseSHA = 'a'.repeat(64), visibleSHA = 'b'.repeat(64), commitment = 'c'.repeat(64);
const result: PreSignResult = { command_sha256: commitment, execution: { id: executionID, sha256: commitment }, document_id: documentID, materialization_id: materialization, materialization_revision: 2, source_commitment: commitment, visible_pdf_sha256: visibleSHA, page_count: 2, use_number: 1, publication: 'published' };
function fixture() {
  let respond!: (value: unknown) => void;
  const env: any = { doc: { id: documentID, org_id: org, status: 'draft', pdf_sha256: baseSHA, html_source_commitment: commitment, html_materialization_revision: 2 }, routeRevision: 1, documentRevision: 1, disposed: false, $page: { params: { id: documentID } }, preSignPresentationBlocked: false, error: null,
    preSignDocumentMatchesResult, resetPDFPlacement() {}, getDocument: () => new Promise(resolve => { respond = resolve; }) };
  const action = new Function('env', `with(env){${code};return receivePreSignCommit;}`)(env);
  const updated = () => ({ ...env.doc, status: 'sent', pre_sign: { schema_version: 1, execution: result.execution, publication: 'published', visible_pdf_sha256: visibleSHA, page_count: 2 } });
  return { env, action: (value = result) => action(value), respond: (value: unknown) => respond(value), updated };
}
test('actual staff adoption refetches exact committed derivative while preserving immutable source pins', async () => {
  const f = fixture(); const pending = f.action(); expect(f.env.preSignPresentationBlocked).toBe(true); f.respond(f.updated()); expect(await pending).toBe(true);
  expect(f.env.doc.pdf_sha256).toBe(baseSHA); expect(f.env.doc.pre_sign.visible_pdf_sha256).toBe(visibleSHA); expect(f.env.doc.html_source_commitment).toBe(commitment); expect(f.env.preSignPresentationBlocked).toBe(false);
});
test('actual staff adoption rejects different execution, derivative, page count, base/source pin or regressed publication', async () => {
  for (const change of [(d: any) => { d.pre_sign.execution = { ...d.pre_sign.execution, id: materialization }; }, (d: any) => { d.pre_sign.visible_pdf_sha256 = baseSHA; }, (d: any) => { d.pre_sign.page_count = 3; }, (d: any) => { d.pdf_sha256 = visibleSHA; }, (d: any) => { d.html_source_commitment = baseSHA; }, (d: any) => { d.html_materialization_revision = 3; }, (d: any) => { d.pre_sign.publication = 'sealing'; }, (d: any) => { delete d.pre_sign; }]) {
    const f = fixture(), response = f.updated(); change(response); const pending = f.action(); f.respond(response); expect(await pending).toBe(false);
    expect(f.env.doc.status).toBe('draft'); expect(f.env.doc.pre_sign).toBeUndefined(); expect(f.env.preSignPresentationBlocked).toBe(true);
  }
});
test('actual staff adoption ignores response after route/source changes and permits real lifecycle advancement', async () => {
  const f = fixture(); const response = f.updated(), pending = f.action(); f.env.documentRevision++; f.respond(response); expect(await pending).toBe(false); expect(f.env.doc.pre_sign).toBeUndefined();
  const g = fixture(), next = g.updated(), commit = { ...result, publication: 'sealing' as const }; const publication = g.action(commit); g.respond(next); expect(await publication).toBe(true);
});
