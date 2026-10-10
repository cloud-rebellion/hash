import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { storeCreationMarker } from '../crmTemplatePopulation';
import { TP_ACTOR, TP_ID, TP_REQUEST } from '../crmTemplatePopulation.test';

function callback(name: string, env: any) {
  const source = readFileSync(new URL('../../routes/templates/+page.svelte', import.meta.url), 'utf8'); let start = source.indexOf(`function ${name}(`);
  if (source.slice(start - 6, start) === 'async ') start -= 6;
  const opening = source.indexOf('{', start); let depth = 1, end = opening; while (depth && ++end < source.length) { if (source[end] === '{') depth++; if (source[end] === '}') depth--; }
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end + 1)); return new Function('env', `with(env) { ${code}; return ${name}; }`)(env);
}
test('the library refuses competing HTML, PDF and block creation whenever a pending request exists despite unchanged default inputs', async () => {
  const calls: string[] = [], env: any = { pendingCreation: true, creatingId: null, selectedHTMLTemplate: null, selectedTemplate: { id: TP_ID }, htmlFormDirty: false,
    window: { confirm: () => { calls.push('confirm'); return true; } }, createStarterTemplate: () => calls.push('seed'), createBlocksTemplate: () => calls.push('blank'), createDocumentFromTemplate: () => calls.push('create'),
    fileInput: { files: [{}] }, nameInput: 'New design', uploadPDFTemplate: () => calls.push('upload') };
  for (const kind of ['html', 'pdf', 'blocks']) await callback('useTemplate', env)({ id: TP_ID, source_kind: kind });
  await callback('createBoundDocument', env)({ preventDefault() {} }); await callback('seedStarter', env)(); await callback('newBlankTemplate', env)(); await callback('onUpload', env)({ preventDefault() {} });
  expect(calls).toEqual([]); expect(env.selectedTemplate.id).toBe(TP_ID);
});
test('the actual library pending callback stores identifiers only and does not clear the guard until explicit recovery resolves it', () => {
  const data = new Map<string, string>(), env: any = { pendingMarker: null, storeCreationMarker,
    window: { sessionStorage: { setItem: (k: string, v: string) => data.set(k, v), removeItem: (k: string) => data.delete(k) } } };
  const persist = callback('persistPending', env), marker = { version: 1, org_id: TP_ACTOR.org_id, user_id: TP_ACTOR.user_id, template_id: TP_ID, request_id: TP_REQUEST };
  persist(marker); expect(env.pendingMarker).toEqual(marker); expect(JSON.parse([...data.values()][0])).toEqual(marker); persist(null); expect(env.pendingMarker).toBeNull(); expect(data.size).toBe(0);
});
