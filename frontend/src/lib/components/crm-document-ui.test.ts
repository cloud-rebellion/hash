import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { CRM_KINDS } from '../crmDocument';
const source = readFileSync(new URL('./CRMDocumentPanel.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  function map('), end = source.indexOf('  beforeNavigate(', start);
if (start < 0 || end < 0) throw new Error('CRM panel callbacks missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with(env) { ${code}; return {map,search}; }`);
test('actual field-selection callback passes only declared source selection, never remote values or wording', () => {
  const calls: unknown[] = [], env = { CRM_KINDS, controller: { map: (...args: unknown[]) => calls.push(args) } };
  const ui = bind(env); ui.map('amount', 'crm.deal:value'); ui.map('amount', ''); ui.map('amount', 'other:arbitrary'); ui.map('amount', 'crm.deal:');
  expect(calls).toEqual([['amount', { kind: 'crm.deal', path: 'value' }], ['amount']]);
});
test('actual search submit guard prevents dispatch while actor/source/account state is unverified', async () => {
  const calls: unknown[] = [], env = { canSearch: false, searchKind: 'crm.deal', query: 'Contract', controller: { search: (...args: unknown[]) => calls.push(args) } };
  const ui = bind(env); let prevented = 0; await ui.search({ preventDefault: () => prevented++ }); expect(calls).toEqual([]);
  env.canSearch = true; await ui.search({ preventDefault: () => prevented++ }); expect(calls).toEqual([['crm.deal', 'Contract']]); expect(prevented).toBe(2);
});
