import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { CRM_KINDS } from '../crmTemplatePopulation';
import { populationControllerFixture } from '../crmTemplatePopulation.test';

function bindMap(controller: ReturnType<typeof populationControllerFixture>['controller']) {
  const source = readFileSync(new URL('./CRMTemplatePopulationPanel.svelte', import.meta.url), 'utf8');
  const start = source.indexOf('function map('), opening = source.indexOf('{', start); let end = opening, depth = 1;
  while (depth && ++end < source.length) { if (source[end] === '{') depth++; if (source[end] === '}') depth--; }
  if (start < 0 || depth) throw new Error('Missing production mapping callback');
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end + 1));
  return new Function('controller', 'CRM_KINDS', `${code}; return map;`)(controller, CRM_KINDS);
}
test('actual initial mapping callback maps catalogued scalar selection without replacing manual entries and clears confirmation on removal', async () => {
  const f = populationControllerFixture(); await f.controller.load(); await f.controller.search('crm.deal', ''); f.controller.select(f.controller.state.search!.choices[0]);
  const raw = structuredClone(f.candidate()), map = bindMap(f.controller);
  map('price', 'crm.deal:value'); expect(f.controller.state.mappings).toEqual([{ variable: 'price', source_kind: 'crm.deal', source_ref: 'deal_CUID2', source_path: 'value' }]); expect(f.candidate()).toEqual(raw);
  await f.controller.observe(); f.controller.confirm('d'.repeat(64), true); expect(f.controller.canCreate()).toBe(true);
  map('price', ''); expect(f.controller.state.mappings).toEqual([]); expect(f.controller.state.confirmation).toBe(''); expect(f.candidate()).toEqual(raw); expect(f.calls.filter(c => c.kind === 'create')).toEqual([]);
});
test('actual initial mapping callback refuses undeclared destinations, wrong types and uncatalogued field paths', async () => {
  const f = populationControllerFixture(); await f.controller.load(); await f.controller.search('crm.deal', ''); f.controller.select(f.controller.state.search!.choices[0]); const map = bindMap(f.controller);
  map('undeclared', 'crm.deal:value'); map('price', 'crm.file:value'); map('price', 'crm.deal:secret'); expect(f.controller.state.mappings).toEqual([]); expect(f.controller.state.observation).toBeNull();
});
test('a metadata-storage refusal before dispatch retains all entered values and never hides a create request in another storage', async () => {
  const f = populationControllerFixture(); const { CRMTemplatePopulationController } = await import('../crmTemplatePopulation');
  const candidate = { ...f.candidate(), values: { ...f.candidate().values, price: '1290.2500' } };
  const c = new CRMTemplatePopulationController(f.template, f.transport, () => candidate, () => {}, () => { throw new Error('Request metadata storage is unavailable.'); }, () => {});
  await c.load(); await c.create(); expect(f.calls.filter(c => c.kind === 'create')).toEqual([]); expect(c.state.pending).toBeNull(); expect(c.state.error).toContain('storage'); expect(candidate.values.sticky).toBe('Typed manual information');
});
