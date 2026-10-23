import { expect, test } from 'bun:test';
import { checkedSupersessionContext, checkedSupersessionResult, readSupersessionMarker, saveSupersessionMarker, supersessionCommand } from './supersession';
import { ids, supersessionFixture } from './supersessionFixtures';
test('supersession context binds current actor, exact original pins and only current template declarations', () => {
  const { actor, ready } = supersessionFixture();
  expect(checkedSupersessionContext(ready, actor, ready.prior.document_id)).toEqual(ready);
  for (const alter of [
    (v: any) => { v.user_id = ids[8]; }, (v: any) => { v.prior.execution_sha256 = 'A'.repeat(64); },
    (v: any) => { v.prior.template.storage_key = 'private'; }, (v: any) => { v.template.defaults.undeclared = 'bypass'; },
    (v: any) => { v.template.id = ids[8]; }, (v: any) => { v.template.values.push(v.template.values[0]); },
    (v: any) => { v.template.values[0].max_chars = 8193; }, (v: any) => { v.template.sections[0].default_text = '\u0000'; },
  ]) { const next = structuredClone(ready); alter(next); expect(() => checkedSupersessionContext(next, actor, ready.prior.document_id)).toThrow(); }
  expect(() => checkedSupersessionContext(ready, { ...actor, org_id: ids[8] }, ready.prior.document_id)).toThrow();
});
test('fresh draft command keeps exact original approval text and binds selected source without copying artifacts or signatures', () => {
  const { ready, marker, result } = supersessionFixture();
  const command = supersessionCommand(ready, 'New linked draft', { customer_name: 'New Customer' }, { scope: 'New reviewed wording' }, marker.request_id);
  expect(command.prior.template.approved_at).toBe('2026-10-10T08:00:00.123456789Z');
  expect(command.source).toMatchObject({ expected_template_version: 2, expected_template_content_sha256: 'd'.repeat(64), expected_org_id: marker.org_id, expected_user_id: marker.user_id, request_id: marker.request_id, values: { customer_name: 'New Customer' } });
  expect(Object.keys(command)).toEqual(['prior', 'template_id', 'source']);
  const deniedFields: Record<string, string>[] = [{}, { customer_name: '' }, { customer_name: 'x'.repeat(81) }, { customer_name: 'ok', provider_signature: 'not source' }];
  for (const fields of deniedFields) expect(() => supersessionCommand(ready, 'New draft', fields, {}, marker.request_id)).toThrow();
  expect(() => supersessionCommand({ ...ready, creation_available: false }, 'New draft', ready.template.defaults, {}, marker.request_id)).toThrow();
  expect(checkedSupersessionResult(result, marker).document_id).toBe(result.document_id);
  for (const bad of [{ ...result, prior_execution_id: ids[8] }, { ...result, request_id: ids[8] }, { ...result, document_id: marker.prior_document_id }]) expect(() => checkedSupersessionResult(bad, marker)).toThrow();
});
test('original opaque request persists without source data and corrupt markers remain blocked', () => {
  const { marker } = supersessionFixture(); let saved: string | null = null;
  const storage = { getItem: () => saved, setItem: (_: string, raw: string) => { saved = raw; }, removeItem: () => { saved = null; } };
  saveSupersessionMarker(storage, marker); expect(readSupersessionMarker(storage)).toEqual({ marker, invalid: false });
  expect(saved).not.toContain('customer'); expect(saved).not.toContain('source_commitment');
  saved = '{}'; expect(readSupersessionMarker(storage).invalid).toBe(true);
  expect(readSupersessionMarker({ getItem: () => { throw new Error('unavailable'); } }).invalid).toBe(true);
  saveSupersessionMarker(storage, null); expect(readSupersessionMarker(storage)).toEqual({ marker: null, invalid: false });
});
