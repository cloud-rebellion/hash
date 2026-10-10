import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { pdfTemplateParties } from '../pdfTemplate';

function callback(source: string, name: string) {
  let start = source.indexOf(`function ${name}(`);
  if (source.slice(start - 6, start) === 'async ') start -= 6;
  const opening = source.indexOf('{', start);
  let position = opening, depth = 1;
  while (depth && ++position < source.length) {
    if (source[position] === '{') depth++;
    if (source[position] === '}') depth--;
  }
  if (start < 0 || opening < 0 || depth) throw new Error(`Missing production callback ${name}`);
  return source.slice(start, position + 1);
}
function bind(file: string, names: string[], env: any) {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8');
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(names.map((name) => callback(source, name)).join('\n'));
  return new Function('env', `with(env) { ${code}; return { ${names.join(',')} }; }`)(env);
}
const event = { preventDefault() {} };

test('PDF Save submits the observed layout only once and never reports a stale source as saved', async () => {
  const calls: any[] = [];
  let saved = 0;
  const env: any = { sourceID: 'A', sourceStamp: 'stamp-A', disposed: false, loading: false, saving: false, error: null,
    name: 'Reusable contract', fieldIDs: ['field-A'], parties: [{ recipient_id: 'old-recipient', role: 'provider', label: 'Provider', source_name: 'Prior person' }],
    document: { id: 'A', updated_at: 'stamp-A', status: 'draft' },
    current: () => !env.disposed && env.document.id === env.sourceID && env.document.updated_at === env.sourceStamp && env.document.status === 'draft',
    savePDFSigningTemplate: (...args: any[]) => new Promise((resolve) => calls.push({ args, resolve })), onSaved: () => saved++,
  };
  const actions = bind('./SavePDFTemplate.svelte', ['save'], env);
  const pending = actions.save(event);
  await actions.save(event);
  expect(calls).toHaveLength(1);
  expect(calls[0].args).toEqual(['A', { name: 'Reusable contract', expected_updated_at: 'stamp-A', expected_field_ids: ['field-A'],
    parties: [{ recipient_id: 'old-recipient', role: 'provider', label: 'Provider' }] }]);
  env.fieldIDs.push('new-field'); env.document.updated_at = 'stamp-new';
  calls[0].resolve({}); await pending;
  expect(saved).toBe(0);
  expect(calls[0].args[1].expected_field_ids).toEqual(['field-A']);
  await actions.save(event); expect(calls).toHaveLength(1);
});

test('template use collects identities and pins the selected revision; failed creation keeps the form', async () => {
  const calls: any[] = [], navigations: string[] = [];
  const template = { id: 'template', name: 'Master', source_kind: 'pdf', version: 7,
    fields_json: { version: 1, parties: [{ role: 'provider', label: 'Provider' }, { role: 'client', label: 'Client' }],
      fields: [{ party_role: 'provider', type: 'signature', required: true }, { party_role: 'client', type: 'signature', required: true }] } };
  const env: any = { creatingId: null, pendingCreation: false, error: null, selectedTemplate: null, selectedHTMLTemplate: null, htmlFormDirty: false, selectedParties: [], bindings: [], documentName: '', disposed: false,
    pdfTemplateParties, createDocumentFromTemplate: (...args: any[]) => new Promise((resolve, reject) => calls.push({ args, resolve, reject })),
    goto: (url: string) => { navigations.push(url); } };
  const actions = bind('../../routes/templates/+page.svelte', ['useTemplate', 'createBoundDocument'], env);
  await actions.useTemplate(template);
  expect(calls).toHaveLength(0);
  expect(env.bindings.map((party: any) => party.role)).toEqual(['provider', 'client']);
  env.bindings[0].name = ' Provider Person '; env.bindings[0].email = ' provider@example.test ';
  env.bindings[1].name = 'Client Person'; env.bindings[1].email = 'client@example.test';
  const failed = actions.createBoundDocument(event);
  await actions.createBoundDocument(event);
  expect(calls).toHaveLength(1);
  expect(calls[0].args[3]).toEqual({ expected_template_version: 7, parties: [
    { role: 'provider', name: 'Provider Person', email: 'provider@example.test', locale: 'en' },
    { role: 'client', name: 'Client Person', email: 'client@example.test', locale: 'en' }] });
  calls[0].reject(new Error('Template changed; review it again')); await failed;
  expect(env.selectedTemplate).toBe(template);
  expect(env.bindings[0].name).toBe(' Provider Person ');
  expect(env.error).toContain('Template changed');
  const next = actions.createBoundDocument(event); env.disposed = true;
  calls[1].resolve({ id: 'new-document' }); await next;
  expect(navigations).toEqual([]);
});
