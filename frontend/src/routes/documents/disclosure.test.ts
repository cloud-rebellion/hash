import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { compile, parse } from 'svelte/compiler';

const source = readFileSync(new URL('./+page.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const names = ['toggleComposer', 'createBlank', 'changeImportKind', 'importProposal'];
const actual = names.map(name => {
  const fn = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  return source.slice(fn.start, fn.end);
}).join('\n');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(actual);
const bind = new Function('env', `with(env) { ${code}; return { ${names.join(', ')} }; }`);
const busy = tree.instance.content.body.flatMap((node: any) => node.declarations ?? []).find((node: any) => node.id.name === 'busy').init.arguments[0];
const evaluateBusy = new Function('env', `with(env) { return (${source.slice(busy.start, busy.end)}); }`);
const event = { preventDefault() {} };

function fixture() {
  const focus: string[] = [], calls: any[][] = [];
  const env: any = {
    composer: null, newName: ' Draft ', importName: ' Imported ', importKind: 'pdf',
    pdfFile: { name: 'retained.pdf' }, htmlFile: { text: async () => '<p>retained</p>' }, landscape: true,
    error: null, creating: false, importing: false, tick: async () => {}, $ui: (text: string) => text,
    blankTrigger: { focus: () => focus.push('blank-trigger') }, importTrigger: { focus: () => focus.push('import-trigger') },
    blankNameInput: { focus: () => focus.push('blank-input') }, importNameInput: { focus: () => focus.push('import-input') },
    createBlocksDocument: async (...args: any[]) => { calls.push(['blank', ...args]); return { id: 'created' }; },
    importProposalPDF: async (...args: any[]) => { calls.push(['pdf', ...args]); return { document: { id: 'imported' } }; },
    importProposalHTML: async (...args: any[]) => { calls.push(['html', ...args]); return { document: { id: 'imported' } }; },
    goto: async (path: string) => { calls.push(['goto', path]); },
  };
  Object.defineProperty(env, 'busy', { get: () => evaluateBusy(env) });
  return { env, focus, calls, ...bind(env) };
}

test('actual disclosure handlers open, switch and close with focus while retaining entered names and selected files', async () => {
  const f = fixture(), pdf = f.env.pdfFile, html = f.env.htmlFile;
  expect(f.env.composer).toBeNull();
  await f.toggleComposer('blank'); expect(f.focus.at(-1)).toBe('blank-input');
  await f.toggleComposer('import'); expect(f.focus.at(-1)).toBe('import-input');
  await f.toggleComposer('import'); expect(f.env.composer).toBeNull(); expect(f.focus.at(-1)).toBe('import-trigger');
  await f.toggleComposer('blank'); await f.toggleComposer('blank'); expect(f.focus.at(-1)).toBe('blank-trigger');
  expect(f.env.newName).toBe(' Draft '); expect(f.env.importName).toBe(' Imported ');
  expect(f.env.pdfFile).toBe(pdf); expect(f.env.htmlFile).toBe(html); expect(f.calls).toEqual([]);
});

test('a pending blank creation blocks closing, switching and duplicate import without changing the actual API payload', async () => {
  const f = fixture(); let release!: (value: any) => void;
  f.env.createBlocksDocument = (name: string) => { f.calls.push(['blank', name]); return new Promise(resolve => { release = resolve; }); };
  await f.toggleComposer('blank'); const pending = f.createBlank(event);
  expect(f.env.creating).toBe(true);
  await f.toggleComposer('blank'); await f.toggleComposer('import'); f.changeImportKind('html'); await f.importProposal(event);
  expect(f.env.composer).toBe('blank'); expect(f.env.importKind).toBe('pdf'); expect(f.calls).toEqual([['blank', 'Draft']]);
  release({ id: 'created' }); await pending;
  expect(f.env.creating).toBe(false); expect(f.calls.at(-1)).toEqual(['goto', '/documents/created']);
});

test('a pending import keeps its disclosure and selection, then preserves the existing PDF and HTML business inputs', async () => {
  const f = fixture(), pdf = f.env.pdfFile; let release!: (value: any) => void;
  f.env.importProposalPDF = (name: string, file: unknown) => { f.calls.push(['pdf', name, file]); return new Promise(resolve => { release = resolve; }); };
  await f.toggleComposer('import'); const pending = f.importProposal(event);
  expect(f.env.importing).toBe(true);
  await f.toggleComposer('blank'); await f.toggleComposer('import'); f.changeImportKind('html'); await f.createBlank(event);
  expect(f.env.composer).toBe('import'); expect(f.env.pdfFile).toBe(pdf); expect(f.calls).toEqual([['pdf', 'Imported', pdf]]);
  release({ document: { id: 'pdf-import' } }); await pending;
  expect(f.env.importing).toBe(false); expect(f.calls.at(-1)).toEqual(['goto', '/documents/pdf-import']);
  f.changeImportKind('html'); expect(f.env.pdfFile).toBeNull();
  f.env.htmlFile = { text: async () => '<h1>Actual HTML</h1>' };
  await f.importProposal(event);
  expect(f.calls.slice(-2)).toEqual([['html', 'Imported', '<h1>Actual HTML</h1>', true], ['goto', '/documents/imported']]);
});

test('disclosures compile for client and server, stay mounted outside conditional blocks, and reference their actual form IDs', () => {
  const forms: any[] = [], controls: string[] = [];
  function walk(node: any, conditional = false) {
    if (!node || typeof node !== 'object') return;
    if (node.name === 'form') { expect(conditional).toBe(false); forms.push(node); }
    for (const attr of node.attributes ?? []) if (attr.name === 'aria-controls') controls.push(attr.value[0].data);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) for (const child of value) walk(child, conditional || node.type === 'IfBlock' || node.type === 'KeyBlock');
      else if (value && typeof value === 'object') walk(value, conditional || node.type === 'IfBlock' || node.type === 'KeyBlock');
    }
  }
  walk(tree.fragment);
  expect(forms.map(form => form.attributes.find((a: any) => a.name === 'id').value[0].data).sort()).toEqual(controls.sort());
  for (const form of forms) expect(form.attributes.some((a: any) => a.name === 'hidden')).toBe(true);
  for (const generate of ['client', 'server'] as const) {
    expect(compile(source, { filename: 'Documents.svelte', generate }).warnings.filter(w => w.code.startsWith('a11y'))).toEqual([]);
  }
});
