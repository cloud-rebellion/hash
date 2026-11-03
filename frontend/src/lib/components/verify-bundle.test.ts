import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile, parse } from 'svelte/compiler';
import { translateStaffText } from '../staffPreferences';

const filename = fileURLToPath(new URL('../../routes/verify/+page.svelte', import.meta.url));
const source = readFileSync(filename, 'utf8'), ast: any = parse(source, { modern: true });
const functions = ast.instance.content.body.filter((node: any) => node.type === 'FunctionDeclaration' && ['verifyBundle', 'onPick', 'onDrop'].includes(node.id.name));
if (functions.length !== 3) throw Error('Actual Verify file handlers missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions.map((node: any) => source.slice(node.start, node.end)).join('\n'));
const bind = new Function('env', `with(env){${code};return{verifyBundle,onPick,onDrop};}`);
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
const report = { ok: true, signature_valid: true, manifest_signature_valid: true, key_trusted: true, checks: [] };

function fixture() {
  const calls: Array<{ url: string; init: RequestInit; resolve: (response: Response) => void; reject: (error: Error) => void }> = [];
  const env: any = { bundleLoading: false, bundleReport: null, bundleError: null, dragging: true,
    fetch: (url: string, init: RequestInit) => new Promise<Response>((resolve, reject) => calls.push({ url, init, resolve, reject })),
  };
  const actions = bind(env);
  return { env, calls, actions,
    select(method: 'picker' | 'drop', file?: File) {
      if (method === 'picker') actions.onPick({ target: { files: file ? [file] : [] } });
      else {
        let prevented = false;
        actions.onDrop({ preventDefault() { prevented = true; }, dataTransfer: { files: file ? [file] : [] } });
        expect(prevented).toBe(true); expect(env.dragging).toBe(false);
      }
    },
  };
}

for (const method of ['picker', 'drop'] as const) {
  test(`actual ${method} sends PDF and ZIP evidence unchanged to the existing server verifier`, async () => {
    for (const [name, type] of [['hash-evidence.pdf', 'application/pdf'], ['hash-evidence.PDF', ''], ['hash-evidence.zip', 'application/zip'], ['hash-evidence.ZIP', 'application/octet-stream']]) {
      const f = fixture(), bytes = new Uint8Array([0x50, 0x4b, 3, 4, 0, 0xff]);
      f.select(method, new File([bytes], name, { type }));
      expect(f.calls).toHaveLength(1); expect(f.env.bundleLoading).toBe(true); expect(f.env.bundleReport).toBeNull();
      const call = f.calls[0]; expect(call.url).toBe('/api/verify-bundle'); expect(call.init.method).toBe('POST');
      const form = call.init.body as FormData; expect([...form.keys()]).toEqual(['bundle']);
      const uploaded = form.get('bundle') as File;
      expect(uploaded.name).toBe(name); expect(uploaded.type).toBe(type); expect(new Uint8Array(await uploaded.arrayBuffer())).toEqual(bytes);
      // File extension eligibility never produces a verdict: only the response does.
      expect(f.env.bundleReport).toBeNull();
      call.resolve(Response.json(report)); await flush();
      expect(f.env.bundleReport).toEqual(report); expect(f.env.bundleLoading).toBe(false); expect(f.env.bundleError).toBeNull();
    }
  });
  test(`actual ${method} rejects other extensions and clears an earlier positive result before any upload`, () => {
    for (const name of ['contract.html', 'contract.exe', 'contract.png', 'contract.pdf.exe', 'contract.zipx', 'contract', '']) {
      const f = fixture(); f.env.bundleReport = report;
      f.select(method, new File(['synthetic'], name, { type: 'application/pdf' }));
      expect(f.calls).toEqual([]); expect(f.env.bundleLoading).toBe(false); expect(f.env.bundleReport).toBeNull();
      expect(f.env.bundleError).toBe('Choose a Hash evidence package (.pdf or .zip).');
    }
  });
  test(`cancelling the actual ${method} leaves the current result and sends nothing`, () => {
    const f = fixture(); f.env.bundleReport = report; f.select(method);
    expect(f.calls).toEqual([]); expect(f.env.bundleReport).toBe(report); expect(f.env.bundleError).toBeNull();
  });
}

test('a pending verification owns both entry points and cannot dispatch or replace itself on a second selection', async () => {
  const f = fixture(); f.select('picker', new File(['pdf'], 'original.pdf'));
  f.select('drop', new File(['zip'], 'replacement.zip')); f.select('picker', new File(['other'], 'other.exe'));
  expect(f.calls).toHaveLength(1); expect((f.calls[0].init.body as FormData).get('bundle')).toHaveProperty('name', 'original.pdf');
  expect(f.env.bundleError).toBeNull(); expect(f.env.bundleLoading).toBe(true);
  f.calls[0].resolve(Response.json(report)); await flush(); expect(f.env.bundleReport).toEqual(report);
});

test('native HTTP refusals, negative verification, malformed responses and network errors never create a positive result', async () => {
  for (const failure of ['http', 'negative', 'malformed', 'network'] as const) {
    const f = fixture(); f.env.bundleReport = report; f.select('drop', new File(['not a valid archive'], 'evidence.zip'));
    expect(f.env.bundleReport).toBeNull();
    if (failure === 'network') f.calls[0].reject(new Error('network unavailable'));
    else if (failure === 'http') f.calls[0].resolve(new Response('scanner unavailable', { status: 503 }));
    else if (failure === 'malformed') f.calls[0].resolve(new Response('{', { status: 200 }));
    else f.calls[0].resolve(Response.json({ ...report, ok: false, key_trusted: false, errors: ['Untrusted issuer'] }));
    await flush(); expect(f.env.bundleLoading).toBe(false);
    if (failure === 'negative') { expect(f.env.bundleReport.ok).toBe(false); expect(f.env.bundleReport.errors).toEqual(['Untrusted issuer']); }
    else { expect(f.env.bundleReport).toBeNull(); expect(f.env.bundleError).toBeTruthy(); }
    if (failure === 'http') expect(f.env.bundleError).toBe('scanner unavailable');
  }
});

test('the actual compiled English and Swedish file picker advertises both native formats and retains the upload disclosure', async () => {
  const lib = resolve(dirname(filename), '../../lib');
  const built = await Bun.build({ entrypoints: ['verify-view-entry'], target: 'bun', plugins: [{ name: 'actual-verify-view', setup(build) {
    build.onResolve({ filter: /^verify-view-entry$/ }, () => ({ path: 'entry', namespace: 'verify-test' }));
    build.onLoad({ filter: /.*/, namespace: 'verify-test' }, () => ({ contents: `import View from ${JSON.stringify(filename)}; import {render} from 'svelte/server'; import {setStaffLocale} from ${JSON.stringify(resolve(lib, 'staffPreferences.ts'))}; export {View,render,setStaffLocale};`, loader: 'ts', resolveDir: process.cwd() }));
    build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
    // Use the actual SSR store file; avoid Bun's default-reader EISDIR in combined cohorts.
    build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, async args => ({ contents: await Bun.file(args.path).text(), loader: 'js', resolveDir: dirname(args.path) }));
    build.onLoad({ filter: /\.svelte$/ }, async args => ({ contents: compile(await Bun.file(args.path).text(), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
  } }] });
  expect(built.success).toBe(true);
  if (!built.success) throw Error(built.logs.map(String).join('\n'));
  const temporary = mkdtempSync(join(tmpdir(), 'hash-verify-view-'));
  try {
    const output = join(temporary, 'view.mjs'); writeFileSync(output, await built.outputs[0].text());
    const view = await import(pathToFileURL(output).href);
    for (const locale of ['en', 'sv']) {
      view.setStaffLocale(locale); const html = view.render(view.View).body;
      const input = html.match(/<input\b[^>]*id="evidence-bundle"[^>]*>/)?.[0]; expect(input).toBeTruthy();
      expect(input).toContain('accept="application/pdf,application/zip,application/x-zip-compressed,.pdf,.zip"');
      expect(input).toContain(locale === 'sv' ? 'Välj bevispaket (PDF eller ZIP)' : 'Choose evidence package (PDF or ZIP)');
      expect(html).toContain(locale === 'sv' ? 'Ladda bara upp dokument som du har rätt att dela.' : 'Only upload documents you are authorized to share.');
      expect(html).toContain(locale === 'sv' ? 'En vanlig avtals-PDF innehåller inte hela verifieringspaketet.' : 'A regular contract PDF on its own does not contain the full verification package.');
    }
    view.setStaffLocale('en');
  } finally { rmSync(temporary, { recursive: true, force: true }); }
  expect(source).toContain('onchange={onPick}'); expect(source).toContain('ondrop={onDrop}'); expect(source).toContain('disabled={bundleLoading}');
  for (const generate of ['client', 'server'] as const) expect(compile(source, { filename, generate }).warnings).toEqual([]);
  for (const text of ['Choose the evidence package', 'Choose a Hash evidence package (.pdf or .zip).', 'Choose evidence package (PDF or ZIP)']) expect(translateStaffText('sv', text)).not.toBe(text);
});
