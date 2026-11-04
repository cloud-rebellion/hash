import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile, parse } from 'svelte/compiler';
import { createWorkspaceSMTPController, type WorkspaceSMTP } from '../workspaceSMTP';

const filename = fileURLToPath(new URL('./WorkspaceSMTPSettings.svelte', import.meta.url));
const source = readFileSync(filename, 'utf8');
const tree: any = parse(source, { modern: true });
const functions = tree.instance.content.body.filter((node: any) => node.type === 'FunctionDeclaration');
const bind = new Function('env', `with(env) { ${functions.map((node: any) => new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(node.start, node.end))).join('\n')}; return { save, askDisable, closeDisable, disableKey }; }`);

test('actual form handler focuses an invalid native field and never submits; valid form submits once', async () => {
  let focused = '', saved = 0, prevented = 0;
  const env = { fenced: false, form: { querySelector: (selector: string) => ({ focus: () => focused = selector }) }, editor: { problems: () => ({ password: 'required' }), save: async () => { saved++; } } };
  const handlers = bind(env); await handlers.save({ preventDefault: () => prevented++ }); expect(focused).toContain('password'); expect(saved).toBe(0);
  env.editor.problems = () => ({} as any); await handlers.save({ preventDefault: () => prevented++ }); expect(saved).toBe(1); expect(prevented).toBe(2); env.fenced = true; await handlers.save({ preventDefault() {} }); expect(saved).toBe(1);
});
test('actual disable handlers focus Cancel, restore the trigger on Escape and respect a busy operation', async () => {
  let focus = '', requested = 0, cancelled = 0;
  const env: any = { busy: false, tick: async () => {}, disableCancel: { focus: () => focus = 'cancel' }, disableButton: { focus: () => focus = 'trigger' }, editor: { requestDisable: () => { requested++; return true; }, cancelDisable: () => { cancelled++; return true; } } };
  const handlers = bind(env); Object.assign(env, handlers); await handlers.askDisable(); expect(focus).toBe('cancel'); handlers.disableKey({ key: 'Escape', preventDefault() {} }); await Promise.resolve(); expect(cancelled).toBe(1); expect(focus).toBe('trigger'); env.busy = true; handlers.disableKey({ key: 'Escape', preventDefault() {} }); expect(cancelled).toBe(1); expect(requested).toBe(1);
});

let serverModule: Promise<any> | undefined;
function renderer() {
  return serverModule ??= (async () => {
    const lib = resolve(dirname(filename), '..');
    const built = await Bun.build({ entrypoints: ['delivery-render-entry'], target: 'bun', minify: false, plugins: [{ name: 'actual-svelte-server', setup(build) {
      build.onResolve({ filter: /^delivery-render-entry$/ }, () => ({ path: 'entry', namespace: 'delivery-test' }));
      build.onLoad({ filter: /.*/, namespace: 'delivery-test' }, () => ({ contents: `import View from ${JSON.stringify(filename)}; import { render } from 'svelte/server'; import { setStaffLocale } from ${JSON.stringify(resolve(lib, 'staffPreferences.ts'))}; export { View, render, setStaffLocale };`, loader: 'ts', resolveDir: process.cwd() }));
      build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
      build.onLoad({ filter: /\.svelte$/ }, async args => ({ contents: compile(await Bun.file(args.path).text(), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!built.success) throw new Error(built.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-smtp-render-'));
    try { const modulePath = join(temporary, 'view.mjs'); writeFileSync(modulePath, await built.outputs[0].text()); return await import(pathToFileURL(modulePath).href); }
    finally { rmSync(temporary, { recursive: true, force: true }); }
  })();
}
const saved: WorkspaceSMTP = { schema_version: 1, revision: 2, mode: 'configured', configured: true, host: 'smtp.example.test', port: 465, tls_mode: 'tls', sender_name: 'Workspace', sender_email: 'sender@example.test', username_set: true, password_set: true, updated_at: null };
test('actual compiled server view renders both locales, protected new-entry inputs and honest test status', async () => {
  const module = await renderer(); const controller = createWorkspaceSMTPController({ load: async () => saved, save: async () => saved, disable: async () => saved, test: async () => { throw new Error('not called'); }, status: async () => { throw new Error('not called'); } });
  await controller.load(); controller.authenticate('replace'); controller.credential('username', 'SYNTHETIC-PRIVATE-USER'); controller.credential('password', 'SYNTHETIC-PRIVATE-PASSWORD');
  module.setStaffLocale('en'); let html = module.render(module.View, { props: { controller } }).body;
  expect(html).toContain('Sender identity'); expect(html).toContain('Connection security'); expect(html).toContain('SMTP acceptance means'); expect(html).not.toContain('SYNTHETIC-PRIVATE');
  for (const id of ['smtp-username', 'smtp-password']) { const input = html.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`))?.[0]; expect(input).toContain('type="password"'); expect(input).not.toMatch(/\svalue=/); }
  module.setStaffLocale('sv'); html = module.render(module.View, { props: { controller } }).body; expect(html).toContain('E-postleverans'); expect(html).toContain('Avsändare'); expect(html).toContain('Anslutningssäkerhet'); expect(html).not.toContain('Sender identity'); controller.dispose(); module.setStaffLocale('en');
});
test('actual view compiles for browser and server with no accessibility warnings', () => {
  for (const generate of ['client', 'server'] as const) { const result = compile(source, { filename, generate }); expect(result.warnings).toEqual([]); }
});
