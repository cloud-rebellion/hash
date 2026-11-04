import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';

const filename = fileURLToPath(new URL('./EmailTemplateSettings.svelte', import.meta.url));
let rendered: Promise<any> | undefined;
function renderer() {
  return rendered ??= (async () => {
    const lib = resolve(dirname(filename), '..');
    const result = await Bun.build({ entrypoints: ['email-design-render-entry'], target: 'bun', plugins: [{ name: 'real-email-design-view', setup(build) {
      build.onResolve({ filter: /^email-design-render-entry$/ }, () => ({ path: 'entry', namespace: 'email-design-test' }));
      build.onLoad({ filter: /.*/, namespace: 'email-design-test' }, () => ({ contents: `import View from ${JSON.stringify(filename)}; import { render } from 'svelte/server'; import { setStaffLocale } from ${JSON.stringify(resolve(lib, 'staffPreferences.ts'))}; import { createEmailTemplateEditor, emailTemplateKinds, editableEmailTemplateKinds } from ${JSON.stringify(resolve(lib, 'emailTemplateEditor.ts'))}; export { View, render, setStaffLocale, createEmailTemplateEditor, emailTemplateKinds, editableEmailTemplateKinds };`, loader: 'ts', resolveDir: process.cwd() }));
      build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
      build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
      build.onLoad({ filter: /\.svelte$/ }, args => ({ contents: compile(readFileSync(args.path, 'utf8'), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!result.success) throw new Error(result.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-email-design-render-'));
    try { const path = join(temporary, 'view.mjs'); writeFileSync(path, await result.outputs[0].text()); return await import(pathToFileURL(path).href); }
    finally { rmSync(temporary, { recursive: true, force: true }); }
  })();
}

test('real compiled email designer renders loaded owner, AI review and builtin states in EN/SV without network', async () => {
  const m = await renderer(); const templates = m.emailTemplateKinds.map((kind: string) => ({ kind, revision: 0, editable: m.editableEmailTemplateKinds.includes(kind), subject_template: '', html_template: '', text_template: '', variables: ['org_name'], mandatory_content: 'appended_by_hash' }));
  const controller = m.createEmailTemplateEditor({ load: async () => ({ schema_version: 1, preview_synthetic: true, limits: { subject_bytes: 256, html_bytes: 16384, text_bytes: 8192, design_bytes: 131072 }, templates }),
    save: async () => { throw new Error('No implicit save'); }, preview: async () => { throw new Error('No implicit preview'); },
    propose: async (kind: string, input: any) => ({ schema_version: 1, kind, expected_revision: input.expected_revision, saved: false, input: { ...input, subject_template: 'AI subject', design_json: JSON.stringify({ schema_version: 1, layout_html: '<div>{{native_content}}</div>', background: '#ffffff', surface: '#ffffff', primary: '#111111', text: '#111111', logo: null, logo_alt: '' }) }, preview: { schema_version: 1, synthetic: true, revision: 0, subject: 'AI rendered', html: '<p>Native</p>', text: 'Native', mandatory_content_preserved: true } }) });
  await controller.load();
  try {
    for (const locale of ['en', 'sv']) {
      m.setStaffLocale(locale); const html = m.render(m.View, { props: { controller } }).body;
      expect(html).toContain(locale === 'sv' ? 'Varumärke och layout' : 'Brand and layout'); expect(html).toContain('type="color"'); expect(html).toContain('accept="image/png,image/jpeg"');
      expect(html).toContain(locale === 'sv' ? 'Utforma med AI' : 'Design with AI'); expect(html).toContain('/settings/ai'); expect(html).toContain('/settings/delivery'); expect(html).not.toContain('<iframe');
    }
    await controller.propose('Readable'); m.setStaffLocale('sv'); let html = m.render(m.View, { props: { controller } }).body;
    expect(html).toContain('AI-förslag · inte sparat'); expect(html).toContain('Använd förslaget i utkastet'); expect(html).toContain('sandbox=""'); expect(html).toContain('img-src data:'); expect(html).toContain('AI rendered');
    controller.discardProposal(); controller.select('email.voided'); html = m.render(m.View, { props: { controller } }).body;
    expect(html).not.toContain('id="email-layout-html"'); expect(html).not.toContain('id="email-design-prompt"');
    expect(html).toContain('Endast visning');
  } finally { controller.dispose(); m.setStaffLocale('en'); }
});
test('actual designer compiles for browser and server without accessibility warnings', () => {
  for (const generate of ['client', 'server'] as const) expect(compile(readFileSync(filename, 'utf8'), { filename, generate }).warnings).toEqual([]);
});
