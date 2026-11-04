import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile, parse } from 'svelte/compiler';
import { getBranding, saveBranding, type OrgBranding } from '../api/client';

const lib = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const filename = join(lib, 'components/BrandingLogoFields.svelte');
const source = readFileSync(filename, 'utf8');
const pageFile = resolve(lib, '../routes/settings/branding/+page.svelte');
const pageSource = readFileSync(pageFile, 'utf8');
function handlers(text: string, names: string[]) {
  const tree: any = parse(text, { modern: true });
  const functions = tree.instance.content.body.filter((node: any) => node.type === 'FunctionDeclaration' && names.includes(node.id.name));
  expect(functions).toHaveLength(names.length);
  return new Function('env', `with(env) { ${functions.map((node: any) => new Bun.Transpiler({ loader: 'ts' }).transformSync(text.slice(node.start, node.end))).join('\n')}; return { ${names.join(',')} }; }`);
}

const theme: OrgBranding = { primary_hex: '#112233', accent_hex: '#336699', surface_hex: '#FFFFFF', text_hex: '#111111', muted_hex: '#555555',
  logo_url: 'https://legacy.example.test/logo.png', logo_alt: 'Example', font_heading: 'Inter', font_body: 'Inter', signature_color: '#112233' };

test('branding API keeps read-only capability out of writes and preserves explicit empty logo fields', async () => {
  const oldFetch = globalThis.fetch;
  const requests: { url: string; method?: string; credentials?: RequestCredentials; body: unknown }[] = [];
  globalThis.fetch = (async (url, options) => {
    requests.push({ url: String(url), method: options?.method, credentials: options?.credentials, body: options?.body ? JSON.parse(String(options.body)) : undefined });
    return new Response(JSON.stringify({ ...theme, logo_url_supported: false }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  try {
    const configuration = await getBranding();
    expect(configuration.logo_url_supported).toBe(false);
    await saveBranding({ ...configuration, logo_url: '', logo_alt: '' });
    expect(requests[0]).toMatchObject({ url: '/api/v1/branding', method: 'GET', credentials: 'include' });
    expect(requests[1]).toMatchObject({ url: '/api/v1/branding', method: 'PUT', credentials: 'include', body: { ...theme, logo_url: '', logo_alt: '' } });
    expect(requests[1].body).not.toHaveProperty('logo_url_supported');
    await saveBranding({ primary_hex: '#445566' });
    expect(requests[2].body).toEqual({ primary_hex: '#445566' });
  } finally { globalThis.fetch = oldFetch; }
});

test('actual branding page separates capability from editable theme and fails closed on unknown or failed load', async () => {
  const env: any = { branding: {}, loading: false, logoURLSupported: false, saving: false, saved: false, error: null,
    getBranding: async () => ({ ...theme, logo_url_supported: true }), saveBranding: async (value: unknown) => value, setTimeout() {} };
  const view = handlers(pageSource, ['load', 'save'])(env);
  await view.load(); expect(env.logoURLSupported).toBe(true); expect(env.branding).toEqual(theme);
  await view.save(); expect(env.logoURLSupported).toBe(true); expect(env.saved).toBe(true);
  env.getBranding = async () => ({ ...theme });
  await view.load(); expect(env.logoURLSupported).toBe(false);
  env.logoURLSupported = true; env.getBranding = async () => { throw new Error('unavailable'); };
  await view.load(); expect(env.logoURLSupported).toBe(false); expect(env.error).toBe('unavailable'); expect(env.loading).toBe(false);
});

test('actual clear handler clears only both logo fields and respects a pending save', () => {
  const patches: unknown[] = [];
  const env = { disabled: false, onChange: (patch: unknown) => patches.push(patch) };
  const view = handlers(source, ['clearLogo'])(env);
  view.clearLogo(); expect(patches).toEqual([{ logo_url: '', logo_alt: '' }]);
  env.disabled = true; view.clearLogo(); expect(patches).toHaveLength(1);
});

let rendering: Promise<any> | undefined;
function renderer() {
  return rendering ??= (async () => {
    const build = await Bun.build({ entrypoints: ['branding769-entry'], target: 'bun', plugins: [{ name: 'actual-branding-fields', setup(b) {
      b.onResolve({ filter: /^branding769-entry$/ }, () => ({ path: 'entry', namespace: 'branding769' }));
      b.onLoad({ filter: /.*/, namespace: 'branding769' }, () => ({ contents: `import Fields from ${JSON.stringify(filename)}; import Page from ${JSON.stringify(pageFile)}; import { render } from 'svelte/server'; import { setStaffLocale } from ${JSON.stringify(join(lib, 'staffPreferences.ts'))}; export { Fields, Page, render, setStaffLocale };`, loader: 'ts', resolveDir: process.cwd() }));
      b.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
      // Keep the real server store implementation independent of other tests'
      // module mocks, matching the existing public-presentation SSR harness.
      b.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
      b.onLoad({ filter: /\.svelte$/ }, async args => ({ contents: compile(await Bun.file(args.path).text(), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!build.success) throw new Error(build.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-branding769-'));
    try { const output = join(temporary, 'fields.mjs'); writeFileSync(output, await build.outputs[0].text()); return await import(pathToFileURL(output).href); }
    finally { rmSync(temporary, { recursive: true, force: true }); }
  })();
}

test('actual EN/SV logo fields disable unsupported editing while keeping legacy clear and email-design access available', async () => {
  const m = await renderer(); const oldFetch = globalThis.fetch; let requests = 0;
  globalThis.fetch = (() => { requests++; throw new Error('SSR must not fetch'); }) as typeof fetch;
  try {
    for (const locale of ['en', 'sv']) {
      m.setStaffLocale(locale);
      const props = { supported: false, logoURL: 'https://legacy.example.test/logo.png', logoAlt: 'Legacy "<Company>"', onChange() {} };
      const html = m.render(m.Fields, { props }).body;
      expect(html).toMatch(/<fieldset[^>]*\sdisabled/);
      // A quoted attribute escapes '<' and quotes; a literal closing '>' is safe.
      expect(html).toMatch(/Legacy (?:&quot;|&#34;)&lt;Company/);
      expect(html).not.toContain('<Company'); expect(html).not.toContain('value="Legacy "');
      expect(html).toContain('href="/settings/email"');
      expect(html).toContain(locale === 'sv' ? 'Rensa logotypens URL' : 'Clear logo URL');
      expect(html).toContain(locale === 'sv' ? 'spara ändringarna' : 'save changes');
      const supported = m.render(m.Fields, { props: { ...props, supported: true } }).body;
      expect(supported).not.toMatch(/<fieldset[^>]*\sdisabled/);
      expect(supported).not.toContain(locale === 'sv' ? 'Rensa logotypens URL' : 'Clear logo URL');
      const empty = m.render(m.Fields, { props: { ...props, logoURL: '' } }).body;
      expect(empty).not.toContain(locale === 'sv' ? 'Rensa logotypens URL' : 'Clear logo URL');
      const page = m.render(m.Page).body;
      expect(page).toContain(locale === 'sv' ? 'Dokumenttema' : 'Document theme');
      expect(page).not.toContain('every rendered document');
    }
    expect(requests).toBe(0);
  } finally { m.setStaffLocale('en'); globalThis.fetch = oldFetch; }
});

test('actual branding fields and page compile for browser/server without accessibility warnings', () => {
  for (const [text, file] of [[source, filename], [pageSource, pageFile]]) {
    for (const generate of ['client', 'server'] as const) expect(compile(text, { filename: file, generate }).warnings).toEqual([]);
  }
});
