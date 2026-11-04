import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';

const lib = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const routes = resolve(lib, '../routes/settings');
const pages = { Settings: join(routes, '+page.svelte'), API: join(routes, 'api-keys/+page.svelte'), Webhooks: join(routes, 'webhooks/+page.svelte') };
let rendering: Promise<any> | undefined;
function renderer() {
  return rendering ??= (async () => {
    const result = await Bun.build({ entrypoints: ['hash-neutral-settings-render'], target: 'bun', plugins: [{ name: 'actual-settings-pages', setup(build) {
      build.onResolve({ filter: /^hash-neutral-settings-render$/ }, () => ({ path: 'entry', namespace: 'neutral-settings' }));
      build.onLoad({ filter: /.*/, namespace: 'neutral-settings' }, () => ({ contents: `${Object.entries(pages).map(([key, path]) => `import ${key} from ${JSON.stringify(path)};`).join('\n')} import { render } from 'svelte/server'; import { setStaffLocale } from ${JSON.stringify(join(lib, 'staffPreferences.ts'))}; export { Settings, API, Webhooks, render, setStaffLocale };`, loader: 'ts', resolveDir: process.cwd() }));
      build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
      build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
      build.onLoad({ filter: /\.svelte$/ }, args => ({ contents: compile(readFileSync(args.path, 'utf8'), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!result.success) throw new Error(result.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-settings-neutral-'));
    try { const output = join(temporary, 'pages.mjs'); writeFileSync(output, await result.outputs[0].text()); return await import(pathToFileURL(output).href); }
    finally { rmSync(temporary, { recursive: true, force: true }); }
  })();
}
async function renderLocales(page: keyof typeof pages, assertion: (html: string, locale: 'en' | 'sv') => void) {
  const m = await renderer(); const previousFetch = globalThis.fetch; let requests = 0;
  globalThis.fetch = (() => { requests++; throw new Error('Settings SSR must not send requests'); }) as typeof fetch;
  try {
    for (const locale of ['en', 'sv'] as const) { m.setStaffLocale(locale); assertion(m.render(m[page]).body, locale); }
    expect(requests).toBe(0);
  } finally { m.setStaffLocale('en'); globalThis.fetch = previousFetch; }
}
test('actual Settings retains email/automation/API routes without a CRM-specific connection card in EN/SV', async () => {
  await renderLocales('Settings', (html, locale) => {
    for (const href of ['/settings/delivery', '/settings/email', '/settings/automations', '/settings/api-keys', '/settings/webhooks', '/settings/branding', '/settings/members']) expect(html).toContain(`href="${href}"`);
    expect(html).not.toContain('/settings/integrations/brightcrm'); expect(html).not.toContain('BrightCRM');
    expect(html).toContain(locale === 'sv' ? 'Anslut valfritt CRM eller automatisering' : 'Use any CRM or automation');
  });
});
test('actual API page explains template/prepared requests, outward status flow and separate MCP in EN/SV', async () => {
  await renderLocales('API', (html, locale) => {
    expect(html).toContain('href="/settings/webhooks"'); expect(html).toContain('id="mcp"');
    expect(html).toContain(locale === 'sv' ? 'godkänd blockmall' : 'approved blocks template');
    expect(html).toContain(locale === 'sv' ? 'redan förberett dokument' : 'already prepared document');
    expect(html).toContain(locale === 'sv' ? 'Din applikation → Hash → din applikation' : 'Your application → Hash → your application');
    expect(html).toContain(locale === 'sv' ? 'till en webhook-URL i din applikation' : 'to a webhook URL in your application');
    expect(html).toContain(locale === 'sv' ? 'Integrationer via HTTP-API kräver inte MCP.' : 'HTTP API integrations do not require MCP.');
  });
});
test('actual webhook page explains receiving direction, completion and optional shared chat in EN/SV', async () => {
  await renderLocales('Webhooks', (html, locale) => {
    expect(html).toContain('href="/settings/api-keys"'); expect(html).toContain('X-Hash-Signature');
    expect(html).toContain(locale === 'sv' ? 'Från Hash till din applikation' : 'From Hash to your application');
    expect(html).toContain(locale === 'sv' ? 'mottagar-URL i din applikation' : 'receiving URL in your application');
    expect(html).toContain(locale === 'sv' ? 'alla obligatoriska signerare och slutbehandlingen är klara' : 'all required signers and finalization are complete');
    expect(html).toContain('document.comment_posted');
    expect(html).toContain(locale === 'sv' ? 'Aviseringar om delad dokumentchatt är valfria.' : 'Shared document chat notifications are optional.');
    expect(html).toContain(locale === 'sv' ? 'meddelandetext och privat aktivitet ingår inte' : 'message text and private activity are not included');
    expect(html).not.toContain('Hash stores only a hash'); expect(html).not.toContain('/webhooks/brightcrm');
  });
});
test('all three actual pages compile for browser/server without accessibility warnings', () => {
  for (const filename of Object.values(pages)) for (const generate of ['client', 'server'] as const) expect(compile(readFileSync(filename, 'utf8'), { filename, generate }).warnings).toEqual([]);
});
