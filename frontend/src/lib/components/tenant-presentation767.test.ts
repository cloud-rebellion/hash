import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';

const lib = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const signer = readFileSync(resolve(lib, '../routes/sign/[token]/+page.svelte'), 'utf8');
const completed = readFileSync(resolve(lib, '../routes/completed/[token]/+page.svelte'), 'utf8');
const notice = readFileSync(join(lib, 'components/NoticeReader.svelte'), 'utf8');
const layout = readFileSync(resolve(lib, '../routes/+layout.svelte'), 'utf8');

function between(source: string, start: string, end: string) {
  const first = source.indexOf(start), last = source.indexOf(end, first);
  if (first < 0 || last < first) throw new Error('actual public presentation fragment missing');
  return source.slice(first, last + end.length);
}
const head = (source: string) => between(source, '<svelte:head>', '</svelte:head>');
const shells = {
  layout: `<script lang="ts">import { isStaffAuthPath, routeCategory } from ${JSON.stringify(join(lib, 'routeSurface.ts'))}; let { showChrome = false, path = '/sign/example' } = $props();</script>${head(layout)}`,
  signer: `<script lang="ts">import { FileSignature } from 'lucide-svelte'; import { t } from ${JSON.stringify(join(lib, 'i18n.ts'))}; let { ctx = null } = $props();</script>${head(signer)}${between(signer, '<header class="signer-bar">', '</header>')}`,
  completed: head(completed),
  notice: `${head(notice)}${between(notice, '<p class="font-display text-xl">', '</p>')}`
};
let rendering: Promise<any> | undefined;
function renderer() {
  return rendering ??= (async () => {
    const result = await Bun.build({ entrypoints: ['tenant767-entry'], target: 'bun', plugins: [{ name: 'actual-public-presentation-fragments', setup(build) {
      build.onResolve({ filter: /^tenant767-/ }, args => ({ path: args.path.slice('tenant767-'.length), namespace: 'tenant767' }));
      build.onLoad({ filter: /.*/, namespace: 'tenant767' }, args => {
        if (args.path === 'entry') return { contents: `import Layout from 'tenant767-layout'; import Signer from 'tenant767-signer'; import Completed from 'tenant767-completed'; import Notice from 'tenant767-notice'; import { render } from 'svelte/server'; export { Layout, Signer, Completed, Notice, render };`, loader: 'ts', resolveDir: process.cwd() };
        const fragment = shells[args.path as keyof typeof shells];
        if (!fragment) throw new Error('undeclared public presentation fragment');
        return { contents: compile(fragment, { filename: `tenant767-${args.path}.svelte`, generate: 'server' }).js.code, loader: 'js', resolveDir: process.cwd() };
      });
      build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
      build.onLoad({ filter: /\.svelte$/ }, args => ({ contents: compile(readFileSync(args.path, 'utf8'), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!result.success) throw new Error(result.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-tenant767-'));
    try { const output = join(temporary, 'shells.mjs'); writeFileSync(output, await result.outputs[0].text()); return await import(pathToFileURL(output).href); }
    finally { rmSync(temporary, { recursive: true, force: true }); }
  })();
}

// Scope: real production head/header markup and Svelte escaping. These fixtures
// do not replace the signer protocol, legal notice, business-state machine or
// any component, and do not claim a full-page/browser/recipient journey.
test('the app shell has a neutral public fallback and retains the staff application title', async () => {
  const m = await renderer();
  for (const path of ['/sign/example', '/completed/example', '/notice/comment/example', '/legal/privacy']) {
    expect(m.render(m.Layout, { props: { path } }).head).toContain('<title>Document</title>');
  }
  for (const path of ['/', '/login', '/reset-password', '/auth/callback']) {
    expect(m.render(m.Layout, { props: { path } }).head).toContain('<title>Hash</title>');
  }
  expect(m.render(m.Layout, { props: { path: '/documents', showChrome: true } }).head).toContain('<title>Hash</title>');
  // The static SPA boot document must leave route titles to SvelteKit.
  const boot = readFileSync(resolve(lib, '../app.html'), 'utf8');
  expect(boot).not.toContain('<title>');
  expect(boot).toContain('type="image/svg+xml"');
});

test('actual shared signer header and title use only trusted controller text across response statuses', async () => {
  const m = await renderer(); const previousFetch = globalThis.fetch; let requests = 0;
  globalThis.fetch = (() => { requests++; throw new Error('presentation SSR must not send requests'); }) as typeof fetch;
  try {
    for (const status of ['sent', 'changes_requested', 'declined', 'completed']) {
      const ctx = { document_name: 'Review copy', status, recipient: { name: 'Example recipient', role: 'signer' }, privacy: { controller: 'Customer & Company', processor: 'Separate processor identity' } };
      const rendered = m.render(m.Signer, { props: { ctx } });
      expect(rendered.body).toContain('Customer &amp; Company');
      expect(rendered.head).toContain('Review copy · Customer &amp; Company');
      expect(rendered.body + rendered.head).not.toContain('Separate processor identity');
      expect(rendered.body + rendered.head).not.toContain('Hash');
    }
    expect(requests).toBe(0);
  } finally { globalThis.fetch = previousFetch; }
});

test('actual signer presentation escapes tenant strings and has a neutral pre-context fallback', async () => {
  const m = await renderer();
  const controller = 'Tenant <img src=x onerror=alert(1)> & Company';
  const ctx = { document_name: 'Agreement <script>bad()</script>', recipient: { name: 'Example', role: 'signer' }, privacy: { controller } };
  const rendered = m.render(m.Signer, { props: { ctx } });
  expect(rendered.body).toContain('Tenant &lt;img'); expect(rendered.head).toContain('Tenant &lt;img');
  expect(rendered.head).toContain('Agreement &lt;script');
  expect(rendered.body + rendered.head).not.toContain('<img'); expect(rendered.body + rendered.head).not.toContain('<script>bad()');
  const empty = m.render(m.Signer, { props: { ctx: null } });
  expect(empty.body).toContain('<span>Document</span>'); expect(empty.head).toContain('<title>Document</title>');
  expect(empty.body + empty.head).not.toContain('Hash');
});

test('actual separate completion and notice shells use neutral document labels without an identity fetch', async () => {
  const m = await renderer(); const previousFetch = globalThis.fetch; let requests = 0;
  globalThis.fetch = (() => { requests++; throw new Error('neutral shell SSR must not send requests'); }) as typeof fetch;
  try {
    const done = m.render(m.Completed), issued = m.render(m.Notice);
    expect(done.head).toContain('<title>Completed contract</title>');
    expect(issued.head).toContain('<title>Email notice</title>'); expect(issued.body).toContain('Document notice');
    expect(done.head + issued.head + issued.body).not.toContain('Hash'); expect(requests).toBe(0);
  } finally { globalThis.fetch = previousFetch; }
});

test('actual modified pages compile for client/server without presentation warnings', () => {
  for (const [filename, source] of [['layout.svelte', layout], ['signer.svelte', signer], ['completed.svelte', completed], ['notice.svelte', notice]]) {
    for (const generate of ['client', 'server'] as const) expect(compile(source, { filename, generate }).warnings).toEqual([]);
  }
});
