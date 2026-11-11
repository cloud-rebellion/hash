import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';

const filename = fileURLToPath(new URL('./RoomPreview.svelte', import.meta.url));
let rendered: Promise<any> | undefined;
function renderer() {
  return rendered ??= (async () => {
    const lib = resolve(dirname(filename), '..');
    const result = await Bun.build({ entrypoints: ['room-preview-render-entry'], target: 'bun', plugins: [{ name: 'real-room-preview-view', setup(build) {
      build.onResolve({ filter: /^room-preview-render-entry$/ }, () => ({ path: 'entry', namespace: 'room-preview-test' }));
      build.onLoad({ filter: /.*/, namespace: 'room-preview-test' }, () => ({ contents: `import View from ${JSON.stringify(filename)}; import { render } from 'svelte/server'; import { setStaffLocale } from ${JSON.stringify(resolve(lib, 'staffPreferences.ts'))}; import { createRoomPreview, createRoomPreviewAccess } from ${JSON.stringify(resolve(lib, 'roomPreview.ts'))}; export { View, render, setStaffLocale, createRoomPreview, createRoomPreviewAccess };`, loader: 'ts', resolveDir: process.cwd() }));
      build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
      build.onLoad({ filter: /\/svelte\/src\/store\/index-server\.js$/ }, args => ({ contents: readFileSync(args.path, 'utf8'), loader: 'js', resolveDir: dirname(args.path) }));
      build.onLoad({ filter: /\.svelte$/ }, args => ({ contents: compile(readFileSync(args.path, 'utf8'), { filename: args.path, generate: 'server' }).js.code, loader: 'js', resolveDir: dirname(args.path) }));
    } }] });
    if (!result.success) throw new Error(result.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-room-preview-render-'));
    try { const path = join(temporary, 'view.mjs'); writeFileSync(path, await result.outputs[0].text()); return await import(pathToFileURL(path).href); }
    finally { rmSync(temporary, { recursive: true, force: true }); }
  })();
}

test('real room view gates on staff identity and renders EN/SV interactions without a recipient token', async () => {
  const m = await renderer();
  const access = m.createRoomPreviewAccess({ identity: async () => ({ user_id: 'staff', org_id: 'workspace', role: 'member' }),
    branding: async () => ({ primary_hex: '#334466', logo_alt: 'Example workspace' }) });
  const room = m.createRoomPreview();
  try {
    let html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
    expect(html).toContain('Checking your staff session'); expect(html).not.toContain('room-preview-message');
    await access.load();
    for (const locale of ['en', 'sv']) {
      m.setStaffLocale(locale);
      html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
      expect(html).toContain(locale === 'sv' ? 'Förhandsvisa mottagarrummet' : 'Recipient room preview');
      expect(html).toContain(locale === 'sv' ? 'Endast test' : 'Test only');
      expect(html).toContain('Example workspace'); expect(html).toContain('alex@example.invalid');
      expect(html).toContain('id="room-preview-message"'); expect(html).toContain('id="room-preview-signature"');
      expect(html).toContain(locale === 'sv' ? 'Sida 1 av 2' : 'Page 1 of 2');
      expect(html).not.toContain('/sign/'); expect(html).not.toContain('download=');
    }
    m.setStaffLocale('en'); expect(room.message('<script>alert(1)</script>')).toBe(true);
    html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
    expect(html).toContain('&lt;script>alert(1)&lt;/script>');
    expect(html).not.toContain('<script'); expect(html).not.toContain('</script>');
    room.requestChanges('Move the example handover.');
    html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
    expect(html).toContain('Changes requested · preview'); expect(html).toContain('Move the example handover.');
    expect(html).not.toContain('id="room-preview-signature"');
    room.reset(); room.setSignatureName('Alex Example'); room.setConfirmed(true); room.finish();
    html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
    expect(html).toContain('No document was signed or saved.'); expect(html).toContain('typed-signature');
    expect(html).toContain('Page 2 of 2'); expect(html).toContain('not a saved evidence log');
    room.setMode('acceptance'); room.setConfirmed(true); room.finish();
    html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
    expect(html).toContain('No agreement was accepted or saved.'); expect(html).not.toContain('typed-signature');
    room.reset();
    html = m.render(m.View, { props: { controller: room, accessController: access } }).body;
    expect(html).toContain('Start a conversation'); expect(html).not.toContain('No agreement was accepted or saved.');
  } finally { access.dispose(); m.setStaffLocale('en'); }
});

test('room and email entry compile for browser/server without accessibility warnings', () => {
  for (const path of [filename, fileURLToPath(new URL('../../routes/settings/room-preview/+page.svelte', import.meta.url)), fileURLToPath(new URL('../../routes/settings/email/+page.svelte', import.meta.url))]) {
    const source = readFileSync(path, 'utf8');
    for (const generate of ['client', 'server'] as const) expect(compile(source, { filename: path, generate }).warnings).toEqual([]);
  }
});

test('room UI has no token-connected signer, document API, certificate export or persistence', () => {
  const source = readFileSync(filename, 'utf8');
  expect(source).not.toMatch(/PdfSignerView|SignerFields|SignerPackage|\/sign\/|localStorage|sessionStorage|fetch\(/);
  expect(source).toContain('identity: getMe, branding: getBranding');
  expect(source).toContain('aria-pressed='); expect(source).toContain('onpointercancel=');
  const email = readFileSync(new URL('../../routes/settings/email/+page.svelte', import.meta.url), 'utf8');
  expect(email).toContain('href="/settings/room-preview"');
});
