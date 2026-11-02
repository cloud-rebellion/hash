import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
const source = readFileSync(new URL('../routes/settings/api-keys/+page.svelte', import.meta.url), 'utf8');
const ast = parse(source, { modern: true }) as any;
const handlers = ['create', 'openCreate', 'closeCreate', 'copyPlaintext', 'invalidateCopyFeedback', 'dismissPlaintext'].map(name => {
 const node = ast.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
 if (!node) throw Error(`Missing real form handler: ${name}`);
 return new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(node.start, node.end));
}).join('\n');
function fixture(input: { name?: string; scopes?: { read: boolean; authoring: boolean; workflow: boolean }; creating?: boolean; secret?: string; dispatch?: () => Promise<unknown>; clipboardFails?: boolean; clipboard?: () => Promise<void> } = {}) {
 const calls: unknown[] = []; let nameFocus = 0, triggerFocus = 0, refreshes = 0;
 const api = async (request: unknown) => { calls.push(request); return input.dispatch ? input.dispatch() : { plaintext: 'TEST-ONLY-NOT-A-CREDENTIAL' }; };
 const clipboard = { writeText: async (_value: string) => { if (input.clipboard) return input.clipboard(); if (input.clipboardFails) throw Error('clipboard denied'); } };
 const instance = new Function('input', 'createAPIKey', 'refresh', 'tick', 'navigator', 'nameInput', 'createTrigger', `
 let newName = input.name ?? '', scopes = input.scopes ?? { read: true, authoring: true, workflow: false }, creating = input.creating ?? false;
 let error = null, showCreate = false, mintedPlaintext = input.secret ?? null, keyCopied = false, copyError = false, copyingKey = false, copyRevision = 0;
 ${handlers}
 return { create, openCreate, closeCreate, copyPlaintext, dismissPlaintext, snapshot: () => ({ newName, scopes, creating, error, showCreate, mintedPlaintext, keyCopied, copyError, copyingKey }) };
 `)(input, api, async () => { refreshes++; }, async () => {}, { clipboard }, { focus: () => nameFocus++ }, { focus: () => triggerFocus++ });
 return { ...instance, calls, nameFocus: () => nameFocus, triggerFocus: () => triggerFocus, refreshes: () => refreshes };
}
test('an empty or whitespace key name gives an actionable error without credential issuance', async () => {
 for (const name of ['', '   ']) { const f = fixture({ name }); await f.create(); expect(f.calls).toHaveLength(0); expect(f.snapshot().error).toBe('Enter a name for this key.'); expect(f.nameFocus()).toBe(1); }
});
test('no selected permissions explains the refusal before any credential request', async () => {
 const f = fixture({ name: 'Sales API', scopes: { read: false, authoring: false, workflow: false } }); await f.create(); expect(f.calls).toHaveLength(0); expect(f.snapshot().error).toBe('Choose at least one permission.');
});
test('real creation handler sends the trimmed name and only explicitly selected scopes', async () => {
 const f = fixture({ name: ' Sales API ', scopes: { read: true, authoring: false, workflow: true } }); await f.create(); expect(f.calls).toEqual([{ name: 'Sales API', scopes: ['read', 'write:workflow'] }]); expect(f.snapshot().creating).toBe(false); expect(f.snapshot().mintedPlaintext).toBe('TEST-ONLY-NOT-A-CREDENTIAL'); expect(f.refreshes()).toBe(1);
});
test('repeated create cannot issue a second key while the original response is pending', async () => {
 let finish!: (value: unknown) => void; const gate = new Promise(resolve => { finish = resolve; }); const f = fixture({ name: 'Sales API', dispatch: () => gate }); const first = f.create(); await f.create(); await f.closeCreate(); expect(f.calls).toHaveLength(1); expect(f.snapshot().creating).toBe(true); finish({ plaintext: 'TEST-ONLY-NOT-A-CREDENTIAL' }); await first; expect(f.snapshot().creating).toBe(false);
});
test('opening focuses the required field and cancelling closes with focus restored', async () => {
 const f = fixture({ name: 'Unsaved name' }); await f.openCreate(); expect(f.snapshot().showCreate).toBe(true); expect(f.nameFocus()).toBe(1); await f.closeCreate(); expect(f.snapshot().showCreate).toBe(false); expect(f.snapshot().newName).toBe('Unsaved name'); expect(f.triggerFocus()).toBe(1);
});
test('clipboard success and refusal both provide visible feedback state without changing the key', async () => {
 for (const clipboardFails of [false, true]) { const f = fixture({ secret: 'TEST-ONLY-NOT-A-CREDENTIAL', clipboardFails }); await f.copyPlaintext(); expect(f.snapshot().keyCopied).toBe(!clipboardFails); expect(f.snapshot().copyError).toBe(clipboardFails); expect(f.snapshot().mintedPlaintext).toBe('TEST-ONLY-NOT-A-CREDENTIAL'); expect(f.calls).toHaveLength(0); }
});

test('late copy completion cannot claim a subsequently issued key was copied', async () => {
 for (const rejected of [false, true]) {
  let finish!: () => void, fail!: () => void;
  const gate = new Promise<void>((resolve, reject) => { finish = resolve; fail = () => reject(Error('clipboard denied')); });
  const f = fixture({ secret: 'TEST-ONLY-OLD-KEY', name: 'New integration', clipboard: () => gate });
  const copying = f.copyPlaintext(); await f.create();
  if (rejected) fail(); else finish(); await copying;
  expect(f.snapshot().mintedPlaintext).toBe('TEST-ONLY-NOT-A-CREDENTIAL');
  expect(f.snapshot().keyCopied).toBe(false); expect(f.snapshot().copyError).toBe(false); expect(f.snapshot().copyingKey).toBe(false);
 }
});
test('dismissing a pending key invalidates its late copy feedback', async () => {
 let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
 const f = fixture({ secret: 'TEST-ONLY-OLD-KEY', clipboard: () => gate }); const copying = f.copyPlaintext(); f.dismissPlaintext(); await f.copyPlaintext(); finish(); await copying;
 expect(f.snapshot().mintedPlaintext).toBeNull(); expect(f.snapshot().keyCopied).toBe(false); expect(f.snapshot().copyError).toBe(false);
});
