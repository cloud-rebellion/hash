import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const lib = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const page = resolve(lib, '../routes/settings/webhooks/+page.svelte');

// Exercise the actual page's script/create handler. The plain $state identity
// and onMount registration substitute reactive scheduling only; no subscription
// map, copied create handler, network implementation or browser claim is added.
test('actual webhook create handler keeps shared chat off until explicit selection and sends no premature request', async () => {
  const source = readFileSync(page, 'utf8');
  const script = source.match(/<script lang="ts">([\s\S]*?)<\/script>/)?.[1];
  if (!script) throw new Error('actual page script missing');
  const result = await Bun.build({ entrypoints: ['chat766-page'], target: 'bun', plugins: [{ name: 'actual-chat-page-handler', setup(build) {
    build.onResolve({ filter: /^chat766-page$/ }, () => ({ path: 'page', namespace: 'chat766' }));
    build.onResolve({ filter: /^\$lib\/api\/client$/ }, () => ({ path: 'api', namespace: 'chat766' }));
    build.onResolve({ filter: /^svelte$/ }, () => ({ path: 'lifecycle', namespace: 'chat766' }));
    build.onResolve({ filter: /^\$lib\// }, args => ({ path: Bun.resolveSync('./' + args.path.slice(5), lib) }));
    build.onLoad({ filter: /.*/, namespace: 'chat766' }, args => {
      if (args.path === 'api') return { contents: `export const calls = []; export async function createWebhook(url, events) { calls.push({url, events}); return {id:'synthetic',url,events_subscribed:events,active:true,created_at:''}; } export async function listWebhooks() {return {webhooks:[]};} export async function deleteWebhook() {} export async function listWebhookDeliveries() {return {deliveries:[]};}`, loader: 'ts' };
      if (args.path === 'lifecycle') return { contents: `export function onMount(callback) { /* registration does not create an endpoint */ }`, loader: 'ts' };
      return { contents: `const $state = <T>(value:T):T => value;\n${script}\nexport {create}; export {calls} from '$lib/api/client'; export function input(url:string, chat?:boolean) {newURL=url;if(chat!==undefined) evt.commentPosted=chat;} export function chatSelected() {return evt.commentPosted;}`, loader: 'ts', resolveDir: process.cwd() };
    });
  } }] });
  if (!result.success) throw new Error(result.logs.map(String).join('\n'));
  const directory = mkdtempSync(join(tmpdir(), 'hash-chat766-'));
  const previousFetch = globalThis.fetch; let requests = 0;
  globalThis.fetch = (() => { requests++; throw new Error('unit handler must not send network requests'); }) as typeof fetch;
  try {
    const output = join(directory, 'page.mjs'); writeFileSync(output, await result.outputs[0].text());
    const actual = await import(pathToFileURL(output).href);
    expect(actual.chatSelected()).toBe(false); expect(actual.calls).toEqual([]);
    await actual.create(); expect(actual.calls).toEqual([]);
    actual.input('https://receiver.example.invalid/hash'); expect(actual.calls).toEqual([]);
    await actual.create();
    expect(actual.calls).toHaveLength(1);
    expect(actual.calls[0]).toEqual({url:'https://receiver.example.invalid/hash',events:['document.sent','document.signed','document.completed','document.declined','document.changes_requested']});
    actual.input('https://receiver.example.invalid/hash', true); expect(actual.calls).toHaveLength(1);
    await actual.create(); expect(actual.calls).toHaveLength(2);
    expect(actual.calls[1].events).toEqual([...actual.calls[0].events,'document.comment_posted']);
    actual.input('https://receiver.example.invalid/hash', false); await actual.create();
    expect(actual.calls).toHaveLength(3); expect(actual.calls[2].events).toEqual(actual.calls[0].events);
    expect(requests).toBe(0);
  } finally { globalThis.fetch = previousFetch; rmSync(directory, {recursive:true,force:true}); }
});
