import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';

const source = readFileSync(new URL('./MCPConnectionGuide.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const copy = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === 'copyEndpoint');
const mount = tree.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression.type === 'CallExpression' && node.expression.callee.name === 'onMount').expression.arguments[0];
const transpiler = new Bun.Transpiler({ loader: 'ts' });
const bindCopy = new Function('env', `with(env) { ${transpiler.transformSync(source.slice(copy.start, copy.end))}; return copyEndpoint; }`);
const mountCode = transpiler.transformSync(`function initialize() ${source.slice(mount.body.start, mount.body.end)}`);
const bindMount = new Function('env', `with(env) { ${mountCode}; return initialize; }`);

test('the actual endpoint is same-origin /mcp and only a read-only identity request decides whether key management is offered', async () => {
  let resolve!: (response: any) => void;
  const calls: any[] = [], env: any = { endpoint: 'https://hash.example.com/mcp', canManageKeys: false, window: { location: { origin: 'https://workspace.example.test:8443' } }, AbortController,
    fetch: (url: string, options: RequestInit) => { calls.push({ url, options }); return new Promise(done => { resolve = done; }); } };
  const dispose = bindMount(env)();
  expect(env.endpoint).toBe('https://workspace.example.test:8443/mcp'); expect(env.canManageKeys).toBe(false);
  expect(calls).toHaveLength(1); expect(calls[0].url).toBe('/api/v1/me'); expect(calls[0].options.credentials).toBe('include'); expect(calls[0].options.cache).toBe('no-store');
  resolve({ ok: true, json: async () => ({ role: 'owner' }) }); await new Promise(done => setTimeout(done, 0));
  expect(env.canManageKeys).toBe(true); dispose(); expect(calls[0].options.signal.aborted).toBe(true);
});

test('late identity after unmount cannot advertise owner actions and nonowners remain unable to manage keys', async () => {
  for (const role of ['viewer', 'sender', 'owner']) {
    let resolve!: (response: any) => void;
    const env: any = { endpoint: '', canManageKeys: false, window: { location: { origin: 'https://workspace.example.test' } }, AbortController,
      fetch: () => new Promise(done => { resolve = done; }) };
    const dispose = bindMount(env)(); if (role === 'owner') dispose();
    resolve({ ok: true, json: async () => ({ role }) }); await new Promise(done => setTimeout(done, 0));
    expect(env.canManageKeys).toBe(false); dispose();
  }
});

test('copying uses the displayed endpoint only and gives a manual fallback without exposing clipboard errors', async () => {
  const values: string[] = [], env: any = { endpoint: 'https://workspace.example.test/mcp', copied: false, copyFailed: false, navigator: { clipboard: { writeText: async (value: string) => { values.push(value); } } } };
  await bindCopy(env)(); expect(values).toEqual([env.endpoint]); expect(env.copied).toBe(true); expect(env.copyFailed).toBe(false);
  env.navigator.clipboard.writeText = async () => { throw new Error('private clipboard detail'); };
  await bindCopy(env)(); expect(env.copied).toBe(false); expect(env.copyFailed).toBe(true);
  expect(source).not.toContain('createAPIKey('); expect(source).toContain('Keep it private; do not add it to the address.');
});
