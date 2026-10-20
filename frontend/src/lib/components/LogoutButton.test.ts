import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';

const source = readFileSync(new URL('./LogoutButton.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const handlers = ['submit', 'dispose'].map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  if (!node) throw new Error('Actual logout lifecycle handler is missing');
  return source.slice(node.start, node.end);
});
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(handlers.join('\n'));
const bind = new Function('env', `with (env) { ${code}; return { submit, dispose }; }`);
const failure = 'Unable to confirm sign out. Please try again.';

function fixture() {
  const calls: any[] = [], navigations: string[] = [];
  let prevented = 0, nextTimer = 0;
  const timers = new Map<number, { callback: () => void; delay: number }>();
  const env: any = {
    busy: false, error: null, disposed: false, request: null, AbortController,
    setTimeout: (callback: () => void, delay: number) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout: (id: number) => { timers.delete(id); },
    fetch: (url: string, options: RequestInit) => new Promise((resolve, reject) => {
      options.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
      calls.push({ url, options, resolve, reject });
    }),
    window: { location: { assign: (url: string) => { navigations.push(url); } } }
  };
  const actions = bind(env);
  const event = { preventDefault: () => { prevented++; } };
  return { env, calls, navigations, timers, send: () => actions.submit(event), dispose: actions.dispose, prevented: () => prevented };
}

function astNodes(root: any): any[] {
  const result: any[] = [];
  function visit(value: any) {
    if (!value || typeof value !== 'object') return;
    if (typeof value.type === 'string') result.push(value);
    for (const child of Object.values(value)) {
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object') visit(child);
    }
  }
  visit(root);
  return result;
}
function attribute(node: any, name: string): any {
  return node.attributes?.find((item: any) => item.type === 'Attribute' && item.name === name)?.value;
}
function textAttribute(node: any, name: string): string | undefined {
  const value = attribute(node, name);
  return Array.isArray(value) && value.length === 1 && value[0].type === 'Text' ? value[0].data : undefined;
}
function binding(node: any, name: string): string | undefined {
  const value = attribute(node, name);
  const expression = Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value;
  return expression?.type === 'ExpressionTag' && expression.expression.type === 'Identifier' ? expression.expression.name : undefined;
}

test('actual logout handler requests HTML redirect following and waits for the successful final response', async () => {
  const f = fixture(), pending = f.send();
  expect(f.prevented()).toBe(1); expect(f.env.busy).toBe(true); expect(f.env.error).toBeNull();
  expect(f.calls).toHaveLength(1);
  expect(f.calls[0].url).toBe('/auth/logout');
  expect(f.calls[0].options).toEqual({ method: 'POST', mode: 'cors', credentials: 'same-origin', headers: { Accept: 'text/html' }, redirect: 'follow', signal: f.calls[0].options.signal });
  expect(f.calls[0].options.signal).toBeInstanceOf(AbortSignal); expect(f.calls[0].options.signal.aborted).toBe(false);
  expect(f.navigations).toEqual([]);
  f.calls[0].resolve({ ok: true, status: 200, redirected: true, url: 'https://hash.example.test/', text: () => { throw new Error('HTML body must not be read'); } });
  await pending;
  expect(f.navigations).toEqual(['/']); expect(f.env.busy).toBe(true); expect(f.env.error).toBeNull(); expect(f.timers.size).toBe(0); expect(f.env.request).toBeNull();
});

test('actual logout failure hides response bodies and raw network errors and permits a deliberate retry', async () => {
  for (const kind of ['http', 'network']) {
    const f = fixture(), pending = f.send();
    if (kind === 'http') f.calls[0].resolve({ ok: false, status: 403, text: () => { throw new Error('PRIVATE response'); } });
    else f.calls[0].reject(new Error('PRIVATE https://issuer.invalid/?code=private-code session=private-cookie'));
    await pending;
    expect(f.navigations).toEqual([]); expect(f.env.busy).toBe(false); expect(f.env.error).toBe(failure);
    const retry = f.send(); expect(f.env.busy).toBe(true); expect(f.env.error).toBeNull(); expect(f.calls).toHaveLength(2);
    f.calls[1].resolve({ ok: true, status: 200, redirected: true }); await retry;
    expect(f.navigations).toEqual(['/']); expect(f.env.error).toBeNull();
  }
});

test('pending and confirmed logout submissions cannot dispatch duplicate revocations', async () => {
  const f = fixture(), pending = f.send();
  await f.send(); expect(f.calls).toHaveLength(1); expect(f.prevented()).toBe(2);
  f.calls[0].resolve({ ok: true, status: 200, redirected: true }); await pending;
  await f.send(); expect(f.calls).toHaveLength(1); expect(f.prevented()).toBe(3); expect(f.navigations).toEqual(['/']);
});

test('a 303 response that was not followed is not accepted as a successful final response', async () => {
  const f = fixture(), pending = f.send(); f.calls[0].resolve({ ok: false, status: 303, redirected: false }); await pending;
  expect(f.navigations).toEqual([]); expect(f.env.busy).toBe(false); expect(f.env.error).toBe(failure);
});

test('a navigation exception remains fail-soft and leaves the same accessible retry state', async () => {
  const f = fixture(); f.env.window.location.assign = () => { throw new Error('PRIVATE navigation failure'); };
  const pending = f.send(); f.calls[0].resolve({ ok: true, status: 200, redirected: true }); await pending;
  expect(f.env.busy).toBe(false); expect(f.env.error).toBe(failure); expect(f.navigations).toEqual([]);
  const retry = f.send(); f.calls[1].reject(new Error('PRIVATE transport failure')); await retry;
  expect(f.calls).toHaveLength(2); expect(f.env.error).toBe(failure);
});

test('logout timeout and unmount abort the actual request and retire their owned timer without stale navigation', async () => {
  for (const unmount of [false, true]) {
    const f = fixture(), pending = f.send();
    expect(f.timers.size).toBe(1); const timer = [...f.timers.values()][0]; expect(timer.delay).toBe(10_000);
    if (unmount) f.dispose(); else timer.callback();
    await pending;
    expect(f.calls[0].options.signal.aborted).toBe(true); expect(f.timers.size).toBe(0); expect(f.env.request).toBeNull(); expect(f.navigations).toEqual([]);
    expect(f.env.error).toBe(unmount ? null : failure);
    if (unmount) { await f.send(); expect(f.calls).toHaveLength(1); }
    else { const retry = f.send(); f.calls[1].resolve({ ok: true, status: 200, redirected: true }); await retry; expect(f.navigations).toEqual(['/']); expect(f.timers.size).toBe(0); }
  }
});

test('shared logout form binds the actual submit handler, busy controls and accessible fixed-error output', () => {
  const hook = tree.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression.type === 'CallExpression' && node.expression.callee.name === 'onDestroy');
  expect(hook.expression.arguments[0].name).toBe('dispose');
  const nodes = astNodes(tree), form = nodes.find(node => node.type === 'RegularElement' && node.name === 'form');
  const button = nodes.find(node => node.type === 'RegularElement' && node.name === 'button');
  expect(textAttribute(form, 'method')).toBe('POST'); expect(textAttribute(form, 'action')).toBe('/auth/logout');
  expect(binding(form, 'onsubmit')).toBe('submit'); expect(binding(form, 'aria-busy')).toBe('busy');
  expect(textAttribute(button, 'type')).toBe('submit'); expect(binding(button, 'disabled')).toBe('busy');
  const alert = nodes.find(node => node.type === 'RegularElement' && textAttribute(node, 'role') === 'alert');
  expect(alert).toBeDefined(); expect(alert.fragment.nodes.some((node: any) => node.type === 'ExpressionTag' && node.expression.name === 'error')).toBe(true);
});

for (const [route, compact] of [['+layout.svelte', true], ['+page.svelte', false]] as const) {
  test(`${route} integrates the shared logout component with its existing button size`, () => {
    const text = readFileSync(new URL(`../../routes/${route}`, import.meta.url), 'utf8');
    const parsed: any = parse(text, { modern: true });
    const imported = parsed.instance.content.body.find((node: any) => node.type === 'ImportDeclaration' && node.source.value === '$lib/components/LogoutButton.svelte');
    expect(imported).toBeDefined(); expect(imported.specifiers).toHaveLength(1); expect(imported.specifiers[0].local.name).toBe('LogoutButton');
    const nodes = astNodes(parsed), callers = nodes.filter(node => node.type === 'Component' && node.name === 'LogoutButton');
    expect(callers).toHaveLength(1); expect(attribute(callers[0], 'compact') === true).toBe(compact);
    expect(nodes.filter(node => node.type === 'RegularElement' && node.name === 'form' && textAttribute(node, 'action') === '/auth/logout')).toHaveLength(0);
  });
}
