import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { consumeStaffAuthToken, staffPasswordError, type StaffAuthMode } from '../staffAuth';
import { staffAuthErrorMessage } from '../api/staffAuth';

const source = readFileSync(new URL('./StaffAuthForm.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const functions = ['clearSecrets', 'dispose', 'initialise', 'submit'].map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  if (!node) throw new Error('Actual native account lifecycle handler is missing');
  return source.slice(node.start, node.end);
});
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions.join('\n'));
const bind = new Function('env', `with (env) { ${code}; return { initialise, submit, dispose }; }`);

function fixture(mode: StaffAuthMode) {
  const calls: any[] = [], statusCalls: any[] = [], navigations: string[] = [], histories: unknown[][] = [];
  const timers = new Map<number, { callback: () => void; delay: number }>();
  let nextTimer = 0, prevented = 0;
  const operation = (name: string) => (...args: any[]) => new Promise<void>((resolve, reject) => {
    const signal = args[args.length - 1] as AbortSignal;
    signal.addEventListener('abort', () => reject(new Error('PRIVATE aborted input')), { once: true });
    calls.push({ name, args, signal, resolve, reject });
  });
  const env: any = {
    mode, tokenMode: mode === 'verify' || mode === 'reset', newPassword: mode === 'register' || mode === 'reset',
    email: ' owner@example.test ', name: ' Owner ', company: ' Example ', password: ' unchanged passphrase ', confirmation: ' unchanged passphrase ',
    token: null, busy: false, complete: false, error: null, oidcEnabled: false, disposed: false, request: null, statusRequest: null,
    consumeStaffAuthToken, staffPasswordError, staffAuthErrorMessage, AbortController,
    loginWithPassword: operation('login'), registerWorkspace: operation('register'), verifyStaffEmail: operation('verify'),
    forgotStaffPassword: operation('forgot'), resetStaffPassword: operation('reset'),
    getStaffAuthStatus: (signal: AbortSignal) => new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error('PRIVATE status')), { once: true });
      statusCalls.push({ signal, resolve, reject });
    }),
    setTimeout: (callback: () => void, delay: number) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout: (id: number) => { timers.delete(id); },
    window: {
      location: { pathname: mode === 'verify' ? '/verify-email' : '/reset-password', hash: '#token=' + 'TOKEN_'.repeat(9), search: '?returnTo=https://PRIVATE.invalid', assign: (path: string) => { navigations.push(path); } },
      history: { replaceState: (...args: unknown[]) => { histories.push(args); env.window.location.hash = ''; env.window.location.search = ''; } },
      get localStorage() { throw new Error('Passwords/tokens must never enter local storage'); },
      get sessionStorage() { throw new Error('Passwords/tokens must never enter session storage'); }
    }
  };
  const actions = bind(env);
  return { env, calls, statusCalls, navigations, histories, timers, initialise: actions.initialise, dispose: actions.dispose,
    send: () => actions.submit({ preventDefault() { prevented++; } }), prevented: () => prevented };
}

async function settle() { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }

test('actual login/register/forgot handlers submit captured values once and wait for acknowledgement', async () => {
  for (const mode of ['login', 'register', 'forgot'] as const) {
    const f = fixture(mode), pending = f.send();
    expect(f.prevented()).toBe(1); expect(f.env.busy).toBe(true); expect(f.calls).toHaveLength(1); expect(f.navigations).toEqual([]);
    expect(f.calls[0].name).toBe(mode);
    const values = f.calls[0].args.slice(0, -1);
    expect(values).toEqual(mode === 'login' ? ['owner@example.test', ' unchanged passphrase '] : mode === 'register' ? ['owner@example.test', 'Owner', 'Example', ' unchanged passphrase '] : ['owner@example.test']);
    await f.send(); expect(f.calls).toHaveLength(1);
    f.calls[0].resolve(); await pending;
    expect(f.env.complete).toBe(true); expect(f.env.password).toBe(''); expect(f.env.confirmation).toBe(''); expect(f.timers.size).toBe(0);
    expect(f.navigations).toEqual(mode === 'login' ? ['/dashboard'] : []);
    await f.send(); expect(f.calls).toHaveLength(1);
  }
});

test('verification/reset fragment is removed before use, remains outside DOM/history and posts only after deliberate submit', async () => {
  for (const mode of ['verify', 'reset'] as const) {
    const f = fixture(mode);
    f.initialise();
    expect(f.histories).toEqual([[null, '', mode === 'verify' ? '/verify-email' : '/reset-password']]);
    expect(f.env.window.location.hash).toBe(''); expect(f.env.window.location.search).toBe(''); expect(f.calls).toHaveLength(0);
    const pending = f.send();
    expect(f.calls).toHaveLength(1); expect(f.calls[0].name).toBe(mode); expect(f.calls[0].args[0]).toBe('TOKEN_'.repeat(9)); expect(f.navigations).toEqual([]);
    expect(f.calls[0].args[1]).toBe(' unchanged passphrase ');
    f.calls[0].resolve(); await pending;
    expect(f.navigations).toEqual([mode === 'verify' ? '/dashboard' : '/login']); expect(f.env.token).toBeNull(); expect(f.env.password).toBe('');
  }
});

test('verification requires the original password and preserves its link in memory after a refused attempt', async () => {
  const f = fixture('verify');
  f.initialise();
  expect(f.calls).toHaveLength(0);
  f.env.password = '';
  await f.send();
  expect(f.calls).toHaveLength(0); expect(f.env.error).toContain('password');
  f.env.password = ' incorrect original password ';
  const refused = f.send();
  expect(f.calls).toHaveLength(1);
  f.calls[0].reject(new Error('PRIVATE wrong password'));
  await refused;
  expect(f.env.busy).toBe(false); expect(f.env.complete).toBe(false);
  expect(f.env.token).toBe('TOKEN_'.repeat(9)); expect(f.env.window.location.hash).toBe('');
  expect(f.navigations).toEqual([]); expect(f.env.error).not.toContain('PRIVATE');
  f.env.password = ' correct original password ';
  const retry = f.send();
  expect(f.calls).toHaveLength(2); expect(f.calls[1].args.slice(0, -1)).toEqual(['TOKEN_'.repeat(9), ' correct original password ']);
  f.calls[1].resolve(); await retry;
  expect(f.navigations).toEqual(['/dashboard']); expect(f.env.token).toBeNull(); expect(f.env.password).toBe('');
});

test('invalid token, confirmation and password policy errors do not dispatch account mutations', async () => {
  const missing = fixture('verify'); missing.env.window.location.hash = '#token=bad'; missing.initialise(); await missing.send();
  expect(missing.calls).toHaveLength(0); expect(missing.histories).toHaveLength(1); expect(missing.env.error).not.toBeNull();
  for (const [password, confirmation] of [['short', 'short'], ['twelve characters', 'different'], ['🦊'.repeat(257), '🦊'.repeat(257)]]) {
    const f = fixture('register'); f.env.password = password; f.env.confirmation = confirmation; await f.send();
    expect(f.calls).toHaveLength(0); expect(f.env.busy).toBe(false); expect(f.env.error).not.toBeNull();
  }
});

test('SSO remains absent until actual typed status confirms it, and stale status cannot update an unmounted form', async () => {
  const f = fixture('login'); f.initialise();
  expect(f.env.oidcEnabled).toBe(false); expect(f.statusCalls).toHaveLength(1);
  f.statusCalls[0].resolve({ password_enabled: true, oidc_enabled: true }); await settle();
  expect(f.env.oidcEnabled).toBe(true); expect(f.timers.size).toBe(0);
  const stale = fixture('login'); stale.initialise(); stale.dispose(); stale.statusCalls[0].resolve({ password_enabled: true, oidc_enabled: true }); await settle();
  expect(stale.env.oidcEnabled).toBe(false); expect(stale.statusCalls[0].signal.aborted).toBe(true); expect(stale.timers.size).toBe(0);
});

test('network refusal, timeout and unmount retire owned requests without leaking diagnostics or stale navigation', async () => {
  for (const kind of ['network', 'timeout', 'unmount']) {
    const f = fixture('login'), pending = f.send();
    expect([...f.timers.values()][0].delay).toBe(15_000);
    if (kind === 'network') f.calls[0].reject(new Error('PRIVATE credentials and provider URL'));
    else if (kind === 'timeout') [...f.timers.values()][0].callback();
    else f.dispose();
    await pending;
    expect(f.navigations).toEqual([]); expect(f.timers.size).toBe(0); expect(f.env.request).toBeNull();
    if (kind === 'unmount') { expect(f.env.error).toBeNull(); expect(f.env.password).toBe(''); await f.send(); expect(f.calls).toHaveLength(1); }
    else { expect(f.env.busy).toBe(false); expect(f.env.error).not.toContain('PRIVATE'); }
  }
});

function nodes(value: any): any[] {
  if (!value || typeof value !== 'object') return [];
  return [...(typeof value.type === 'string' ? [value] : []), ...Object.values(value).flatMap(child => Array.isArray(child) ? child.flatMap(nodes) : nodes(child))];
}
function textAttribute(node: any, name: string): string | undefined {
  const value = node.attributes?.find((item: any) => item.type === 'Attribute' && item.name === name)?.value;
  return Array.isArray(value) && value.length === 1 && value[0].type === 'Text' ? value[0].data : undefined;
}
function binding(node: any, name: string): string | undefined {
  const value = node.attributes?.find((item: any) => item.type === 'Attribute' && item.name === name)?.value;
  const expression = Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value;
  return expression?.type === 'ExpressionTag' && expression.expression.type === 'Identifier' ? expression.expression.name : undefined;
}

test('all five actual routes mount the shared accessible POST form with appropriate password/autocomplete controls', () => {
  for (const [route, mode] of [['login', 'login'], ['register', 'register'], ['verify-email', 'verify'], ['forgot-password', 'forgot'], ['reset-password', 'reset']]) {
    const routeSource = readFileSync(new URL(`../../routes/${route}/+page.svelte`, import.meta.url), 'utf8');
    const routeTree: any = parse(routeSource, { modern: true });
    const forms = nodes(routeTree).filter(node => node.type === 'Component' && node.name === 'StaffAuthForm');
    expect(forms).toHaveLength(1); expect(textAttribute(forms[0], 'mode')).toBe(mode);
  }
  const all = nodes(tree), form = all.find(node => node.type === 'RegularElement' && node.name === 'form');
  expect(textAttribute(form, 'method')).toBe('POST');
  expect(binding(form, 'onsubmit')).toBe('submit'); expect(binding(form, 'aria-busy')).toBe('busy');
  for (const [hook, handler] of [['onMount', 'initialise'], ['onDestroy', 'dispose']]) {
    const registration = tree.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression.type === 'CallExpression' && node.expression.callee.name === hook);
    expect(registration?.expression.arguments[0].name).toBe(handler);
  }
  const password = all.find(node => node.type === 'RegularElement' && textAttribute(node, 'id') === 'staff-password');
  const confirmation = all.find(node => node.type === 'RegularElement' && textAttribute(node, 'id') === 'staff-confirmation');
  expect(textAttribute(password, 'type')).toBe('password'); expect(textAttribute(password, 'maxlength')).toBe('1024');
  const passwordGuard = all.find(node => node.type === 'IfBlock' && node.test?.type === 'LogicalExpression' && nodes(node).includes(password) && source.slice(node.test.start, node.test.end).includes("mode === 'verify'"));
  expect(passwordGuard).toBeDefined();
  const showsPassword = new Function('mode', 'newPassword', `return (${source.slice(passwordGuard.test.start, passwordGuard.test.end)});`);
  expect(showsPassword('verify', false)).toBe(true); expect(showsPassword('forgot', false)).toBe(false);
  const autocompleteValue = password.attributes.find((item: any) => item.type === 'Attribute' && item.name === 'autocomplete').value;
  const autocompleteExpression = (Array.isArray(autocompleteValue) ? autocompleteValue[0] : autocompleteValue).expression;
  const autocomplete = new Function('newPassword', `return (${source.slice(autocompleteExpression.start, autocompleteExpression.end)});`);
  expect(autocomplete(false)).toBe('current-password'); expect(autocomplete(true)).toBe('new-password');
  expect(textAttribute(confirmation, 'type')).toBe('password'); expect(textAttribute(confirmation, 'autocomplete')).toBe('new-password');
  expect(all.some(node => node.type === 'RegularElement' && textAttribute(node, 'role') === 'alert')).toBe(true);
  expect(all.some(node => node.type === 'RegularElement' && textAttribute(node, 'role') === 'status')).toBe(true);
  expect(all.filter(node => node.type === 'RegularElement' && node.name === 'input' && textAttribute(node, 'name') === 'token')).toHaveLength(0);
  const sso = all.find(node => node.type === 'IfBlock' && node.test?.name === 'oidcEnabled');
  expect(sso).toBeDefined(); expect(nodes(sso).some(node => node.type === 'RegularElement' && textAttribute(node, 'href') === '/auth/login')).toBe(true);
  expect(all.filter(node => node.type === 'RegularElement' && textAttribute(node, 'src'))).toHaveLength(0);
});
