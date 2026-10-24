import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { APIError } from '../api/client';

const source = readFileSync(new URL('../../routes/settings/members/+page.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(['sendInvitation', 'disposeInvitation'].map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  if (!node) throw new Error('Actual member invitation handler is absent');
  return source.slice(node.start, node.end);
}).join('\n'));
const bind = new Function('env', `with (env) { ${code}; return { sendInvitation, disposeInvitation }; }`);
const accepted = 'Invitation request accepted. Eligible accounts receive a password setup email.';

function fixture(isOwner = true) {
  const calls: any[] = [], timers = new Map<number, { callback: () => void; delay: number }>();
  let timerID = 0, refreshes = 0;
  const env: any = {
    isOwner, disposed: false, inviteEmail: 'invitee@example.test', inviteName: 'Invitee', inviteRole: 'sender',
    inviteBusy: false, inviteError: null, inviteMessage: null, invitationRequest: null, AbortController, APIError,
    setTimeout: (callback: () => void, delay: number) => { const id = ++timerID; timers.set(id, { callback, delay }); return id; },
    clearTimeout: (id: number) => { timers.delete(id); },
    refresh: async () => { refreshes++; },
    inviteMember: (input: unknown, signal: AbortSignal) => new Promise<void>((resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error('PRIVATE abort')), { once: true });
      calls.push({ input, signal, resolve, reject });
    })
  };
  const actions = bind(env);
  return { env, calls, timers, refreshes: () => refreshes, send: () => actions.sendInvitation({ preventDefault() {} }), dispose: actions.disposeInvitation };
}

test('owner invitation waits for202 semantics, prevents duplicate requests and then refreshes with generic acknowledgement', async () => {
  const f = fixture(), pending = f.send();
  expect(f.env.inviteBusy).toBe(true); expect(f.calls).toHaveLength(1); expect(f.env.inviteMessage).toBeNull(); expect(f.refreshes()).toBe(0);
  expect(f.calls[0].input).toEqual({ email: 'invitee@example.test', name: 'Invitee', role: 'sender' });
  await f.send(); expect(f.calls).toHaveLength(1);
  f.calls[0].resolve(); await pending;
  expect(f.env.inviteMessage).toBe(accepted); expect(f.refreshes()).toBe(1);
  expect(f.env.inviteEmail).toBe(''); expect(f.env.inviteName).toBe(''); expect(f.env.inviteRole).toBe('sender');
  expect(f.env.inviteBusy).toBe(false); expect(f.timers.size).toBe(0);
});

test('viewer/empty requests cannot dispatch and permission refusal refreshes current identity without claiming an invitation', async () => {
  const viewer = fixture(false); await viewer.send(); expect(viewer.calls).toHaveLength(0);
  const empty = fixture(); empty.env.inviteEmail = ' '; await empty.send(); expect(empty.calls).toHaveLength(0);
  const owner = fixture(), pending = owner.send(); owner.calls[0].reject(new APIError(403, 'Only workspace owners can invite members.')); await pending;
  expect(owner.env.inviteMessage).toBeNull(); expect(owner.env.inviteError).toContain('owners'); expect(owner.refreshes()).toBe(1); expect(owner.env.inviteEmail).toBe('invitee@example.test');
});

test('invitation timeout/unmount aborts owned work, clears its timer and suppresses stale acceptance', async () => {
  for (const unmount of [false, true]) {
    const f = fixture(), pending = f.send();
    expect([...f.timers.values()][0].delay).toBe(15_000);
    if (unmount) f.dispose(); else [...f.timers.values()][0].callback();
    await pending;
    expect(f.calls[0].signal.aborted).toBe(true); expect(f.env.inviteMessage).toBeNull(); expect(f.refreshes()).toBe(0); expect(f.timers.size).toBe(0); expect(f.env.invitationRequest).toBeNull();
    if (!unmount) expect(f.env.inviteError).not.toContain('PRIVATE');
    else { await f.send(); expect(f.calls).toHaveLength(1); }
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

test('actual owner-only member form exposes only name/email/role and binds the tested invitation lifecycle', () => {
  const all = nodes(tree), form = all.find(node => node.type === 'RegularElement' && node.name === 'form' && textAttribute(node, 'action') === '/api/v1/members');
  expect(form).toBeDefined(); expect(textAttribute(form, 'method')).toBe('POST');
  const ownerBlock = all.find(node => node.type === 'IfBlock' && node.test?.name === 'isOwner' && nodes(node).includes(form));
  expect(ownerBlock).toBeDefined();
  const fields = nodes(form).filter(node => node.type === 'RegularElement' && ['input', 'select'].includes(node.name));
  expect(fields.map(node => textAttribute(node, 'name')).sort()).toEqual(['email', 'name', 'role']);
  expect(fields.some(node => textAttribute(node, 'type') === 'password')).toBe(false);
  const submit = form.attributes.find((attribute: any) => attribute.name === 'onsubmit').value;
  expect((Array.isArray(submit) ? submit[0] : submit).expression.name).toBe('sendInvitation');
  const cleanup = tree.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression.type === 'CallExpression' && node.expression.callee.name === 'onDestroy');
  expect(cleanup.expression.arguments[0].name).toBe('disposeInvitation');
  const roles = tree.instance.content.body.find((node: any) => node.type === 'VariableDeclaration' && node.declarations[0]?.id.name === 'ROLES').declarations[0].init;
  expect(roles.elements.map((entry: any) => entry.properties.find((property: any) => property.key.name === 'value').value.value)).toEqual(['owner', 'sender', 'viewer']);
});
