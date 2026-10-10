import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

// Invoke the actual component callbacks so secret-clearing and confirmation are
// tested at their user-facing dispatch boundary, not a duplicated UI model.
const source = readFileSync(new URL('./CRMConnectionSettings.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  async function refresh()'), end = source.indexOf('  beforeNavigate(', start);
if (start < 0 || end < 0) throw new Error('CRM connection component callbacks missing');
const callbacks = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
function fixture() {
  const calls: { action: string; value?: unknown }[] = [];
  const env = { token: 'a'.repeat(64), pin: 'captured_connection_pin', revokeConfirmed: true,
    controller: {
      refresh: async () => { calls.push({ action: 'refresh' }); },
      configure: async (value: string) => { calls.push({ action: 'configure', value }); },
      enable: async () => { calls.push({ action: 'enable' }); },
      revoke: async (value: string) => { calls.push({ action: 'revoke', value }); },
      interrupt: () => { calls.push({ action: 'interrupt' }); },
    } };
  const bound = new Function('env', `with(env) { ${callbacks}; return { refresh, configure, enable, revoke, interrupt }; }`)(env);
  return { env, calls, bound };
}
test('actual submit clears its password before the request settles and only passes the captured key', async () => {
  const f = fixture(); let settle!: () => void;
  f.env.controller.configure = (value) => { f.calls.push({ action: 'configure', value }); return new Promise<void>((resolve) => { settle = resolve; }); };
  let prevented = false;
  const pending = f.bound.configure({ preventDefault: () => { prevented = true; } });
  expect(prevented).toBe(true); expect(f.env.token).toBe(''); expect(f.env.revokeConfirmed).toBe(false);
  expect(f.calls).toEqual([{ action: 'configure', value: 'a'.repeat(64) }]);
  f.env.token = 'b'.repeat(64); settle(); await pending;
  expect(f.calls[0].value).toBe('a'.repeat(64));
});
test('actual revoke requires explicit confirmation and captures the reviewed connection pin', async () => {
  const f = fixture(); f.env.revokeConfirmed = false; await f.bound.revoke(); expect(f.calls).toHaveLength(0);
  f.env.revokeConfirmed = true; await f.bound.revoke();
  expect(f.calls).toEqual([{ action: 'revoke', value: 'captured_connection_pin' }]);
  expect(f.env.token).toBe(''); expect(f.env.revokeConfirmed).toBe(false);
});
test('actual navigation and refresh callbacks clear secret and revoke confirmation before dispatch', async () => {
  const f = fixture(); f.bound.interrupt();
  expect(f.env.token).toBe(''); expect(f.env.revokeConfirmed).toBe(false); expect(f.calls[0].action).toBe('interrupt');
  f.env.token = 'a'.repeat(64); f.env.revokeConfirmed = true; await f.bound.refresh();
  expect(f.env.token).toBe(''); expect(f.env.revokeConfirmed).toBe(false); expect(f.calls[1].action).toBe('refresh');
});
