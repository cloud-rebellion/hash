import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('./Editor.svelte', import.meta.url), 'utf8');
const start = source.indexOf('  function sharedEditingRecovered(');
const end = source.indexOf('  function manualSave()', start);
if (start < 0 || end < 0) throw new Error('Editor recovery handlers missing');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
const bind = new Function('env', `with (env) { ${code}; return {sharedEditingRecovered, reloadRecoveredDocument}; }`);
function fixture() {
  const env: any = {
    disposed: false, doc: { id: 'doc' }, editRevision: 1, dirty: true,
    saveConflict: false, collaborationRejected: false, connected: true,
    saveTimer: null, clearTimeout, canceled: 0, disconnected: 0, reloads: 0,
    checkpointRequests: { cancel: () => env.canceled++ },
    provider: { disconnect: () => env.disconnected++ },
    window: { confirm: () => true, location: { reload: () => env.reloads++ } }
  };
  return { env, handlers: bind(env) };
}

test('shared recovery stops the old provider and preserves dirty editor content', () => {
  const { env, handlers } = fixture();
  handlers.sharedEditingRecovered('doc');
  expect(env.saveConflict).toBe(true); expect(env.collaborationRejected).toBe(true);
  expect(env.connected).toBe(false); expect(env.dirty).toBe(true);
  expect(env.canceled).toBe(1); expect(env.disconnected).toBe(1); expect(env.reloads).toBe(0);
});

test('reload requires current document/revision and a separate user confirmation', () => {
  const { env, handlers } = fixture();
  handlers.reloadRecoveredDocument('other', 1); handlers.reloadRecoveredDocument('doc', 0);
  expect(env.reloads).toBe(0); expect(env.dirty).toBe(true);
  env.window.confirm = () => false; handlers.reloadRecoveredDocument('doc', 1);
  expect(env.reloads).toBe(0); expect(env.dirty).toBe(true);
  env.window.confirm = () => { env.editRevision++; return true; };
  handlers.reloadRecoveredDocument('doc', 1);
  expect(env.reloads).toBe(0); expect(env.dirty).toBe(true);
  env.window.confirm = () => true; handlers.reloadRecoveredDocument('doc', 2);
  expect(env.reloads).toBe(1); expect(env.dirty).toBe(false);
});

test('disposed editor ignores recovery and reload callbacks', () => {
  const { env, handlers } = fixture(); env.disposed = true;
  handlers.sharedEditingRecovered('doc'); handlers.reloadRecoveredDocument('doc', 1);
  expect(env.saveConflict).toBe(false); expect(env.disconnected).toBe(0);
  expect(env.reloads).toBe(0); expect(env.dirty).toBe(true);
});
