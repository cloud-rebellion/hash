import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import * as Y from 'yjs';
import { WebsocketProvider } from 'y-websocket';
import { MESSAGE_SAVED, isNewerSaveReceipt } from './save-receipt';

const source = readFileSync(new URL('./Editor.svelte', import.meta.url), 'utf8');
function production(startMarker: string, endMarker: string) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  if (start < 0 || end < 0) throw new Error(`Production code missing: ${startMarker}`);
  return new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end));
}

class Socket {
  send() {}
  close() {}
}

test('production provider constructor binds the exact canonical observation in its upgrade URL', () => {
  const doc = new Y.Doc();
  let receivedOptions: any;
  class ObservedProvider extends WebsocketProvider {
    constructor(base: string, room: string, ydoc: Y.Doc, options: any) {
      receivedOptions = options;
      super(base, room, ydoc, { ...options, connect: false, WebSocketPolyfill: Socket as unknown as typeof WebSocket });
    }
  }
  const constructor = production('    provider = new WebsocketProvider(', '\n\n    // Register our compact-request');
  const bind = new Function('env', `with(env){${constructor};return provider;}`);
  const observedAt = '2026-10-05T12:00:00.000001Z';
  const provider = bind({ provider: null, WebsocketProvider: ObservedProvider, wsBase: 'wss://hash.example.test/api/v1/documents/doc', ydoc: doc, doc: { updated_at: observedAt } }) as WebsocketProvider;
  try {
    expect(receivedOptions.params).toEqual({ expected_updated_at: observedAt });
    expect(receivedOptions.disableBc).toBe(true);
    expect(new URL(provider.url).searchParams.getAll('expected_updated_at')).toEqual([observedAt]);
    const acknowledgedAt = '2026-10-05T12:00:00.000002Z';
    provider.params.expected_updated_at = acknowledgedAt;
    expect(new URL(provider.url).searchParams.getAll('expected_updated_at')).toEqual([acknowledgedAt]);
  } finally { provider.destroy(); doc.destroy(); }
});

test('verified peer save receipt updates reconnect observation without replacing local content', () => {
  const code = production('    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_SAVED]', '\n\n    (provider as unknown as { messageHandlers: Array<unknown> }).messageHandlers[MESSAGE_GENERATION]');
  const bind = new Function('env', `with(env){${code};return provider.messageHandlers[MESSAGE_SAVED];}`);
  const env: any = {
    disposed: false, canonicalGeneration: '2', doc: { updated_at: 'old', blocks_json: 'local draft' },
    collaborationRejected: false, dirty: true, error: null, MESSAGE_SAVED, isNewerSaveReceipt,
    receipt: { generation: '3', updatedAt: '2026-10-05T12:00:00.000003Z' },
    readCanonicalSaveReceipt: () => env.receipt,
    provider: { params: { expected_updated_at: 'old' }, messageHandlers: [], disconnect: () => {} }
  };
  const handler = bind(env);
  handler(null, null);
  expect(env.doc.updated_at).toBe(env.receipt.updatedAt);
  expect(env.provider.params.expected_updated_at).toBe(env.receipt.updatedAt);
  expect(env.doc.blocks_json).toBe('local draft'); expect(env.dirty).toBe(true);
  env.receipt = { generation: '2', updatedAt: 'older' }; handler(null, null);
  expect(env.provider.params.expected_updated_at).toBe('2026-10-05T12:00:00.000003Z');
  env.disposed = true; env.receipt = { generation: '4', updatedAt: 'late' }; handler(null, null);
  expect(env.provider.params.expected_updated_at).toBe('2026-10-05T12:00:00.000003Z');
});

test('bounded queued reconnect cannot revive a disposed, conflicted or changed editor', () => {
  const code = production('  function queueCollaborationReconnect(', '\n  onMount(');
  const bind = new Function('env', `with(env){${code};return queueCollaborationReconnect;}`);
  for (const stop of [
    (env: any) => { env.disposed = true; },
    (env: any) => { env.saveConflict = true; },
    (env: any) => { env.collaborationRejected = true; },
    (env: any) => { env.doc.id = 'other'; }
  ]) {
    const timers: Array<{ callback: () => void; delay: number }> = [];
    const env: any = { disposed: false, saveConflict: false, collaborationRejected: false, doc: { id: 'doc' }, reconnectTimer: null,
      connects: 0, provider: { connect: () => env.connects++ },
      setTimeout: (callback: () => void, delay: number) => { timers.push({ callback, delay }); return timers.length; }
    };
    const queue = bind(env); queue('doc'); queue('doc');
    expect(timers).toHaveLength(1); expect(timers[0].delay).toBe(1000);
    stop(env); timers[0].callback(); expect(env.connects).toBe(0); expect(env.reconnectTimer).toBeNull();
  }
});
