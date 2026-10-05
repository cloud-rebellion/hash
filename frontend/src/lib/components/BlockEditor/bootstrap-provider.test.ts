import { expect, test } from 'bun:test';
import * as Y from 'yjs';
import { WebsocketProvider } from 'y-websocket';
import * as encoding from 'lib0/encoding';
import * as decoding from 'lib0/decoding';
import * as sync from 'y-protocols/sync';
import { bootstrapIfGranted, MESSAGE_BOOTSTRAP, readBootstrapGrant } from './bootstrap';

class Socket {
  onmessage?: (event: { data: Uint8Array }) => void;
  onopen?: () => void;
  onclose?: () => void;
  send() {}
  close() {}
}

test('actual provider dispatch respects grant before sync and reassignment after sync', () => {
  for (const initialGrant of [false, true]) {
    const doc = new Y.Doc(); const server = new Y.Doc();
    const provider = new WebsocketProvider('ws://localhost', 'bootstrap-test', doc, {
      connect: false, disableBc: true, WebSocketPolyfill: Socket as unknown as typeof WebSocket
    });
    let granted = false;
    const seed = () => doc.getXmlFragment('default').insert(0, [new Y.XmlElement('paragraph')]);
    provider.messageHandlers[MESSAGE_BOOTSTRAP] = (_encoder, decoder) => {
      granted = readBootstrapGrant(decoder);
      if (provider.synced) bootstrapIfGranted(doc, granted, seed);
    };
    provider.on('sync', (synced: boolean) => { if (synced) bootstrapIfGranted(doc, granted, seed); });
    try {
      provider.connect();
      const socket = provider.ws as unknown as Socket;
      socket.onopen!();
      socket.onmessage!({ data: new Uint8Array([MESSAGE_BOOTSTRAP, Number(initialGrant)]) });
      expect(doc.getXmlFragment('default').length).toBe(0);
      const encoder = encoding.createEncoder(); encoding.writeVarUint(encoder, 0);
      sync.writeSyncStep2(encoder, server);
      socket.onmessage!({ data: encoding.toUint8Array(encoder) });
      expect(provider.synced).toBe(true);
      expect(doc.getXmlFragment('default').length).toBe(Number(initialGrant));
      socket.onmessage!({ data: new Uint8Array([MESSAGE_BOOTSTRAP, 1]) });
      socket.onmessage!({ data: new Uint8Array([MESSAGE_BOOTSTRAP, 1]) });
      expect(doc.getXmlFragment('default').length).toBe(1);
    } finally { provider.destroy(); doc.destroy(); server.destroy(); }
  }
});

test('grant decoder rejects invalid values and trailing bytes', () => {
  for (const payload of [new Uint8Array([2]), new Uint8Array([1, 0])]) {
    expect(() => readBootstrapGrant(decoding.createDecoder(payload))).toThrow();
  }
});
