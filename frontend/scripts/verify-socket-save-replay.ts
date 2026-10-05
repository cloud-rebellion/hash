// Verify real Go WebSocket checkpoint frames with installed Yjs/y-protocols.
import * as Y from 'yjs';
import * as decoding from 'lib0/decoding';
import * as encoding from 'lib0/encoding';
import * as sync from 'y-protocols/sync';

const path = process.argv[2];
if (!path) throw new Error('Pass verbose Go socket-save test output');
const output = await Bun.file(path).text();
const match = output.match(/YJS_SOCKET_SAVE_FRAMES=(\[[^\n]+\])/);
if (!match || !output.includes('--- PASS: TestCollabTwoSocketCanonicalSaveAndReconnectE2E')) {
  throw new Error('Passing real socket-save evidence missing');
}
const frames = JSON.parse(match[1]) as number[][];
const doc = new Y.Doc();
try {
  for (const frame of frames) {
    const decoder = decoding.createDecoder(Uint8Array.from(frame));
    if (decoding.readVarUint(decoder) !== 0) throw new Error('Unexpected message');
    sync.readSyncMessage(decoder, encoding.createEncoder(), doc, null);
    if (decoding.hasContent(decoder)) throw new Error('Trailing replay bytes');
  }
  if (doc.getText('test').toString() !== 'first second') throw new Error('Socket save lost Yjs content');
  if (frames.length !== 2 || frames[0][1] !== sync.messageYjsUpdate ||
      frames[1][1] !== sync.messageYjsSyncStep2) throw new Error('Premature checkpoint sync completion');
  console.log('PASS: authenticated Go socket checkpoint/save replay retains real Yjs text "first second"');
} finally { doc.destroy(); }
