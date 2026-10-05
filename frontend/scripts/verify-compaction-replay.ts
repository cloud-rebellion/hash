import * as Y from 'yjs';
import * as decoding from 'lib0/decoding';
import * as encoding from 'lib0/encoding';
import * as sync from 'y-protocols/sync';

const path = process.argv[2];
if (!path) throw new Error('Pass the verbose Go compaction test output path');
const output = await Bun.file(path).text();
const match = output.match(/YJS_COMPACTION_FRAMES=(\[[^\n]+\])/);
if (!match) throw new Error('Go compaction replay evidence missing');
const frames = JSON.parse(match[1]) as number[][];
const doc = new Y.Doc();
try {
  for (const frame of frames) {
    const decoder = decoding.createDecoder(Uint8Array.from(frame));
    if (decoding.readVarUint(decoder) !== 0) throw new Error('Unexpected wire message');
    sync.readSyncMessage(decoder, encoding.createEncoder(), doc, null);
    if (decoding.hasContent(decoder)) throw new Error('Unconsumed wire bytes');
  }
  if (doc.getText('test').toString() !== 'first second') {
    throw new Error(`Compaction lost content: ${doc.getText('test').toString()}`);
  }
  if (frames.length !== 2 || frames[0][1] !== sync.messageYjsUpdate ||
      frames[1][1] !== sync.messageYjsSyncStep2) throw new Error('Premature sync completion');
  console.log('PASS: Go compacted replay preserves real Yjs text "first second"');
} finally { doc.destroy(); }
