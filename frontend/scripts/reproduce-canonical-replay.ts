// Diagnostic for an unresolved integrity requirement; not a passing acceptance test.
import * as Y from 'yjs';
import * as sync from 'y-protocols/sync';
import * as encoding from 'lib0/encoding';
import * as decoding from 'lib0/decoding';
import { bootstrapIfGranted } from '../src/lib/components/BlockEditor/bootstrap';

const stored = new Y.Doc();
const reconnected = new Y.Doc();
try {
  const paragraph = new Y.XmlElement('paragraph');
  const text = new Y.XmlText();
  text.insert(0, 'original contract');
  paragraph.insert(0, [text]);
  stored.getXmlFragment('default').insert(0, [paragraph]);
  const savedUpdate = Y.encodeStateAsUpdate(stored);
  // REST/MCP canonical replacement changes blocks_json; current SQL and room
  // loaders still retain this independent saved CRDT update.
  const canonicalReplacement = 'replacement contract';
  const frame = encoding.createEncoder();
  encoding.writeVarUint(frame, 0);
  sync.writeSyncStep2(frame, stored);
  const decoder = decoding.createDecoder(encoding.toUint8Array(frame));
  if (decoding.readVarUint(decoder) !== 0) throw new Error('Unexpected message');
  sync.readSyncMessage(decoder, encoding.createEncoder(), reconnected, null);
  if (decoding.hasContent(decoder)) throw new Error('Unread replay bytes');
  const seededReplacement = bootstrapIfGranted(reconnected, false, () => {
    throw new Error('Existing history must not receive a seed grant');
  });
  const actual = reconnected.getXmlFragment('default').toString();
  const reproduced = actual.includes('original contract') && !actual.includes(canonicalReplacement);
  const evidence = {
    status: reproduced ? 'UNRESOLVED_STALE_CANONICAL_REPLAY' : 'NOT_REPRODUCED',
    canonicalReplacement, replayedContent: actual, seededReplacement,
    persistedUpdateBytes: savedUpdate.length,
    scope: 'installed Yjs/y-protocols and production bootstrap policy; no DB or network acceptance'
  };
  const output = JSON.stringify(evidence, null, 2);
  console.log(output);
  const path = process.env.HASH_REPLAY_EVIDENCE;
  if (path) await Bun.write(path, output + '\n');
  // Nonzero distinguishes evidence of a known defect from acceptance success.
  process.exitCode = reproduced ? 2 : 1;
} finally {
  stored.destroy();
  reconnected.destroy();
}
