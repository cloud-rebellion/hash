import * as Y from 'yjs';
import * as decoding from 'lib0/decoding';

export const MESSAGE_BOOTSTRAP = 5;

export function readBootstrapGrant(decoder: decoding.Decoder): boolean {
  const grant = decoding.readVarUint(decoder);
  if (grant > 1 || decoding.hasContent(decoder)) throw new Error('Invalid initialization grant');
  return grant === 1;
}

// Empty visible content may be an intentional, replicated deletion. Seed only
// a document with no Yjs history; tombstones remain visible in its state vector.
export function shouldBootstrap(doc: Y.Doc): boolean {
  return doc.getXmlFragment('default').length === 0 &&
    Y.decodeStateVector(Y.encodeStateVector(doc)).size === 0;
}

export function bootstrapIfGranted(doc: Y.Doc, granted: boolean, seed: () => void): boolean {
  if (!granted || !shouldBootstrap(doc)) return false;
  seed();
  return true;
}
