import * as decoding from 'lib0/decoding';
import * as encoding from 'lib0/encoding';

export const MESSAGE_CHECKPOINT = 7;
export interface SaveCheckpointReceipt {
  nonce: Uint8Array;
  peerID: string;
  generation: string;
  revision: string;
  token: string;
}

export function checkpointRequest(nonce: Uint8Array): Uint8Array {
  if (nonce.length !== 16) throw new Error('Invalid checkpoint nonce');
  const encoder = encoding.createEncoder();
  encoding.writeVarUint(encoder, MESSAGE_CHECKPOINT);
  encoding.writeVarUint(encoder, 0);
  encoding.writeUint8Array(encoder, nonce);
  return encoding.toUint8Array(encoder);
}

export function readSaveCheckpoint(decoder: decoding.Decoder): SaveCheckpointReceipt {
  if (decoding.readVarUint(decoder) !== 1) throw new Error('Invalid checkpoint response');
  const nonce = new Uint8Array(decoding.readUint8Array(decoder, 16));
  const peerID = decoding.readVarString(decoder);
  const generation = decoding.readVarString(decoder);
  const revision = decoding.readVarString(decoder);
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(peerID) ||
      !/^[1-9][0-9]{0,18}$/.test(generation) || BigInt(generation) > 9223372036854775807n ||
      !/^(0|[1-9][0-9]{0,19})$/.test(revision) || BigInt(revision) > 18446744073709551615n) {
    throw new Error('Invalid checkpoint identity');
  }
  const tokenBytes = decoding.readUint8Array(decoder, 32);
  if (decoding.hasContent(decoder)) throw new Error('Trailing checkpoint data');
  const token = Array.from(tokenBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return { nonce, peerID, generation, revision, token };
}

// One outstanding request per editor, with bounded lifetime and exact nonce
// correlation. Closing/disposal rejects it before a reconnect can reuse it.
export class CheckpointRequests {
  private pending: { nonce: Uint8Array; resolve: (receipt: SaveCheckpointReceipt) => void;
    reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;

  request(send: (frame: Uint8Array) => void, timeoutMs = 5000): Promise<SaveCheckpointReceipt> {
    if (this.pending) return Promise.reject(new Error('Checkpoint request already pending'));
    return new Promise((resolve, reject) => {
      const nonce = crypto.getRandomValues(new Uint8Array(16));
      const timer = setTimeout(() => this.cancel(new Error('Collaboration checkpoint timed out; your draft is preserved')), timeoutMs);
      this.pending = { nonce, resolve, reject, timer };
      try { send(checkpointRequest(nonce)); } catch (error) { this.cancel(error as Error); }
    });
  }

  receive(receipt: SaveCheckpointReceipt): boolean {
    const pending = this.pending;
    if (!pending || receipt.nonce.length !== 16 || receipt.nonce.some((byte, index) => byte !== pending.nonce[index])) return false;
    clearTimeout(pending.timer);
    this.pending = null;
    pending.resolve(receipt);
    return true;
  }

  cancel(error = new Error('Collaboration connection closed; your draft is preserved')) {
    if (!this.pending) return;
    clearTimeout(this.pending.timer);
    const pending = this.pending;
    this.pending = null;
    pending.reject(error);
  }
}
