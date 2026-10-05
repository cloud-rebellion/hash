import { expect, test } from 'bun:test';
import * as decoding from 'lib0/decoding';
import * as encoding from 'lib0/encoding';
import { CheckpointRequests, checkpointRequest, readSaveCheckpoint } from './checkpoint';

function response(generation = '9223372036854775807', revision = '18446744073709551615', trailing = false) {
  const e = encoding.createEncoder();
  encoding.writeVarUint(e, 1);
  encoding.writeUint8Array(e, new Uint8Array(16).fill(17));
  for (const value of ['alice', generation, revision]) encoding.writeVarString(e, value);
  encoding.writeUint8Array(e, new Uint8Array(32).fill(171));
  if (trailing) encoding.writeVarUint(e, 1);
  return decoding.createDecoder(encoding.toUint8Array(e));
}

test('checkpoint request matches Go fixed nonce framing', () => {
  expect(Array.from(checkpointRequest(new Uint8Array(16).fill(17)))).toEqual([7, 0, ...Array(16).fill(17)]);
  expect(() => checkpointRequest(new Uint8Array(15))).toThrow();
});

test('checkpoint receipt retains exact generation/revision and correlation nonce', () => {
  const cp = readSaveCheckpoint(response());
  expect(cp.generation).toBe('9223372036854775807');
  expect(cp.revision).toBe('18446744073709551615');
  expect(cp.peerID).toBe('alice');
  expect(cp.token).toBe('ab'.repeat(32));
  expect(Array.from(cp.nonce)).toEqual(Array(16).fill(17));
});

test('checkpoint parser rejects overflow, noncanonical identity and trailing/truncated data', () => {
  for (const [generation, revision] of [['0', '0'], ['01', '0'], ['9223372036854775808', '0'], ['1', '18446744073709551616'], ['1', '-1'], ['1', '01']]) {
    expect(() => readSaveCheckpoint(response(generation, revision))).toThrow();
  }
  expect(() => readSaveCheckpoint(response('1', '0', true))).toThrow();
  expect(() => readSaveCheckpoint(decoding.createDecoder(new Uint8Array([1, 17])))).toThrow();
});

test('checkpoint correlator rejects late/unmatched receipts and serializes requests',async()=>{
 const requests=new CheckpointRequests();let sent:Uint8Array;
 const pending=requests.request(frame=>sent=frame);
 await expect(requests.request(()=>{})).rejects.toThrow('already pending');
 const cp={nonce:new Uint8Array(16),peerID:'alice',generation:'1',revision:'0',token:'ab'.repeat(32)};
 expect(requests.receive(cp)).toBe(false);
 cp.nonce=sent!.slice(2);
 expect(requests.receive(cp)).toBe(true);
 expect(await pending).toBe(cp);
 expect(requests.receive(cp)).toBe(false);
 const next=requests.request(()=>{});
 requests.cancel();await expect(next).rejects.toThrow('connection closed');
 expect(requests.receive(cp)).toBe(false);
});

test('checkpoint send failure and timeout preserve bounded request lifecycle',async()=>{
 const requests=new CheckpointRequests();
 await expect(requests.request(()=>{throw new Error('offline')})).rejects.toThrow('offline');
 await expect(requests.request(()=>{},1)).rejects.toThrow('timed out');
 const next=requests.request(()=>{});requests.cancel();await expect(next).rejects.toThrow();
});
