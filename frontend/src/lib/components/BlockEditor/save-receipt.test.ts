import { expect, test } from 'bun:test';
import * as decoding from 'lib0/decoding';
import * as encoding from 'lib0/encoding';
import { isNewerSaveReceipt, readCanonicalSaveReceipt } from './save-receipt';
function wire(generation:string,at='2026-10-05T12:00:00.123456Z',trailing=false){
 const e=encoding.createEncoder();encoding.writeVarString(e,generation);encoding.writeVarString(e,at);
 if(trailing)encoding.writeVarUint(e,1);return decoding.createDecoder(encoding.toUint8Array(e));
}
test('canonical receipt preserves timestamp microseconds and bigint; reordered receipts ignored',()=>{
 const receipt=readCanonicalSaveReceipt(wire('9007199254740993'));
 expect(receipt.updatedAt).toBe('2026-10-05T12:00:00.123456Z');
 expect(isNewerSaveReceipt('9007199254740992',receipt)).toBe(true);
 expect(isNewerSaveReceipt('9007199254740993',receipt)).toBe(false);
 expect(isNewerSaveReceipt('9007199254740994',receipt)).toBe(false);
});
test('canonical receipt rejects malformed generation/timestamp and trailing data',()=>{
 for(const g of ['0','01','9223372036854775808'])expect(()=>readCanonicalSaveReceipt(wire(g))).toThrow();
 expect(()=>readCanonicalSaveReceipt(wire('1','invalid'))).toThrow();
 expect(()=>readCanonicalSaveReceipt(wire('1',undefined,true))).toThrow();
});
