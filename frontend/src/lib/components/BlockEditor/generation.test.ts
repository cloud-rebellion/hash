import { expect, test } from 'bun:test';
import * as encoding from 'lib0/encoding';
import * as decoding from 'lib0/decoding';
import { observeCanonicalGeneration, readCanonicalGeneration } from './generation';

function frame(value: string, trailing = false) {
  const encoder = encoding.createEncoder();
  encoding.writeVarString(encoder, value);
  if (trailing) encoding.writeVarUint(encoder, 1);
  return decoding.createDecoder(encoding.toUint8Array(encoder));
}

test('generation preserves full PostgreSQL bigint precision', () => {
  for (const value of ['1', '9007199254740993', '9223372036854775807']) {
    expect(readCanonicalGeneration(frame(value))).toBe(value);
  }
});

test('generation rejects invalid, overflow and trailing payloads', () => {
  for (const value of ['0', '-1', '01', '1.0', ' 1', '', '9223372036854775808', '10000000000000000000']) {
    expect(() => readCanonicalGeneration(frame(value))).toThrow();
  }
  expect(() => readCanonicalGeneration(frame('1', true))).toThrow();
  expect(() => readCanonicalGeneration(decoding.createDecoder(new Uint8Array([19, 49])))).toThrow();
});

test('reconnect accepts its same generation but requires recovery for another', () => {
  expect(observeCanonicalGeneration(null, '3')).toBe('3');
  expect(observeCanonicalGeneration('3', '3')).toBe('3');
  expect(() => observeCanonicalGeneration('3', '4')).toThrow('preserve draft');
});

test('decodes the Go GenerationFrame wire format without precision loss', () => {
  const payload = new TextEncoder().encode('9223372036854775807');
  const wire = new Uint8Array([6, 19, ...payload]);
  const decoder = decoding.createDecoder(wire);
  expect(decoding.readVarUint(decoder)).toBe(6);
  expect(readCanonicalGeneration(decoder)).toBe('9223372036854775807');
});
