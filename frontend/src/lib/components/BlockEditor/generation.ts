import * as decoding from 'lib0/decoding';

export const MESSAGE_GENERATION = 6;
const MAX_GENERATION = 9223372036854775807n;

// Keep the database int64 as a decimal string, never a JavaScript number.
export function readCanonicalGeneration(decoder: decoding.Decoder): string {
  const value = decoding.readVarString(decoder);
  if (!/^[1-9][0-9]{0,18}$/.test(value) ||
      BigInt(value) > MAX_GENERATION || decoding.hasContent(decoder)) {
    throw new Error('Invalid canonical generation');
  }
  return value;
}

export function observeCanonicalGeneration(current: string | null, next: string): string {
  if (current !== null && current !== next) {
    throw new Error('Canonical generation changed; preserve draft and reload');
  }
  return next;
}
