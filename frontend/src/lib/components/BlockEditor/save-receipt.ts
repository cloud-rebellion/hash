import * as decoding from 'lib0/decoding';

export const MESSAGE_SAVED = 8;
export interface CanonicalSaveReceipt { generation: string; updatedAt: string }

export function readCanonicalSaveReceipt(decoder: decoding.Decoder): CanonicalSaveReceipt {
  const generation = decoding.readVarString(decoder);
  const updatedAt = decoding.readVarString(decoder);
  if (!/^[1-9][0-9]{0,18}$/.test(generation) || BigInt(generation) > 9223372036854775807n ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(updatedAt) ||
      !Number.isFinite(Date.parse(updatedAt)) || decoding.hasContent(decoder)) {
    throw new Error('Invalid canonical save receipt');
  }
  return { generation, updatedAt };
}

// Receipts acknowledge persistence only; they never replace local content.
export function isNewerSaveReceipt(current: string | null, receipt: CanonicalSaveReceipt): boolean {
  return current === null || BigInt(receipt.generation) > BigInt(current);
}
