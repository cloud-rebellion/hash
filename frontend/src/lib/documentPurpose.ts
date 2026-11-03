export type DocumentPurpose = 'document' | 'presentation' | 'signing';
export function isDocumentPurpose(value: unknown): value is DocumentPurpose {
  return value === 'document' || value === 'presentation' || value === 'signing';
}
// The server resolves legacy metadata. A missing or malformed response is never
// client-side permission to show or dispatch a signing workflow.
export function documentPurpose(value: unknown): DocumentPurpose | null {
  return isDocumentPurpose(value) ? value : null;
}
export function requireDocumentPurpose(value: unknown): DocumentPurpose {
  if (!isDocumentPurpose(value)) throw new Error('Choose how this document will be used.');
  return value;
}
export function purposeLabel(value: unknown): string {
  return value === 'document' ? 'Document' : value === 'presentation' ? 'Presentation' : value === 'signing' ? 'Signing' : 'Purpose unavailable';
}

// Display capability only; the native writer still validates the complete
// current tree in its transaction. Never infer non-signing support from a
// missing, malformed or unbounded template body.
export function blockTemplateNeedsSigning(value: unknown): boolean | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const tree = value as { version?: unknown; blocks?: unknown };
  if (tree.version !== 1 || !Array.isArray(tree.blocks)) return null;
  const fields = new Set(['signature_field', 'initial_field', 'text_field', 'date_field', 'checkbox']);
  const pending: { rows: unknown[]; depth: number }[] = [{ rows: tree.blocks, depth: 0 }], seen = new WeakSet<object>();
  let count = 0;
  while (pending.length) {
    const { rows, depth } = pending.pop()!;
    if (depth > 64 || rows.length > 20000 - count) return null;
    for (const item of rows) {
      if (++count > 20000 || !item || typeof item !== 'object' || Array.isArray(item) || seen.has(item)) return null;
      seen.add(item);
      const block = item as { type?: unknown; content?: unknown };
      if (typeof block.type !== 'string' || !block.type) return null;
      if (fields.has(block.type)) return true;
      if (block.content !== undefined) {
        if (!Array.isArray(block.content)) return null;
        pending.push({ rows: block.content, depth: depth + 1 });
      }
    }
  }
  return false;
}
