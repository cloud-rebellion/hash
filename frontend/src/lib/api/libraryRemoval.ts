export type LibraryItemKind = 'document' | 'template';

export class LibraryRemovalError extends Error {
  constructor(public outcome: 'refused' | 'unknown', message: string, public status?: number) { super(message); }
}

const conflicts: Record<string, string> = {
  'only draft documents can be deleted': 'Only drafts can be deleted. Sent and signed documents keep their evidence.',
  'draft evidence or sealing state requires review before deletion': 'This draft has retained signing evidence and cannot be deleted here.',
  'privacy review is changing; retry after it completes': 'A privacy review is changing. Wait for it to finish before deleting this draft.',
  'document deletion awaits the open privacy request review': 'This draft has an open privacy request. Complete that review before deleting it.',
};
async function conflictMessage(response: Response): Promise<string | undefined> {
  const reader = response.body?.getReader();
  if (!reader) return;
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    for (;;) {
      const part = await reader.read(); if (part.done) break;
      length += part.value.byteLength;
      if (length > 4096) return;
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (value && typeof value === 'object' && 'error' in value && typeof value.error === 'string') return conflicts[value.error];
  } catch { /* Only known public conflicts are displayed. */ }
  finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

// These are the existing native lifecycle actions: draft soft-delete and
// template archive. A missing acknowledgement never becomes a success claim.
export async function removeLibraryItem(kind: LibraryItemKind, id: string, signal: AbortSignal): Promise<void> {
  if ((kind !== 'document' && kind !== 'template') || !id || id.length > 256 || /[\u0000-\u001f\u007f]/u.test(id)) {
    throw new LibraryRemovalError('refused', 'Choose a saved document or template.');
  }
  let response: Response;
  try {
    response = await fetch(`/api/v1/${kind === 'document' ? 'documents' : 'templates'}/${encodeURIComponent(id)}`, {
      method: 'DELETE', signal, credentials: 'include', cache: 'no-store', redirect: 'error',
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new LibraryRemovalError('unknown', 'The result could not be confirmed. Reload the library before trying again.');
  }
  if (response.status === 204) return;
  if (response.status === 409) {
    const known = await conflictMessage(response);
    throw new LibraryRemovalError('refused', known ?? 'The item changed or is still in use. Reload the library before continuing.', 409);
  }
  await response.body?.cancel().catch(() => {});
  if (response.status === 401) throw new LibraryRemovalError('refused', 'Your session has expired. Please sign in again.', 401);
  if (response.status === 403) throw new LibraryRemovalError('refused', 'You do not have permission to do that.', 403);
  if (response.status === 404) throw new LibraryRemovalError('refused', 'The item is no longer available. Reload the library.', 404);
  if (response.status >= 400 && response.status < 500 && response.status !== 408) {
    throw new LibraryRemovalError('refused', 'The item could not be removed. Reload the library and check its current state.', response.status);
  }
  throw new LibraryRemovalError('unknown', 'The result could not be confirmed. Reload the library before trying again.', response.status);
}
