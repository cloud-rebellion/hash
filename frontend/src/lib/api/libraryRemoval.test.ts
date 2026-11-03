import { expect, test } from 'bun:test';
import { LibraryRemovalError, removeLibraryItem } from './libraryRemoval';

async function mocked(response: () => Response | Promise<Response>, run: (calls: { url: string; options: RequestInit }[]) => Promise<void>) {
  const original = globalThis.fetch, calls: { url: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (url: RequestInfo | URL, options: RequestInit) => { calls.push({ url: String(url), options }); return response(); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}
test('only native draft-delete and template-archive routes dispatch, with encoded IDs and no body or redirect', async () => {
  await mocked(() => new Response(null, { status: 204 }), async calls => {
    const signal = new AbortController().signal;
    await removeLibraryItem('document', 'doc/unsafe', signal); await removeLibraryItem('template', 'template/unsafe', signal);
    expect(calls.map(call => call.url)).toEqual(['/api/v1/documents/doc%2Funsafe', '/api/v1/templates/template%2Funsafe']);
    for (const call of calls) { expect(call.options).toMatchObject({ method: 'DELETE', credentials: 'include', cache: 'no-store', redirect: 'error', signal }); expect(call.options.body).toBeUndefined(); }
    for (const kind of ['folder', 'documents']) await expect(removeLibraryItem(kind as any, 'id', signal)).rejects.toThrow('Choose a saved');
    for (const id of ['', 'x'.repeat(257), 'bad\u0000id']) await expect(removeLibraryItem('document', id, signal)).rejects.toThrow('Choose a saved');
    expect(calls).toHaveLength(2);
  });
});
test('known native signing and privacy conflicts are actionable and never announce a deletion', async () => {
  for (const [error, fragment] of [
    ['only draft documents can be deleted', 'Only drafts'],
    ['draft evidence or sealing state requires review before deletion', 'retained signing evidence'],
    ['document deletion awaits the open privacy request review', 'open privacy request'],
    ['privacy review is changing; retry after it completes', 'privacy review is changing'],
  ]) await mocked(() => Response.json({ error }, { status: 409 }), async () => {
    try { await removeLibraryItem('document', 'id', new AbortController().signal); throw Error('unexpected success'); }
    catch (failure) { expect(failure).toBeInstanceOf(LibraryRemovalError); expect((failure as LibraryRemovalError).outcome).toBe('refused'); expect((failure as Error).message).toContain(fragment); }
  });
});
test('unknown server messages and large or invalid bodies never leak into UI errors', async () => {
  for (const body of ['<html>private upstream detail</html>', JSON.stringify({ error: 'private database detail' }), JSON.stringify({ error: 'x'.repeat(5000) })]) {
    await mocked(() => new Response(body, { status: 409 }), async () => {
      await expect(removeLibraryItem('template', 'id', new AbortController().signal)).rejects.toThrow('The item changed or is still in use.');
    });
  }
});
test('permissions and missing records remain refusals, not evidence that removal succeeded', async () => {
  for (const status of [400, 401, 403, 404, 429]) await mocked(() => new Response(null, { status }), async () => {
    try { await removeLibraryItem('document', 'id', new AbortController().signal); throw Error('unexpected success'); }
    catch (failure) { expect(failure).toBeInstanceOf(LibraryRemovalError); expect((failure as LibraryRemovalError).outcome).toBe('refused'); expect((failure as LibraryRemovalError).status).toBe(status); }
  });
});
test('ambiguous network, timeout, server failure and non-native success responses stay unknown', async () => {
  for (const status of [200, 202, 408, 500, 503]) await mocked(() => new Response(null, { status }), async () => {
    try { await removeLibraryItem('document', 'id', new AbortController().signal); throw Error('unexpected success'); }
    catch (failure) { expect(failure).toBeInstanceOf(LibraryRemovalError); expect((failure as LibraryRemovalError).outcome).toBe('unknown'); }
  });
  await mocked(() => { throw Error('secret local transport detail'); }, async () => {
    await expect(removeLibraryItem('template', 'id', new AbortController().signal)).rejects.toThrow('The result could not be confirmed.');
  });
});
