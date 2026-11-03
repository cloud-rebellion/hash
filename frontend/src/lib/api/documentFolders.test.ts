import { expect, test } from 'bun:test';
import { APIError, listDocuments, listDocumentFolders, createDocumentFolder, renameDocumentFolder, deleteDocumentFolder, moveDocumentFolder } from './client';

async function mocked(run: (calls: { path: string; options: RequestInit }[]) => Promise<void>, response: () => Response) {
  const original = globalThis.fetch, calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: RequestInfo | URL, options: RequestInit = {}) => { calls.push({ path: String(path), options }); return response(); }) as typeof fetch;
  try { await run(calls); } finally { globalThis.fetch = original; }
}

test('document lists preserve the old no-options request and send one server folder/status scope before pagination', async () => {
  await mocked(async calls => {
    await listDocuments(); expect(calls[0].path).toBe('/api/v1/documents');
    const signal = new AbortController().signal;
    await listDocuments({ folder: 'unfiled', status: 'completed', limit: 24, offset: 48 }, signal);
    const url = new URL(calls[1].path, 'https://hash.example');
    expect([...url.searchParams]).toEqual([['limit','24'],['offset','48'],['folder_id','unfiled'],['status','completed']]);
    expect(calls[1].options).toMatchObject({ method:'GET',credentials:'include',signal });
    await listDocuments({ folder:'all',status:'all',limit:24,offset:0 });
    expect(calls[2].path).toBe('/api/v1/documents?limit=24&offset=0');
  }, () => Response.json({documents:[],total:0}));
});

test('folder endpoints encode identities, carry only documented bodies and explicitly unfile with null', async () => {
  await mocked(async calls => {
    const signal = new AbortController().signal;
    await listDocumentFolders(25, 25, signal);
    await createDocumentFolder('  Customers  ');
    await renameDocumentFolder('folder/unsafe', ' Partners ');
    await moveDocumentFolder('document/unsafe', 'folder');
    await moveDocumentFolder('document', null);
    await deleteDocumentFolder('folder/unsafe');
    expect(calls.map(c=>[c.options.method,c.path])).toEqual([
      ['GET','/api/v1/document-folders?limit=25&offset=25'],['POST','/api/v1/document-folders'],
      ['PATCH','/api/v1/document-folders/folder%2Funsafe'],['PUT','/api/v1/documents/document%2Funsafe/folder'],
      ['PUT','/api/v1/documents/document/folder'],['DELETE','/api/v1/document-folders/folder%2Funsafe']
    ]);
    expect(calls[0].options.signal).toBe(signal);
    expect(calls.every(c=>c.options.credentials==='include')).toBe(true);
    expect(calls.slice(1,5).map(c=>JSON.parse(String(c.options.body)))).toEqual([{name:'Customers'},{name:'Partners'},{folder_id:'folder'},{folder_id:null}]);
    expect(calls[5].options.body).toBeUndefined();
  }, () => Response.json({}));
});

test('invalid pagination refuses before dispatch and folder conflict/permissions keep the real HTTP status', async () => {
  await mocked(async calls => {
    for (const [limit,offset] of [[0,0],[501,0],[25,-1],[1.5,0],[25,Number.NaN]]) await expect(listDocumentFolders(limit,offset)).rejects.toThrow('Invalid page.');
    expect(calls).toHaveLength(0);
  },()=>Response.json({}));
  for(const status of [403,404,409,503]) await mocked(async calls=>{
    try { await deleteDocumentFolder('f'); throw new Error('unexpected success'); }
    catch(error) { expect(error).toBeInstanceOf(APIError); expect((error as APIError).status).toBe(status); }
    expect(calls).toHaveLength(1);
  },()=>Response.json({error:status===409?'move the documents before deleting this folder':'refused'},{status}));
});
