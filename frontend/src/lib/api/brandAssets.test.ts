import { afterEach, expect, test } from 'bun:test';
import { prepareBrandAsset, uploadBrandAsset, listBrandAssets, inspectBrandAssetUpload, brandAssetContentURL, checkedBrandAsset, type PreparedBrandAsset } from './brandAssets';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });
const signal = () => new AbortController().signal;
const id = '22222222-2222-4222-8222-222222222222';
async function prepared() { return prepareBrandAsset('Real logo', new File([new Uint8Array([1, 2, 3, 4])], 'logo.png', { type: 'image/png' })); }
function asset(p: PreparedBrandAsset) {
  const original = { version_id: 'original-version', sha256: p.originalSHA, bytes: p.originalBytes, media_type: p.input.media_type, width: 1, height: 1 };
  return { asset_id: id, revision: 1, name: p.input.name, original, render: { ...original, version_id: 'render-version', sha256: p.renderSHA, bytes: p.renderBytes, media_type: 'image/png' }, render_method: 'original_png_v1', created_at: '2026-11-04T12:00:00Z' };
}
function fake(value: unknown, status = 200) {
  const calls: { url: string; init: RequestInit }[] = [];
  globalThis.fetch = (async (url, init) => { calls.push({ url: String(url), init: init! }); return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } }); }) as typeof fetch;
  return calls;
}
test('uploads retain exact original bytes and verify stored original/render hashes', async () => {
  const p = await prepared(); const expected = asset(p); const calls = fake(expected, 201);
  expect(await uploadBrandAsset(p, signal())).toEqual(expected);
  expect(calls[0]).toMatchObject({ url: '/api/v1/brand-assets', init: { method: 'POST', credentials: 'include', cache: 'no-store', redirect: 'error' } });
  const body = JSON.parse(calls[0].init.body as string);
  expect(body.request_id).toBe(p.input.request_id); expect(atob(body.original_base64)).toBe('\x01\x02\x03\x04');
  fake({ ...expected, original: { ...expected.original, sha256: 'f'.repeat(64) } });
  await expect(uploadBrandAsset(p, signal())).rejects.toThrow('differs');
});
test('file bounds and SVG companion requirement are checked before any request', async () => {
  const calls = fake({});
  await expect(prepareBrandAsset('', new File(['x'], 'a.png'))).rejects.toThrow();
  await expect(prepareBrandAsset('Vector', new File(['<svg></svg>'], 'a.svg'))).rejects.toThrow('PNG');
  await expect(prepareBrandAsset('Logo', new File([new Uint8Array(8 * 1024 ** 2 + 1)], 'a.png'))).rejects.toThrow('limit');
  await expect(prepareBrandAsset('Logo', new File(['x'], 'a.zip'))).rejects.toThrow('SVG or PNG');
  const vector = new File(['<svg></svg>'], 'a.svg', { type: 'image/svg+xml' });
  const variant = new File(['png'], 'a.png', { type: 'image/png' });
  const p = await prepareBrandAsset('Vector', vector, variant);
  expect(atob(p.input.original_base64)).toBe('<svg></svg>'); expect(atob(p.input.render_png_base64!)).toBe('png');
  expect(calls).toHaveLength(0);
});
test('uncertain uploads are not automatically repeated and explicit retry retains request identity', async () => {
  const p = await prepared(); const calls = fake({ private_provider_error: 'hidden' }, 503);
  await expect(uploadBrandAsset(p, signal())).rejects.toThrow('not confirmed'); expect(calls).toHaveLength(1);
  await expect(uploadBrandAsset(p, signal())).rejects.toThrow();
  expect(JSON.parse(calls[0].init.body as string)).toEqual(JSON.parse(calls[1].init.body as string));
});
test('status inspection is read only and binds the exact immutable asset revision', async () => {
  const p = await prepared(); let calls = fake({ request_id: p.input.request_id, state: 'preparing' });
  expect(await inspectBrandAssetUpload(p, signal())).toBeNull(); expect(calls[0].init.method).toBe('GET');
  const a = asset(p); const paths: string[] = [];
  globalThis.fetch = (async (url, init) => { paths.push(String(url)); expect(init?.method).toBe('GET');
    return new Response(JSON.stringify(paths.length === 1 ? { request_id: p.input.request_id, state: 'committed', asset_id: id, revision: 1 } : a), { headers: { 'content-type': 'application/json' } }); }) as typeof fetch;
  expect(await inspectBrandAssetUpload(p, signal())).toEqual(a); expect(paths[1]).toBe(`/api/v1/brand-assets/${id}?revision=1`);
});
test('catalogue and download URLs reject foreign shapes and path injection', async () => {
  const p = await prepared(); const a = asset(p); fake({ assets: [a] });
  expect(await listBrandAssets(signal())).toEqual([a]);
  expect(brandAssetContentURL(a, 'render')).toBe(`/api/v1/brand-assets/${id}/revisions/1/content?representation=render`);
  for (const bad of [{ ...a, asset_id: '../private' }, { ...a, revision: -1 }, { ...a, original: { ...a.original, version_id: '' } }, { ...a, render: { ...a.render, width: 4096, height: 4096 } }]) expect(() => checkedBrandAsset(bad)).toThrow();
  fake({ assets: [a, a] }); await expect(listBrandAssets(signal())).rejects.toThrow('Duplicate');
});
