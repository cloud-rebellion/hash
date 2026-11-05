import { APIError } from './client';

export interface BrandAssetObject {
  version_id: string; sha256: string; bytes: number; media_type: string; width: number; height: number;
}
export interface BrandAsset {
  asset_id: string; revision: number; name: string; original: BrandAssetObject; render: BrandAssetObject;
  render_method: string; created_at: string;
}
export interface BrandAssetUpload {
  request_id: string; expected_revision: 0; name: string; media_type: 'image/png' | 'image/svg+xml';
  original_base64: string; render_png_base64?: string;
}
export interface PreparedBrandAsset {
  input: BrandAssetUpload; originalSHA: string; renderSHA: string; originalBytes: number; renderBytes: number;
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const digest = /^[a-f0-9]{64}$/;
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const positive = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;
function checkedObject(v: unknown, render: boolean): v is BrandAssetObject {
  return object(v) && typeof v.version_id === 'string' && v.version_id.length > 0 && v.version_id.length <= 1024
    && typeof v.sha256 === 'string' && digest.test(v.sha256) && positive(v.bytes) && v.bytes <= (render ? 2 : 8) * 1024 ** 2
    && positive(v.width) && positive(v.height) && v.width <= 16384 && v.height <= 16384
    && (render ? v.media_type === 'image/png' && v.width * v.height <= 4194304 : ['image/png', 'image/svg+xml'].includes(String(v.media_type)));
}
export function checkedBrandAsset(v: unknown): BrandAsset {
  if (!object(v) || typeof v.asset_id !== 'string' || !uuid.test(v.asset_id) || !positive(v.revision)
    || typeof v.name !== 'string' || !v.name || new TextEncoder().encode(v.name).length > 160
    || !checkedObject(v.original, false) || !checkedObject(v.render, true)
    || !['original_png_v1', 'provided_png_v1'].includes(String(v.render_method)) || typeof v.created_at !== 'string') throw new Error('Invalid brand asset response');
  return v as unknown as BrandAsset;
}
async function request(method: 'GET' | 'POST', path: string, signal: AbortSignal, body?: BrandAssetUpload): Promise<unknown> {
  const r = await fetch(path, { method, credentials: 'include', cache: 'no-store', redirect: 'error', signal,
    headers: body ? { Accept: 'application/json', 'Content-Type': 'application/json' } : { Accept: 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  if (!r.ok) { await r.body?.cancel().catch(() => {}); throw new APIError(r.status, 'Brand asset request was not confirmed.'); }
  if (!r.headers.get('content-type')?.toLowerCase().startsWith('application/json')) { await r.body?.cancel(); throw new Error('Invalid brand asset response'); }
  const reader = r.body?.getReader(); if (!reader) throw new Error('Missing brand asset response');
  let size = 0; const chunks: Uint8Array[] = [];
  try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
    if (size > 256 * 1024) { await reader.cancel(); throw new Error('Brand asset response too large'); } chunks.push(part.value); }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
export async function listBrandAssets(signal: AbortSignal, after = ''): Promise<BrandAsset[]> {
  if (after && !uuid.test(after)) throw new Error('Invalid brand asset page');
  const r = await request('GET', '/api/v1/brand-assets?limit=50' + (after ? '&after=' + encodeURIComponent(after) : ''), signal);
  if (!object(r) || !Array.isArray(r.assets) || r.assets.length > 50) throw new Error('Invalid brand asset list');
  const assets = r.assets.map(checkedBrandAsset);
  if (new Set(assets.map(a => a.asset_id)).size !== assets.length) throw new Error('Duplicate brand asset');
  return assets;
}
export function brandAssetContentURL(asset: BrandAsset, representation: 'original' | 'render') {
  checkedBrandAsset(asset);
  return `/api/v1/brand-assets/${asset.asset_id}/revisions/${asset.revision}/content?representation=${representation}`;
}
async function fileData(file: File, max: number) {
  if (file.size < 1 || file.size > max) throw new Error('Brand asset file is outside the upload limit');
  const bytes = new Uint8Array(await file.arrayBuffer());
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  let binary = ''; for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return { base64: btoa(binary), sha: Array.from(hash, b => b.toString(16).padStart(2, '0')).join(''), size: bytes.length };
}
export async function prepareBrandAsset(name: string, original: File, render?: File): Promise<PreparedBrandAsset> {
  name = name.trim();
  if (!name || new TextEncoder().encode(name).length > 160 || /[\x00-\x1f\x7f]/.test(name)) throw new Error('Enter a short asset name');
  const svg = original.type === 'image/svg+xml' || /\.svg$/i.test(original.name);
  if (!svg && original.type !== 'image/png' && !/\.png$/i.test(original.name)) throw new Error('Choose an SVG or PNG original');
  if (svg && !render) throw new Error('Choose a PNG rendering variant for the SVG original');
  if (render && render.type !== 'image/png' && !/\.png$/i.test(render.name)) throw new Error('The rendering variant must be PNG');
  const a = await fileData(original, (svg ? 2 : 8) * 1024 ** 2);
  const b = render ? await fileData(render, 2 * 1024 ** 2) : a;
  return { input: { request_id: crypto.randomUUID(), expected_revision: 0, name, media_type: svg ? 'image/svg+xml' : 'image/png', original_base64: a.base64, ...(render ? { render_png_base64: b.base64 } : {}) }, originalSHA: a.sha, renderSHA: b.sha, originalBytes: a.size, renderBytes: b.size };
}
function matches(asset: BrandAsset, prepared: PreparedBrandAsset) {
  if (asset.original.sha256 !== prepared.originalSHA || asset.render.sha256 !== prepared.renderSHA
    || asset.original.bytes !== prepared.originalBytes || asset.render.bytes !== prepared.renderBytes
    || asset.original.media_type !== prepared.input.media_type) throw new Error('Stored brand asset differs from the selected files');
  return asset;
}
export async function uploadBrandAsset(prepared: PreparedBrandAsset, signal: AbortSignal): Promise<BrandAsset> {
  const asset = checkedBrandAsset(await request('POST', '/api/v1/brand-assets', signal, prepared.input));
  if (asset.revision !== 1) throw new Error('Unexpected new brand asset revision');
  return matches(asset, prepared);
}
export async function inspectBrandAssetUpload(prepared: PreparedBrandAsset, signal: AbortSignal): Promise<BrandAsset | null> {
  const id = prepared.input.request_id; if (!uuid.test(id)) throw new Error('Invalid upload reference');
  const result = await request('GET', `/api/v1/brand-assets/uploads/${id}`, signal);
  if (!object(result) || result.request_id !== id || !['preparing', 'committed'].includes(String(result.state))) throw new Error('Invalid upload state');
  if (result.state === 'preparing') return null;
  if (typeof result.asset_id !== 'string' || !uuid.test(result.asset_id) || !positive(result.revision)) throw new Error('Invalid uploaded asset identity');
  const asset = checkedBrandAsset(await request('GET', `/api/v1/brand-assets/${result.asset_id}?revision=${result.revision}`, signal));
  if (asset.asset_id !== result.asset_id || asset.revision !== result.revision) throw new Error('Uploaded asset revision changed');
  return matches(asset, prepared);
}
