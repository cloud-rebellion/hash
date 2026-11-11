import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { cachedThumbnail, clearThumbnailCache, rememberThumbnail, thumbnailKey } from './documentThumbnail';

const pdf = { id: 'd1', name: 'A', source_kind: 'pdf', pdf_sha256: 'aaa' };

test('keys follow content identity: pdf hash, or updated_at for other kinds', () => {
  expect(thumbnailKey('document', pdf)).not.toBe(thumbnailKey('document', { ...pdf, pdf_sha256: 'bbb' }));
  expect(thumbnailKey('document', pdf)).toBe(thumbnailKey('document', { ...pdf, name: 'renamed', updated_at: 'later' }));
  expect(thumbnailKey('document', pdf)).not.toBe(thumbnailKey('template', pdf));
  const blocks = { id: 'd2', name: 'B', source_kind: 'blocks', updated_at: 't1' };
  expect(thumbnailKey('document', blocks)).not.toBe(thumbnailKey('document', { ...blocks, updated_at: 't2' }));
});
test('the cache is bounded, least recently used first, and clears on sign-out', () => {
  clearThumbnailCache();
  for (let i = 0; i < 70; i++) rememberThumbnail(`k${i}`, { lines: [String(i)] });
  expect(cachedThumbnail('k0')).toBeUndefined();
  expect(cachedThumbnail('k69')?.lines).toEqual(['69']);
  clearThumbnailCache();
  expect(cachedThumbnail('k69')).toBeUndefined();
});
test('thumbnails consult the cache before downloading, are never persisted, and sign-out clears them', () => {
  const view = readFileSync(new URL('./components/DocumentThumbnail.svelte', import.meta.url), 'utf8');
  expect(view.indexOf('cachedThumbnail(cacheKey)')).toBeLessThan(view.indexOf('fetchVerifiedDocumentPDF(source.id'));
  const cache = readFileSync(new URL('./documentThumbnail.ts', import.meta.url), 'utf8');
  expect(cache).not.toMatch(/localStorage|sessionStorage|indexedDB|caches\./);
  expect(readFileSync(new URL('./components/LogoutButton.svelte', import.meta.url), 'utf8')).toContain('clearThumbnailCache();');
});
