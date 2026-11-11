import { expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDocument, getTimeline } from './client';

const traversal = '../data-subject/export?email=ceo@customer.test';

function capture(): { urls: string[]; restore: () => void } {
  const urls: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    urls.push(String(input));
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  return { urls, restore: () => { globalThis.fetch = real; } };
}

test('a route param with a traversal payload cannot leave /api/v1/documents/', async () => {
  const c = capture();
  try {
    await getDocument(traversal).catch(() => {});
    await getDocument('..%2Fdata-subject%2Fexport').catch(() => {});
    await getTimeline(traversal).catch(() => {});
  } finally { c.restore(); }
  expect(c.urls.length).toBeGreaterThanOrEqual(3);
  for (const url of c.urls) {
    const resolved = new URL(url, 'https://hash.test');
    expect(resolved.origin).toBe('https://hash.test');
    expect(resolved.pathname.startsWith('/api/v1/documents/')).toBe(true);
    const segments = resolved.pathname.split('/');
    expect(segments.includes('data-subject')).toBe(false);
    expect(segments.includes('..')).toBe(false);
    expect(segments.slice(0, 4)).toEqual(['', 'api', 'v1', 'documents']);
    expect(resolved.search).toBe('');
  }
});

test('no source file interpolates a bare id into an /api/v1 path', () => {
  const offenders: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (/\.(ts|svelte)$/.test(entry.name) && !/\.test\./.test(entry.name)) {
        for (const [i, line] of readFileSync(path, 'utf8').split('\n').entries()) {
          for (const m of line.matchAll(/`[^`\n]*\/api\/v1\/[^`\n]*`/g)) {
            const path_ = m[0].slice(m[0].indexOf('/api/v1/'))
              .replace(/\$\{(?:encodeURIComponent\([^)]*\)|qs|commentQuery\([^)]*\)|[^}]*\? *'[^']*' *: *'[^']*')\}/g, '').split('?')[0];
            if (path_.includes('${')) offenders.push(`${path}:${i + 1}`);
          }
        }
      }
    }
  };
  walk(fileURLToPath(new URL('../../', import.meta.url)));
  expect(offenders).toEqual([]);
});
