import { expect, test } from 'bun:test';
import { previewLines, thumbnailTurn } from './documentThumbnail';

test('content previews use actual source text, preserve order and never mount active HTML or asset URLs', () => {
  expect(previewLines({ blocks: [{ text: 'Agreement' }, { text: 'First clause' }, { rows: [['Price', '100 SEK']] }] })).toEqual(['Agreement', 'First clause', 'Price · 100 SEK']);
  expect(previewLines({ html: '<h1>Our agreement</h1><script>private()</script><style>body{color:red}</style><p>Terms &amp; conditions</p><img src="https://private.invalid/pixel">' }, true)).toEqual(['Our agreement', 'Terms & conditions']);
  expect(previewLines({ html: '<p>{{company_name}}</p>' }, true)).toEqual(['{{company_name}}']);
  expect(previewLines(null)).toEqual([]);
});

test('content projection stays bounded for oversized or cyclic input', () => {
  const cyclic: Record<string, unknown> = {}; cyclic.content = cyclic;
  expect(previewLines(cyclic)).toEqual([]);
  const lines = previewLines({ blocks: Array.from({ length: 2000 }, () => ({ text: 'a'.repeat(2000) })) });
  expect(lines).toHaveLength(12); expect(lines.every(line => line.length <= 180)).toBe(true);
});

test('thumbnail jobs have two active slots, cancelled waiters do not run, release is idempotent', async () => {
  const first = await thumbnailTurn(new AbortController().signal);
  const second = await thumbnailTurn(new AbortController().signal);
  const cancelled = new AbortController();
  const rejected = thumbnailTurn(cancelled.signal).catch(error => error);
  let started = false;
  const waiting = thumbnailTurn(new AbortController().signal).then(release => { started = true; return release; });
  await Promise.resolve(); expect(started).toBe(false);
  cancelled.abort(); expect((await rejected).name).toBe('AbortError');
  first(); first();
  const third = await waiting; expect(started).toBe(true);
  third(); second();
  const closed = new AbortController(); closed.abort();
  await expect(thumbnailTurn(closed.signal)).rejects.toThrow('Preview closed');
  const next = await thumbnailTurn(new AbortController().signal); next();
});
