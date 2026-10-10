import { expect, test } from 'bun:test';
import { assetByteLength, blankHTMLAuthorDraft, draftFromHTMLTemplate, htmlAssetFromFile, htmlAuthorFingerprint, htmlAuthorInput } from './htmlAuthor';
import type { HTMLAsset } from './htmlTemplate';

function draft() {
  return { ...blankHTMLAuthorDraft(), name: 'Reusable design', html: '<p><span data-hash-value="company"></span></p><div data-hash-section="scope"></div>',
    css: 'p { color: #123456; }', values: [{ key: 1, name: 'company', required: true, max_chars: 100, default_value: '' }],
    sections: [{ key: 2, name: 'scope', max_chars: 100, default_text: 'Approved <text> & terms' }] };
}
function asset(bytes: Uint8Array, name = 'logo'): HTMLAsset {
  return { name, media_type: 'image/png', data_base64: Buffer.from(bytes).toString('base64'), sha256: 'a'.repeat(64) };
}

test('author input keeps approved source, declared defaults and wording separate, without local row keys', () => {
  const input = htmlAuthorInput(draft());
  expect(input.variables_json).toEqual({ company: '' });
  expect(input.html_master_json.values).toEqual([{ name: 'company', required: true, max_chars: 100 }]);
  expect(input.html_master_json.sections).toEqual([{ name: 'scope', default_text: 'Approved <text> & terms', max_chars: 100 }]);
  expect(input.html_master_json.html).toBe(draft().html);
  const recovered = draftFromHTMLTemplate({ ...input, id: 'design', org_id: 'org', source_kind: 'html', version: 1, content_sha256: 'b'.repeat(64) } as any);
  expect(htmlAuthorFingerprint(recovered)).toBe(htmlAuthorFingerprint(draft()));
  recovered.values[0].key = 500;
  expect(htmlAuthorFingerprint(recovered)).toBe(htmlAuthorFingerprint(draft()));
  recovered.values[0].default_value = 'Changed printed default';
  expect(htmlAuthorFingerprint(recovered)).not.toBe(htmlAuthorFingerprint(draft()));
});

test('author rejects duplicate/unknown declaration names, invalid Unicode and encoded source bounds', () => {
  for (const mutate of [
    (d: ReturnType<typeof draft>) => d.values.push({ ...d.values[0], key: 3 }),
    (d: ReturnType<typeof draft>) => { d.values[0].name = 'Company'; },
    (d: ReturnType<typeof draft>) => { d.values[0].default_value = '\ud800'; },
    (d: ReturnType<typeof draft>) => { d.sections[0].max_chars = 0; },
    (d: ReturnType<typeof draft>) => { d.html = 'é'.repeat(150_000); },
    (d: ReturnType<typeof draft>) => { d.css = 'a'.repeat(128 * 1024 + 1); },
  ]) { const input = draft(); mutate(input); expect(() => htmlAuthorInput(input)).toThrow(); }
  const input = draft(); input.values[0].max_chars = 1; input.values[0].default_value = '😀';
  expect(htmlAuthorInput(input).variables_json.company).toBe('😀');
  input.values[0].default_value += 'a'; expect(() => htmlAuthorInput(input)).toThrow();
});

test('base64 validation is linear at the actual 2 MiB boundary and refuses malformed/canonical padding', () => {
  const bytes = new Uint8Array(2 * 1024 * 1024); bytes.fill(255);
  const local = asset(bytes);
  expect(assetByteLength(local)).toBe(bytes.length);
  const input = draft(); input.assets = [local]; expect(htmlAuthorInput(input).html_master_json.assets).toEqual([local]);
  for (const value of ['A===', 'AA=A', 'AB==', 'AAB=', '====', 'AAA', 'AAAA\n', 'AA-_']) {
    expect(() => assetByteLength({ ...local, data_base64: value })).toThrow();
  }
  expect(assetByteLength({ ...local, data_base64: 'AA==' })).toBe(1);
  expect(assetByteLength({ ...local, data_base64: 'AAA=' })).toBe(2);
  expect(assetByteLength({ ...local, data_base64: 'AAAA' })).toBe(3);
  input.assets = [asset(new Uint8Array(2 * 1024 * 1024 + 1))]; expect(() => htmlAuthorInput(input)).toThrow();
  input.assets = Array.from({ length: 5 }, (_, i) => ({ ...local, name: `logo_${i}` })); expect(() => htmlAuthorInput(input)).toThrow('8 MiB');
});

test('local assets are size-bounded before reading, content-sniffed, SHA-bound and never browser-decoded', async () => {
  let reads = 0;
  await expect(htmlAssetFromFile({ size: 2 * 1024 * 1024 + 1, arrayBuffer() { reads++; return Promise.resolve(new ArrayBuffer(0)); } } as File, 'logo', [])).rejects.toThrow('2 MiB');
  expect(reads).toBe(0);
  const bytes = Uint8Array.of(137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3);
  const added = await htmlAssetFromFile(new File([bytes], 'logo.png', { type: 'application/javascript' }), 'logo', []);
  expect(added.media_type).toBe('image/png');
  expect(added.sha256).toBe(new Bun.CryptoHasher('sha256').update(bytes).digest('hex'));
  expect(Buffer.from(added.data_base64, 'base64')).toEqual(Buffer.from(bytes));
  for (const file of [new File([bytes], 'wrong.svg'), new File(['<script>'], 'wrong.png'), new File(['wOF2x'], 'font.woff')]) {
    await expect(htmlAssetFromFile(file, 'other', [])).rejects.toThrow('matching content');
  }
  await expect(htmlAssetFromFile(new File([bytes], 'logo.png'), 'logo', [added])).rejects.toThrow('unique');
  const font = await htmlAssetFromFile(new File(['wOF2bounded'], 'font.woff2'), 'body_font', []);
  expect(font.media_type).toBe('font/woff2');
});
