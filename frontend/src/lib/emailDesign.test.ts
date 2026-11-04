import { expect, test } from 'bun:test';
import { defaultEmailDesign, readEmailDesign, emailDesignProblem, emailDesignDraft, localEmailLogo } from './emailDesign';

test('design bounds validate source, canonical fields, native slot and embedded logo shape', () => {
  const design = defaultEmailDesign(); expect(readEmailDesign(JSON.stringify(design))).toEqual(design);
  expect(readEmailDesign('')).toBeNull(); expect(readEmailDesign(undefined)).toBeNull();
  for (const patch of [{ schema_version: 2 }, { primary: '#ABCDEF' }, { text: 'red' }, { layout_html: '<p>No slot</p>' },
    { layout_html: '<div>{{native_content}}{{native_content}}</div>' }, { logo_alt: 'å'.repeat(101) }, { extra: true }, { logo: { url: 'https://example.invalid/logo' } }]) {
    expect(emailDesignProblem(JSON.stringify({ ...design, ...patch }))).toBeTruthy();
  }
  expect(emailDesignProblem(' '.repeat(131073))).toContain('large');
});
test('an incomplete authored layout stays visible while its missing native slot is explained', () => {
  const source = JSON.stringify({ ...defaultEmailDesign(), layout_html: '<div>Work in progress</div>' });
  expect(emailDesignDraft(source).layout_html).toBe('<div>Work in progress</div>');
  expect(emailDesignProblem(source)).toContain('required content slot');
});
test('local logo refuses unsupported media and size before reading bytes or decoding', async () => {
  for (const file of [new File(['<svg/>'], 'logo.svg', { type: 'image/svg+xml' }), new File([new Uint8Array(32769)], 'logo.png', { type: 'image/png' })]) {
    await expect(localEmailLogo(file)).rejects.toThrow('local PNG or JPEG');
  }
});
test('local logo verifies dimensions, closes the decoder and commits exact bytes without network', async () => {
  const oldBitmap = globalThis.createImageBitmap, oldFetch = globalThis.fetch;
  let closed = 0; globalThis.fetch = (() => { throw new Error('Unexpected network'); }) as typeof fetch;
  globalThis.createImageBitmap = (async () => ({ width: 512, height: 16, close() { closed++; } })) as typeof createImageBitmap;
  try {
    const logo = await localEmailLogo(new File([new Uint8Array([1, 2, 3])], 'local.png', { type: 'image/png' }));
    expect(logo.data_base64).toBe('AQID'); expect(logo.sha256).toBe('039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'); expect(closed).toBe(1);
    globalThis.createImageBitmap = (async () => ({ width: 513, height: 1, close() { closed++; } })) as typeof createImageBitmap;
    await expect(localEmailLogo(new File(['x'], 'large.png', { type: 'image/png' }))).rejects.toThrow(); expect(closed).toBe(2);
  } finally { globalThis.createImageBitmap = oldBitmap; globalThis.fetch = oldFetch; }
});
