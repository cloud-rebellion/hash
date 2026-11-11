import { expect, test } from 'bun:test';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pdfjsSource, pdfjsTarget, syncPdfjsAssets } from '../../scripts/sync-pdfjs-assets.mjs';

function files(dir: string, prefix = ''): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? files(join(dir, e.name), `${prefix}${e.name}/`) : [`${prefix}${e.name}`]);
}

test('the committed pdf.js decoders, CMaps and fonts are byte-identical to the installed pdfjs-dist', () => {
  const copied = files(pdfjsTarget);
    for (const required of ['wasm/jbig2.wasm', 'wasm/jbig2_nowasm_fallback.js', 'wasm/openjpeg.wasm', 'wasm/openjpeg_nowasm_fallback.js', 'wasm/qcms_bg.wasm', 'cmaps/UniGB-UCS2-H.bcmap', 'cmaps/90ms-RKSJ-H.bcmap', 'cmaps/Adobe-Japan1-UCS2.bcmap', 'standard_fonts/FoxitDingbats.pfb', 'standard_fonts/FoxitSymbol.pfb', 'standard_fonts/LiberationSans-Regular.ttf']) expect(copied).toContain(required);
    for (const name of copied) expect(Buffer.compare(readFileSync(join(pdfjsTarget, name)), readFileSync(join(pdfjsSource, name)))).toBe(0);
  const expected = mkdtempSync(join(tmpdir(), 'hash-pdfjs-'));
  try {
    syncPdfjsAssets(expected);
    expect(copied.sort()).toEqual(files(expected).sort());
  } finally { rmSync(expected, { recursive: true, force: true }); }
});
