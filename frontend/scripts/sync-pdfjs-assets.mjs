// Copies the pdf.js decoders, CMaps and standard fonts from node_modules into static/pdfjs/ so they are served
// same-origin. The copies are committed because the frontend audit pins the build script and Vite config.
// Run this after changing pdfjs-dist; src/lib/pdfjsAssets.test.ts fails if they drift.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
export const pdfjsSource = join(root, 'node_modules', 'pdfjs-dist');
export const pdfjsTarget = join(root, 'static', 'pdfjs');
// quickjs-eval (PDF form scripting) is not used, so it is not shipped.
const skip = new Set(['quickjs-eval.js', 'quickjs-eval.wasm']);

export function syncPdfjsAssets(target = pdfjsTarget) {
  if (!existsSync(join(pdfjsSource, 'cmaps'))) throw new Error('pdfjs-dist is not installed; run bun install');
  rmSync(target, { recursive: true, force: true });
  for (const dir of ['wasm', 'cmaps', 'standard_fonts']) {
    mkdirSync(join(target, dir), { recursive: true });
    for (const name of readdirSync(join(pdfjsSource, dir))) if (!skip.has(name)) cpSync(join(pdfjsSource, dir, name), join(target, dir, name));
  }
}
if (import.meta.main) syncPdfjsAssets();
