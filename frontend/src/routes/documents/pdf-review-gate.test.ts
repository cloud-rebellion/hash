import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const page = readFileSync(new URL('./[id]/+page.svelte', import.meta.url), 'utf8');
const designer = readFileSync(new URL('../../lib/components/PdfFieldDesigner.svelte', import.meta.url), 'utf8');

test('a draft PDF with a pending HTML review shows only the review gate', () => {
  expect(page).toContain("{#if doc.status === 'draft' && doc.html_review_required}");
  expect(page).toContain("doc.html_review_required === true);");
  // The gate branch precedes, and therefore excludes, the designer and preview iframe branch.
  expect(page.indexOf('{:else if pdfReviewGate}')).toBeGreaterThan(0);
  expect(page.indexOf('{:else if pdfReviewGate}')).toBeLessThan(page.lastIndexOf("{:else if doc.status === 'draft' && doc.source_kind === 'pdf'}"));
  expect(page).toContain('disabled={pdfReviewGate} onclick={() => (showPreview = !showPreview)}');
});
test('after review the page shows a status line instead of the review card', () => {
  expect(page).toContain('{:else if doc.status === \'draft\' && doc.source_kind === \'pdf\'}\n        <p class="text-sm text-success mb-4" role="status">{$ui("This exact PDF has been reviewed.")}');
});
test('an unmounted designer clears its busy and dirty state so Send is not left blocked', () => {
  const destroy = designer.slice(designer.indexOf('onDestroy(() => {'));
  expect(destroy.slice(0, 300)).toContain('onStateChange?.({ busy: false, dirty: false })');
});
