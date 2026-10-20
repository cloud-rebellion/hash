// Thin wrapper around pdf.js so the field designer and the signer page share
// one PDF rendering path. Browser-only: call from onMount, never during SSR.
import * as pdfjsLib from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { checkedCanvasSize } from './pdfViewport';
import { PdfLoad } from './pdfLoad';
import { pdfCanvasBudget, type CanvasGeneration, type PaintOptions } from './pdfCanvas';

pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl;

export type PdfDoc = Awaited<ReturnType<typeof pdfjsLib.getDocument>['promise']>;

// The document object is only an opaque generation key, never a credential or
// source URL in the allocation ledger. The original loading promise is retained.
const canvasOwners = new WeakMap<PdfDoc, CanvasGeneration>();
function ownPdf(create: () => ReturnType<typeof pdfjsLib.getDocument>): PdfLoad<PdfDoc> {
  const generation = pdfCanvasBudget.generation();
  let task: ReturnType<typeof pdfjsLib.getDocument>;
  try { task = create(); } catch (error) { pdfCanvasBudget.retired(generation); throw error; }
  const load = new PdfLoad(task, {
    closing: () => pdfCanvasBudget.closing(generation),
    retired: () => pdfCanvasBudget.retired(generation),
    failed: () => pdfCanvasBudget.retirementFailed(generation),
  });
  void task.promise.then(doc => { canvasOwners.set(doc, generation); }, () => {});
  return load;
}
export function startPdf(url: string): PdfLoad<PdfDoc> {
  return ownPdf(() => pdfjsLib.getDocument({ url, withCredentials: true }));
}
export function startPdfData(data: Uint8Array): PdfLoad<PdfDoc> {
  return ownPdf(() => pdfjsLib.getDocument({ data }));
}
function canvasOwner(doc: PdfDoc): CanvasGeneration {
  const generation = canvasOwners.get(doc);
  if (!generation) throw new Error('This PDF has no preview owner. Reopen the document.');
  return generation;
}
export function recyclePage(doc: PdfDoc, canvas: HTMLCanvasElement): boolean {
  return pdfCanvasBudget.recycle(canvasOwner(doc), canvas);
}
export function pageIsResident(doc: PdfDoc, canvas: HTMLCanvasElement): boolean {
  return pdfCanvasBudget.resident(canvasOwner(doc), canvas);
}
// Stable CSS geometry is measured before mounting or recycling backing stores.
export async function pageGeometry(doc: PdfDoc, num: number): Promise<{ num: number; w: number; h: number; scale: number }> {
  const page = await doc.getPage(num);
  const natural = page.getViewport({ scale: 1 });
  const scale = Math.min(760 / natural.width, 2);
  const viewport = page.getViewport({ scale });
  const size = checkedCanvasSize(viewport.width, viewport.height, scale);
  return { num, w: size.width, h: size.height, scale };
}

// renderPage paints page `pageNumber` into `canvas` at `scale` and returns the
// rendered pixel size so the caller can size the field overlay to match.
export async function renderPage(
  doc: PdfDoc,
  pageNumber: number,
  canvas: HTMLCanvasElement,
  scale: number,
  options: PaintOptions = {},
): Promise<{ width: number; height: number }> {
  const page = await doc.getPage(pageNumber);
  const viewport = page.getViewport({ scale });
  const dimensions = checkedCanvasSize(viewport.width, viewport.height, scale);
  const lease = await pdfCanvasBudget.acquire(canvasOwner(doc), canvas, dimensions.width, dimensions.height, options);
  try {
    // A queued owner may have been retired between grant and this continuation.
    lease.assertCurrent();
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('canvas 2d context unavailable');
    canvas.width = dimensions.width;
    canvas.height = dimensions.height;
    const task = page.render({ canvas, canvasContext: ctx, viewport });
    lease.observe(task.promise);
    await task.promise;
    return dimensions;
  } finally { lease.finish(); }
}

// unscaledWidth returns a page's natural width in PDF points so a caller can
// compute the scale that fits a target pixel width.
export async function unscaledWidth(doc: PdfDoc, pageNumber: number): Promise<number> {
  const page = await doc.getPage(pageNumber);
  return page.getViewport({ scale: 1 }).width;
}
