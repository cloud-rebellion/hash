// Thin wrapper around pdf.js so the field designer and the signer page share
// one PDF rendering path. Browser-only: call from onMount, never during SSR.
import * as pdfjsLib from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { checkedCanvasSize } from './pdfViewport';
import { PdfLoad } from './pdfLoad';

pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl;

export type PdfDoc = Awaited<ReturnType<typeof pdfjsLib.getDocument>['promise']>;

// startPdf owns fetching/parsing immediately. withCredentials sends the session/magic-token
// cookie reaches the authed PDF endpoints.
export function startPdf(url: string): PdfLoad<PdfDoc> {
  return new PdfLoad(pdfjsLib.getDocument({ url, withCredentials: true }));
}

// Caller verifies these bytes against the observed server PDF commitment first.
export function startPdfData(data: Uint8Array): PdfLoad<PdfDoc> {
  return new PdfLoad(pdfjsLib.getDocument({ data }));
}

// renderPage paints page `pageNumber` into `canvas` at `scale` and returns the
// rendered pixel size so the caller can size the field overlay to match.
export async function renderPage(
  doc: PdfDoc,
  pageNumber: number,
  canvas: HTMLCanvasElement,
  scale: number,
): Promise<{ width: number; height: number }> {
  const page = await doc.getPage(pageNumber);
  const viewport = page.getViewport({ scale });
  const dimensions = checkedCanvasSize(viewport.width, viewport.height, scale);
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('canvas 2d context unavailable');
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  await page.render({ canvas, canvasContext: ctx, viewport }).promise;
  return { width: canvas.width, height: canvas.height };
}

// unscaledWidth returns a page's natural width in PDF points so a caller can
// compute the scale that fits a target pixel width.
export async function unscaledWidth(doc: PdfDoc, pageNumber: number): Promise<number> {
  const page = await doc.getPage(pageNumber);
  return page.getViewport({ scale: 1 }).width;
}
