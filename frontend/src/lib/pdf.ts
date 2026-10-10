// Thin wrapper around pdf.js so the field designer and the signer page share
// one PDF rendering path. Browser-only: call from onMount, never during SSR.
import * as pdfjsLib from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { checkedCanvasSize } from './pdfViewport';

pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl;

export type PdfDoc = Awaited<ReturnType<typeof pdfjsLib.getDocument>['promise']>;

// loadPdf fetches + parses a PDF. withCredentials so the session/magic-token
// cookie reaches the authed PDF endpoints.
export async function loadPdf(url: string): Promise<PdfDoc> {
  return pdfjsLib.getDocument({ url, withCredentials: true }).promise;
}

// Caller verifies these bytes against the observed server PDF commitment first.
export async function loadPdfData(data: Uint8Array): Promise<PdfDoc> {
  return pdfjsLib.getDocument({ data }).promise;
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
