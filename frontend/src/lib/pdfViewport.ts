// Browser canvas allocation limits apply to authoring, signing and PDF review.
const MAX_CANVAS_DIMENSION = 8192;
const MAX_CANVAS_PIXELS = 16 * 1024 * 1024;
export function checkedCanvasSize(width: number, height: number, scale: number): { width: number; height: number } {
  if (!Number.isFinite(scale) || scale <= 0 || scale > 4 || !Number.isFinite(width) || !Number.isFinite(height)
      || width < 1 || height < 1 || width > MAX_CANVAS_DIMENSION || height > MAX_CANVAS_DIMENSION
      || width * height > MAX_CANVAS_PIXELS) {
    throw new Error('This PDF page exceeds safe preview dimensions. Ask its owner to review the source design.');
  }
  return { width: Math.floor(width), height: Math.floor(height) };
}
