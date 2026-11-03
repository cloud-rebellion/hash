import type { PaintOptions } from './pdfCanvas';
import type { PDFPageGeometry } from './pdfPageResidency';

const closed = () => new DOMException('The document view was closed.', 'AbortError');
export const PDF_FIT_PAGE_HEIGHT = 'max(160px, min(64dvh, calc(100dvh - 30rem)))';
type PaintClient = 'page' | 'thumbnail';
type Job = { work(): Promise<unknown>; resolve(value: unknown): void; reject(reason: unknown): void; detach(): void; signal?: AbortSignal };

// PdfCanvasBudget intentionally permits only one waiter per generation. The
// two real UI consumers cooperate here, with at most one request each. This
// does not change that native quota or complete an active paint on cancellation.
export class PDFPaintLane {
  private active: Job | null = null;
  private queued = new Map<PaintClient, Job>();
  private clients = new Set<PaintClient>();
  private stopped = false;
  constructor(private readonly current: () => void) {}
  paint<T>(client: PaintClient, work: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (this.stopped || signal?.aborted) return Promise.reject(closed());
    if (!['page', 'thumbnail'].includes(client) || this.clients.has(client)) return Promise.reject(new Error('A PDF paint is already pending.'));
    return new Promise<T>((resolve, reject) => {
      const abort = () => {
        if (this.active === job) return; // The original active paint must settle.
        if (this.queued.get(client) === job) { this.queued.delete(client); this.clients.delete(client); job.detach(); reject(closed()); }
      };
      const job: Job = { work, resolve: value => resolve(value as T), reject, signal, detach: () => signal?.removeEventListener('abort', abort) };
      this.clients.add(client); this.queued.set(client, job); signal?.addEventListener('abort', abort, { once: true }); this.pump();
    });
  }
  close(): void {
    if (this.stopped) return; this.stopped = true;
    for (const [client, job] of this.queued) { job.detach(); this.clients.delete(client); job.reject(closed()); }
    this.queued.clear();
  }
  snapshot() { return { active: this.active !== null, queued: this.queued.size, clients: this.clients.size, closed: this.stopped }; }
  private pump(): void {
    if (this.active || this.stopped) return;
    const client = this.queued.has('page') ? 'page' : 'thumbnail';
    const job = this.queued.get(client); if (!job) return;
    this.queued.delete(client); this.active = job;
    const finish = (value: unknown, failed: boolean) => {
      this.active = null; this.clients.delete(client); job.detach();
      if (failed) job.reject(value); else job.resolve(value); this.pump();
    };
    void Promise.resolve().then(() => { this.current(); if (job.signal?.aborted) throw closed(); return job.work(); }).then(value => finish(value, false), error => finish(error, true));
  }
}

export function pdfThumbnailPages(active: number, total: number): number[] {
  if (!Number.isInteger(total) || total < 1 || total > 500 || !Number.isInteger(active) || active < 1 || active > total) throw new Error('Unexpected PDF page selection.');
  const first = Math.max(1, Math.min(active - 2, total - 4));
  return Array.from({ length: Math.min(total, 5) }, (_, index) => first + index);
}
export type ThumbnailPaint<D> = (doc: D, page: number, canvas: HTMLCanvasElement, scale: number, options: PaintOptions) => Promise<{ width: number; height: number }>;
export type ThumbnailState = 'loading' | 'ready' | 'released';
type ThumbnailPorts<D> = {
  current(): void; geometry(doc: D, page: number): Promise<PDFPageGeometry>;
  canvas(slot: number): HTMLCanvasElement | undefined; paint: ThumbnailPaint<D>;
  recycle(doc: D, canvas: HTMLCanvasElement): boolean; resident(doc: D, canvas: HTMLCanvasElement): boolean;
  state(slot: number, page: number, state: ThumbnailState): void; failed(reason: unknown): void;
};

// Exactly five reusable bitmap slots and one joined painter. Thumbnails never
// establish full-page review or field-placement proof. Native PdfLoad retains
// generation ownership, including when destruction is uncertain.
export class PDFThumbnailWindow<D extends { numPages: number }> {
  private desired: number[] = [];
  private painted = new Map<number, { page: number; canvas: HTMLCanvasElement }>();
  private attempted = new Map<number, number>();
  private revision = 0;
  private task: Promise<void> | null = null;
  private stopped = false;
  private controller = new AbortController();
  constructor(private readonly doc: D, private readonly ports: ThumbnailPorts<D>) {}
  select(page: number): void {
    if (this.stopped) return; this.desired = pdfThumbnailPages(page, this.doc.numPages); this.revision++;
    for (let slot = 0; slot < this.desired.length; slot++) { const item = this.painted.get(slot); this.ports.state(slot, this.desired[slot], item?.page === this.desired[slot] && this.ports.resident(this.doc, item.canvas) ? 'ready' : 'loading'); }
    this.kick();
  }
  stop(): Promise<void> { this.stopped = true; this.controller.abort(); return this.task ?? Promise.resolve(); }
  private kick(): void {
    if (this.task || this.stopped) return;
    const task = this.run(); this.task = task;
    void task.then(() => { if (this.task === task) this.task = null; if (!this.stopped && this.pending()) this.kick(); }, error => { this.stopped = true; this.controller.abort(); this.ports.failed(error); });
  }
  private needsPaint(page: number, slot: number): boolean { const item = this.painted.get(slot); return this.attempted.get(slot) !== this.revision && (item?.page !== page || !this.ports.resident(this.doc, item.canvas)); }
  private pending(): boolean { return this.desired.some((page, slot) => this.needsPaint(page, slot)); }
  private async run(): Promise<void> {
    while (!this.stopped) {
      this.ports.current(); const slot = this.desired.findIndex((page, index) => this.needsPaint(page, index));
      if (slot < 0) return;
      const page = this.desired[slot], canvas = this.ports.canvas(slot); if (!canvas) throw new Error('A PDF thumbnail could not be displayed.');
      this.attempted.set(slot, this.revision); this.ports.state(slot, page, 'loading');
      const geometry = await this.ports.geometry(this.doc, page); this.ports.current(); if (this.stopped) return;
      if (geometry.num !== page || !Number.isInteger(geometry.w) || !Number.isInteger(geometry.h) || geometry.w < 1 || geometry.h < 1 || !Number.isFinite(geometry.scale) || geometry.scale <= 0) throw new Error('Unexpected PDF thumbnail geometry.');
      // Geometry is an integer envelope around PDF.js's fractional viewport.
      // Leave one pixel for the native paint's independent rounding.
      const scale = geometry.scale * Math.min(111 / geometry.w, 159 / geometry.h, 1);
      if (!Number.isFinite(scale) || scale <= 0) throw new Error('Unexpected PDF thumbnail dimensions.');
      const size = await this.ports.paint(this.doc, page, canvas, scale, { signal: this.controller.signal, priority: 'background', thumbnail: true, evictable: () => true,
        onEvict: () => { this.painted.delete(slot); if (!this.stopped) this.ports.state(slot, this.desired[slot], 'released'); } });
      if (!Number.isInteger(size.width) || !Number.isInteger(size.height) || size.width < 1 || size.height < 1 || size.width > 112 || size.height > 160) throw new Error('Unexpected PDF thumbnail dimensions.');
      this.ports.current();
      this.painted.set(slot, { page, canvas });
      if (this.stopped) return;
      if (this.desired[slot] !== page) { if (!this.ports.recycle(this.doc, canvas)) throw new Error('A PDF thumbnail is still rendering.'); this.painted.delete(slot); continue; }
      this.ports.state(slot, page, this.ports.resident(this.doc, canvas) ? 'ready' : 'released');
    }
  }
}
