// Logical canvas backing-store policy, shared by every PDF viewer in this tab.
// This is not an RSS measurement or a browser/GPU memory guarantee.
export const PDF_CANVAS_PIXELS = 32 * 1024 * 1024;
export const PDF_CANVAS_LOGICAL_BYTES = PDF_CANVAS_PIXELS * 4;
const MAX_OWNERS = 32;
const MAX_STORES_PER_OWNER = 3;
export const PDF_CANVAS_WAIT_MS = 10_000;
const unavailable = () => new Error('PDF preview memory is busy. Close another PDF preview and reopen this document.');
const closed = () => new DOMException('The document view was closed.', 'AbortError');
export type CanvasStore = Pick<HTMLCanvasElement, 'width' | 'height'>;
export type PaintOptions = {
  priority?: 'visible' | 'background';
  signal?: AbortSignal;
  evictable?: () => boolean;
  onEvict?: () => void;
};
type Generation = {
  controller: AbortController; state: 'open' | 'closing' | 'retired' | 'failed';
  waiting?: Waiter;
};
type Lease = {
  generation: Generation; canvas: CanvasStore; pixels: number; painting: boolean;
  options: PaintOptions;
};
type Waiter = {
  generation: Generation; canvas: CanvasStore; width: number; height: number; options: PaintOptions;
  resolve: (lease: PaintLease) => void; reject: (reason: unknown) => void; cleanup: () => void;
};
export type CanvasGeneration = Generation;
export type PaintLease = { assertCurrent(): void; observe(promise: Promise<unknown>): void; finish(): void };

export class PdfCanvasBudget {
  private owners = new Set<Generation>();
  private stores = new Map<CanvasStore, Lease>();
  private waiters: Waiter[] = [];
  private active: Lease | undefined;
  private pixels = 0;
  private failed = false;
  private visibleGrants = 0;
  constructor(private readonly limit = PDF_CANVAS_PIXELS, private readonly waitMilliseconds = PDF_CANVAS_WAIT_MS) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > PDF_CANVAS_PIXELS
      || !Number.isSafeInteger(waitMilliseconds) || waitMilliseconds < 1 || waitMilliseconds > PDF_CANVAS_WAIT_MS) throw unavailable();
  }
  generation(): CanvasGeneration {
    if (this.failed || this.owners.size >= MAX_OWNERS) throw unavailable();
    const generation: Generation = { controller: new AbortController(), state: 'open' };
    this.owners.add(generation);
    return generation;
  }
  closing(generation: Generation): void {
    if (generation.state !== 'open') return;
    generation.state = 'closing';
    generation.controller.abort();
  }
  retired(generation: Generation): void {
    generation.state = 'retired';
    generation.controller.abort();
    for (const lease of this.stores.values()) if (lease.generation === generation && !lease.painting) this.release(lease);
    this.forget(generation);
    this.pump();
  }
  retirementFailed(generation: Generation): void {
    generation.state = 'failed';
    generation.controller.abort();
    // Unconfirmed stores stay charged. A reload is required; granting more work
    // after a failed native destruction would conceal unresolved ownership.
    this.failed = true;
    for (const waiter of [...this.waiters]) this.refuse(waiter, unavailable());
  }
  recycle(generation: Generation, canvas: CanvasStore): boolean {
    const lease = this.stores.get(canvas);
    if (!lease) return true;
    if (lease.generation !== generation || lease.painting || generation.state !== 'open') return false;
    this.release(lease);
    this.pump();
    return !this.failed && !this.stores.has(canvas);
  }
  resident(generation: Generation, canvas: CanvasStore): boolean {
    const lease = this.stores.get(canvas);
    return !!lease && lease.generation === generation && !lease.painting && generation.state === 'open';
  }
  acquire(generation: Generation, canvas: CanvasStore, width: number, height: number, options: PaintOptions = {}): Promise<PaintLease> {
    if (!this.owners.has(generation) || generation.state !== 'open' || options.signal?.aborted) return Promise.reject(closed());
    if (this.failed || generation.waiting || !Number.isSafeInteger(width) || !Number.isSafeInteger(height)
      || width < 1 || height < 1 || width * height > this.limit) return Promise.reject(unavailable());
    return new Promise((resolve, reject) => {
      const abort = () => this.refuse(waiter, closed());
      const timer = setTimeout(() => this.refuse(waiter, unavailable()), this.waitMilliseconds);
      const waiter: Waiter = { generation, canvas, width, height, options, resolve, reject, cleanup: () => {
        clearTimeout(timer); generation.controller.signal.removeEventListener('abort', abort);
        options.signal?.removeEventListener('abort', abort);
      } };
      generation.waiting = waiter;
      generation.controller.signal.addEventListener('abort', abort, { once: true });
      options.signal?.addEventListener('abort', abort, { once: true });
      this.waiters.push(waiter);
      this.pump();
    });
  }
  private refuse(waiter: Waiter, reason: unknown): void {
    if (waiter.generation.waiting !== waiter) return;
    this.remove(waiter); waiter.reject(reason); this.pump();
  }
  private remove(waiter: Waiter): void {
    this.waiters.splice(this.waiters.indexOf(waiter), 1);
    waiter.generation.waiting = undefined; waiter.cleanup();
  }
  private forget(generation: Generation): void {
    if (generation.state === 'retired' && ![...this.stores.values()].some(lease => lease.generation === generation)) this.owners.delete(generation);
  }
  private release(lease: Lease): void {
    if (this.stores.get(lease.canvas) !== lease || lease.painting) return;
    // Zero before returning the charge. Failure leaves the charge in place.
    try { lease.canvas.width = 0; lease.canvas.height = 0; }
    catch { this.retirementFailed(lease.generation); return; }
    this.stores.delete(lease.canvas); this.pixels -= lease.pixels;
    try { lease.options.onEvict?.(); } catch { this.retirementFailed(lease.generation); }
    this.forget(lease.generation);
  }
  private ownedStores(generation: Generation): number {
    let count = 0;
    for (const lease of this.stores.values()) if (lease.generation === generation) count++;
    return count;
  }
  private pump(): void {
    if (this.active || this.failed) return;
    const background = this.waiters.filter(waiter => waiter.options.priority === 'background');
    const visible = this.waiters.filter(waiter => waiter.options.priority !== 'background');
    // A waiting background owner gets a turn after four visible grants. There
    // is at most one waiter per owner and 32 live owners, never one per page.
    const ordered = this.visibleGrants >= 4 ? [...background, ...visible] : [...visible, ...background];
    for (const waiter of ordered) {
      const old = this.stores.get(waiter.canvas);
      if (old && (old.generation !== waiter.generation || old.painting)) continue;
      if (old) this.release(old);
      if (this.failed) return;
      for (const lease of [...this.stores.values()]) {
        if (this.pixels + waiter.width * waiter.height <= this.limit && this.ownedStores(waiter.generation) < MAX_STORES_PER_OWNER) break;
        if ((lease.generation === waiter.generation || this.pixels + waiter.width * waiter.height > this.limit)
          && !lease.painting && lease.generation.state === 'open' && lease.options.evictable?.() === true) this.release(lease);
      }
      if (this.failed) return;
      if (this.pixels + waiter.width * waiter.height > this.limit || this.ownedStores(waiter.generation) >= MAX_STORES_PER_OWNER) continue;
      // Synchronous reservation before resolving the waiter prevents two
      // callers from both observing the same free budget.
      const lease: Lease = { generation: waiter.generation, canvas: waiter.canvas,
        pixels: waiter.width * waiter.height, painting: true, options: waiter.options };
      this.stores.set(waiter.canvas, lease); this.pixels += lease.pixels; this.active = lease;
      this.remove(waiter);
      this.visibleGrants = waiter.options.priority === 'background' ? 0 : this.visibleGrants + 1;
      let observed = false, settled = false, finished = false, requested = false;
      const finish = () => {
        if (finished || !requested || observed && !settled) return;
        finished = true; lease.painting = false; this.active = undefined;
        if (lease.generation.state === 'retired') this.release(lease);
        this.pump();
      };
      waiter.resolve({
        assertCurrent: () => { if (lease.generation.state !== 'open' || lease.options.signal?.aborted) throw closed(); },
        observe: promise => {
          if (observed || finished) throw unavailable();
          observed = true;
          // Observe, never replace or mutate, the original RenderTask.promise.
          void promise.then(() => { settled = true; finish(); }, () => { settled = true; finish(); });
        },
        finish: () => { requested = true; finish(); },
      });
      return;
    }
  }
  snapshot(): { pixels: number; logicalBytes: number; owners: number; stores: number; waiting: number; painting: boolean; blocked: boolean } {
    return { pixels: this.pixels, logicalBytes: this.pixels * 4, owners: this.owners.size,
      stores: this.stores.size, waiting: this.waiters.length, painting: !!this.active, blocked: this.failed };
  }
}

export const pdfCanvasBudget = new PdfCanvasBudget();
