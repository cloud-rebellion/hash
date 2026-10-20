import { PDF_CANVAS_WAIT_MS, type PaintOptions } from './pdfCanvas';

export type PDFPageGeometry = { num: number; w: number; h: number; scale: number };
type Port<D> = {
  current(): void;
  geometry(doc: D, page: number): Promise<PDFPageGeometry>;
  mount(pages: PDFPageGeometry[]): Promise<void>;
  canvas(page: number): HTMLCanvasElement | undefined;
  paint(doc: D, page: number, canvas: HTMLCanvasElement, scale: number, options: PaintOptions): Promise<{ width: number; height: number }>;
  recycle(doc: D, canvas: HTMLCanvasElement): boolean;
  isResident(doc: D, canvas: HTMLCanvasElement): boolean;
  resident(page: number, ready: boolean): void;
  failed(reason: unknown): void;
};

// One bounded event-driven runner per document, not one promise per page. All
// wrappers and field DOM remain mounted. Only their bitmap stores are recycled.
export class ContinuousPDFPages<D extends { numPages: number }> {
  private pages: PDFPageGeometry[] = [];
  private completed = new Set<number>();
  private resident = new Set<number>();
  private visible = new Set<number>();
  private pointer = new Map<number, { page: number }>();
  private releasing = new Set<{ page: number }>();
  private focused = 0;
  private running = false;
  private started = false;
  private dirty = false;
  private pausedTimer?: ReturnType<typeof setTimeout>;
  private stopped = false;
  private controller = new AbortController();
  private observer?: IntersectionObserver;
  private listeners: (() => void)[] = [];
  private resolve!: (pages: PDFPageGeometry[]) => void;
  private reject!: (reason: unknown) => void;
  private readonly ready = new Promise<PDFPageGeometry[]>((resolve, reject) => { this.resolve = resolve; this.reject = reject; });
  constructor(private readonly doc: D, private readonly port: Port<D>, private readonly expectedPages = doc.numPages) {
    // Suppress only an unobserved disposal rejection; start() still returns the
    // original joined promise and cannot turn cancellation into readiness.
    void this.ready.catch(() => {});
  }
  async start(): Promise<PDFPageGeometry[]> {
    if (this.started) return this.ready;
    this.started = true;
    try {
      this.check();
      if (!Number.isInteger(this.doc.numPages) || this.doc.numPages < 1 || this.doc.numPages > 500 || this.doc.numPages !== this.expectedPages) {
        throw new Error('The loaded PDF has an unexpected page count.');
      }
      for (let page = 1; page <= this.doc.numPages; page++) {
        const geometry = await this.port.geometry(this.doc, page); this.check();
        if (geometry.num !== page || !Number.isInteger(geometry.w) || !Number.isInteger(geometry.h) || geometry.w < 1 || geometry.h < 1) throw new Error('A document page could not be laid out.');
        this.pages.push(geometry);
      }
      await this.port.mount(this.pages); this.check();
      this.observe();
      this.kick();
    } catch (error) { this.fail(error); }
    return this.ready;
  }
  pageReady(page: number): boolean { return !this.stopped && this.resident.has(page); }
  allPagesRendered(): boolean { return !this.stopped && this.completed.size === this.pages.length && this.pages.length === this.expectedPages; }
  stop(): void {
    if (this.stopped) return;
    this.stopped = true; this.controller.abort(); this.observer?.disconnect();
    clearTimeout(this.pausedTimer); this.pausedTimer = undefined;
    for (const remove of this.listeners) remove();
    this.listeners = []; this.pointer.clear(); this.releasing.clear();
    this.reject(new DOMException('The document view was closed.', 'AbortError'));
    // Store ownership remains with PdfLoad and its real native destruction.
  }
  private check(): void {
    if (this.stopped) throw new DOMException('The document view was closed.', 'AbortError');
    this.port.current();
  }
  private fail(error: unknown): void {
    if (this.stopped) return;
    this.reject(error); this.stop(); this.port.failed(error);
  }
  private pinned(page: number): boolean { return page === this.focused || [...this.pointer.values()].some(pin => pin.page === page); }
  private wanted(): number[] {
    const pinned = this.pages.filter(page => this.pinned(page.num)).map(page => page.num);
    // Keep one scan slot until every page has genuinely painted. At most two
    // visible/focused pages plus that slot, then three viewport pages afterward.
    const slots = this.completed.size === this.pages.length ? 3 : 2;
    const candidates = [...this.visible].sort((a, b) => this.distance(a) - this.distance(b));
    return [...new Set([...pinned, ...candidates])].slice(0, Math.max(pinned.length, slots));
  }
  private distance(page: number): number {
    const rect = this.port.canvas(page)?.parentElement?.getBoundingClientRect();
    return rect ? Math.abs((rect.top + rect.bottom) / 2 - window.innerHeight / 2) : Infinity;
  }
  private observe(): void {
    if (typeof IntersectionObserver !== 'function') throw new Error('This browser cannot manage PDF page previews. Use a current browser.');
    const numbers = new Map<Element, number>();
    this.observer = new IntersectionObserver(entries => {
      if (this.stopped) return;
      for (const entry of entries) {
        const page = numbers.get(entry.target)!;
        if (entry.isIntersecting) this.visible.add(page); else this.visible.delete(page);
      }
      this.kick();
    });
    for (const event of ['pointerup', 'pointercancel', 'lostpointercapture']) {
      const release = (event: Event) => {
        const id = (event as PointerEvent).pointerId, pin = this.pointer.get(id);
        if (!pin || this.releasing.has(pin)) return;
        this.releasing.add(pin);
        // Window capture precedes the designer's drop handler. Keep its exact
        // canvas/geometry pinned until that handler has built the saved request.
        queueMicrotask(() => {
          this.releasing.delete(pin);
          if (!this.stopped && this.pointer.get(id) === pin) { this.pointer.delete(id); this.kick(); }
        });
      };
      window.addEventListener(event, release, true);
      this.listeners.push(() => window.removeEventListener(event, release, true));
    }
    for (const page of this.pages) {
      const element = this.port.canvas(page.num)?.parentElement;
      if (!element) throw new Error('A document page could not be displayed.');
      numbers.set(element, page.num); this.observer.observe(element);
      const on = (name: string, callback: EventListener) => {
        element.addEventListener(name, callback); this.listeners.push(() => element.removeEventListener(name, callback));
      };
      on('focusin', () => { this.focused = page.num; this.kick(); });
      on('focusout', event => {
        if (!element.contains((event as FocusEvent).relatedTarget as Node | null)) this.focused = 0;
        this.kick();
      });
      on('pointerdown', event => {
        const id = (event as PointerEvent).pointerId;
        if (this.pointer.size >= 8 && !this.pointer.has(id)) { this.fail(new Error('Too many active PDF gestures. Lift your fingers and reopen the preview.')); return; }
        if (new Set([...[...this.pointer.values()].map(pin => pin.page), this.focused, page.num].filter(Boolean)).size > 3) { this.fail(new Error('Too many PDF pages are being edited at once. Finish the current gesture and reopen the preview.')); return; }
        this.pointer.set(id, { page: page.num }); this.kick();
      });
    }
  }
  private kick(): void {
    if (this.stopped) return;
    if (this.running) { this.dirty = true; return; }
    this.running = true;
    void this.run().catch(error => this.fail(error)).finally(() => {
      this.running = false;
      if (this.dirty) { this.dirty = false; this.kick(); }
    });
  }
  private async run(): Promise<void> {
    while (!this.stopped) {
      this.check();
      const wanted = this.wanted();
      // Even when no paint is needed, a released focus/gesture must permit
      // settled offscreen stores to return their charge.
      for (const number of [...this.resident]) {
        if (!wanted.includes(number) && !this.pinned(number)) this.recycle(number);
      }
      const page = wanted.find(number => !this.resident.has(number))
        ?? this.pages.find(candidate => !this.completed.has(candidate.num))?.num;
      if (!page) {
        clearTimeout(this.pausedTimer); this.pausedTimer = undefined;
        this.resolve(this.pages); return;
      }
      if (!this.resident.has(page) && this.resident.size >= 3) {
        // Do not grow a hidden per-page wait queue or spin while three real
        // focus/gesture owners pin every slot. Events may free a slot; otherwise
        // one finite timer supplies an actionable failure under the same policy.
        this.pausedTimer ??= setTimeout(() => this.fail(new Error('Finish the active PDF gestures and reopen this preview.')), PDF_CANVAS_WAIT_MS);
        return;
      }
      clearTimeout(this.pausedTimer); this.pausedTimer = undefined;
      const geometry = this.pages[page - 1], canvas = this.port.canvas(page);
      if (!canvas) throw new Error('A document page could not be displayed.');
      this.port.resident(page, false);
      const size = await this.port.paint(this.doc, page, canvas, geometry.scale, {
        signal: this.controller.signal,
        priority: wanted.includes(page) ? 'visible' : 'background',
        evictable: () => !this.pinned(page) && !this.wanted().includes(page),
        onEvict: () => { this.resident.delete(page); this.port.resident(page, false); },
      });
      this.check();
      if (size.width !== geometry.w || size.height !== geometry.h) throw new Error('The painted PDF page changed dimensions. Reopen the document.');
      this.completed.add(page);
      if (this.port.isResident(this.doc, canvas)) { this.resident.add(page); this.port.resident(page, true); }
      // An offscreen scan never keeps an extra backing store resident.
      if (this.resident.has(page) && !this.wanted().includes(page) && !this.pinned(page)) this.recycle(page);
      if (this.completed.size === this.pages.length) this.resolve(this.pages);
    }
  }
  private recycle(page: number): void {
    const canvas = this.port.canvas(page);
    if (!canvas || !this.port.recycle(this.doc, canvas)) throw new Error('A PDF page is still rendering. Reopen the document before continuing.');
    this.resident.delete(page); this.port.resident(page, false);
  }
}
