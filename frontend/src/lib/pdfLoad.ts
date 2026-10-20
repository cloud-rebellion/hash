// Own the PDF.js loading task before awaiting its document. Destruction is a
// separate joined operation; a rejected destruction never becomes retirement.
export type PdfLoadingTask<T> = { promise: Promise<T>; destroy(): Promise<void> };

export type PdfLoadLifecycle = { closing(): void; retired(): void; failed(): void };

export class PdfLoad<T> {
  readonly promise: Promise<T>;
  private task?: PdfLoadingTask<T>;
  private retirement?: Promise<void>;

  constructor(task: PdfLoadingTask<T>, private readonly lifecycle?: PdfLoadLifecycle) {
    this.task = task;
    this.promise = task.promise;
  }

  // Housekeeping is an observer of native destruction, never its replacement.
  // A bookkeeping defect freezes the allocation owner if possible, but cannot
  // suppress native invocation, replace its error or strand public retirement.
  private notify(phase: keyof PdfLoadLifecycle): void {
    try { this.lifecycle?.[phase](); }
    catch {
      if (phase !== 'failed') { try { this.lifecycle?.failed(); } catch {} }
    }
  }

  destroy(): Promise<void> {
    if (this.retirement) return this.retirement;
    let resolve!: () => void;
    let reject!: (reason: unknown) => void;
    const retirement = new Promise<void>((done, failed) => { resolve = done; reject = failed; });
    this.retirement = retirement;
    // Svelte disposal is synchronous. Observe rejection without changing the
    // returned promise, so an owner/retry can still await the real failure.
    void retirement.catch(() => {});
    const task = this.task!;
    this.notify('closing');
    try {
      void Promise.resolve(task.destroy()).then(() => {
        this.task = undefined;
        this.notify('retired');
        resolve();
      }, error => { this.notify('failed'); reject(error); });
    } catch (error) { this.notify('failed'); reject(error); }
    return retirement;
  }
}
