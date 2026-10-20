// Own the PDF.js loading task before awaiting its document. Destruction is a
// separate joined operation; a rejected destruction never becomes retirement.
export type PdfLoadingTask<T> = { promise: Promise<T>; destroy(): Promise<void> };

export class PdfLoad<T> {
  readonly promise: Promise<T>;
  private task?: PdfLoadingTask<T>;
  private retirement?: Promise<void>;

  constructor(task: PdfLoadingTask<T>) {
    this.task = task;
    this.promise = task.promise;
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
    try {
      void Promise.resolve(task.destroy()).then(() => {
        this.task = undefined;
        resolve();
      }, reject);
    } catch (error) { reject(error); }
    return retirement;
  }
}
