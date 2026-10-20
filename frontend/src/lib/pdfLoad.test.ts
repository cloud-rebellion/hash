import { expect, test } from 'bun:test';
import { PdfLoad } from './pdfLoad';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, failed) => { resolve = done; reject = failed; });
  return { promise, resolve, reject };
}
const flush = () => new Promise(resolve => setTimeout(resolve, 0));

test('owns a pending parser before document resolution and joins destruction exactly once', async () => {
  const document = deferred<{ numPages: number }>(), retirement = deferred<void>();
  let destroys = 0;
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; return retirement.promise; } });
  expect(load.promise).toBe(document.promise);
  const closing = load.destroy();
  expect(destroys).toBe(1);
  expect(load.destroy()).toBe(closing);
  let joined = false;
  void closing.then(() => { joined = true; });
  await flush(); expect(joined).toBe(false);
  retirement.resolve(); await closing;
  expect(joined).toBe(true); expect(destroys).toBe(1);
  expect(load.destroy()).toBe(closing);
  document.resolve({ numPages: 1 }); expect(await load.promise).toEqual({ numPages: 1 });
});

test('retains destruction rejection and blocks a fresh task behind it', async () => {
  const document = deferred<unknown>(), retirement = deferred<void>();
  const failure = new Error('synthetic retirement refusal');
  let destroys = 0, replacements = 0;
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; return retirement.promise; } });
  const closing = load.destroy();
  const replace = (async () => { await load.destroy(); replacements++; })();
  const outcomes = Promise.allSettled([closing, replace]);
  retirement.reject(failure);
  const settled = await outcomes;
  expect(settled).toHaveLength(2);
  for (const result of settled) {
    expect(result.status).toBe('rejected');
    if (result.status === 'rejected') expect(result.reason).toBe(failure);
  }
  expect(load.destroy()).toBe(closing); expect(destroys).toBe(1); expect(replacements).toBe(0);
  document.resolve(undefined); await document.promise;
});

test('synchronous destroy refusal is the same retained rejected retirement', async () => {
  const failure = new Error('synthetic synchronous refusal');
  let destroys = 0;
  const document = deferred<unknown>();
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; throw failure; } });
  const closing = load.destroy();
  await expect(closing).rejects.toBe(failure);
  expect(load.destroy()).toBe(closing); expect(destroys).toBe(1);
  document.resolve(undefined); await document.promise;
});

test('a sibling initialization failure retires a parser whose document has not resolved', async () => {
  const document = deferred<unknown>(), retirement = deferred<void>();
  let destroys = 0, joined = false;
  const load = new PdfLoad({ promise: document.promise, destroy() { destroys++; return retirement.promise; } });
  const failure = new Error('synthetic fields refusal');
  const initialize = Promise.all([load.promise, Promise.reject(failure)]).catch(async error => {
    await load.destroy(); joined = true; throw error;
  });
  await flush(); expect(destroys).toBe(1); expect(joined).toBe(false);
  document.resolve(undefined); await document.promise;
  retirement.resolve(); await expect(initialize).rejects.toBe(failure);
  expect(joined).toBe(true);
});
