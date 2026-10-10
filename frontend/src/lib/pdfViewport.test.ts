import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { checkedCanvasSize } from './pdfViewport';

test('normal portrait, landscape and rotated preview geometry stays exact', () => {
  expect(checkedCanvasSize(760.8, 1075.9, 1.25)).toEqual({ width: 760, height: 1075 });
  expect(checkedCanvasSize(1075, 760, 1)).toEqual({ width: 1075, height: 760 });
  expect(checkedCanvasSize(4096, 4096, 2)).toEqual({ width: 4096, height: 4096 });
});

test('shared renderer rejects unsafe source geometry before touching the canvas or dispatching page rendering', async () => {
  const source = readFileSync(new URL('./pdf.ts', import.meta.url), 'utf8');
  const start = source.indexOf('export async function renderPage(');
  const end = source.indexOf('// unscaledWidth', start);
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(start, end).replace('export async', 'async'));
  const renderPage = new Function('checkedCanvasSize', `${code}; return renderPage;`)(checkedCanvasSize);
  for (const geometry of [{ width: 760, height: 1000000 }, { width: NaN, height: 500 }, { width: 5000, height: 5000 }]) {
    let touched = 0;
    const doc = { getPage: async () => ({ getViewport: () => geometry, render: () => { touched++; return { promise: Promise.resolve() }; } }) };
    const canvas = { getContext: () => { touched++; return {}; }, set width(_: number) { touched++; }, set height(_: number) { touched++; } };
    await expect(renderPage(doc, 1, canvas, 1)).rejects.toThrow('safe preview dimensions');
    expect(touched).toBe(0);
  }
});
test('invalid scale, huge aspect ratio or total pixels refuse before a canvas allocation', () => {
  for (const [width, height, scale] of [[NaN, 100, 1], [100, Infinity, 1], [0, 100, 1], [-1, 100, 1],
    [760, 1000000, 1], [8193, 1, 1], [5000, 5000, 1], [100, 100, 0], [100, 100, NaN], [100, 100, Infinity], [100, 100, 5]]) {
    expect(() => checkedCanvasSize(width, height, scale)).toThrow('safe preview dimensions');
  }
});
