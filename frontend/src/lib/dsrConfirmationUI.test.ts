import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { compile, parse } from 'svelte/compiler';
import { DSRTransitionError } from './api/dsrTransition';
import { translateStaffText } from './staffPreferences';

const filename = new URL('../routes/settings/dsr/+page.svelte', import.meta.url);
const source = readFileSync(filename, 'utf8');
const ast: any = parse(source, { modern: true });
const names = new Set(['transition', 'submitTransition', 'confirmErasure', 'cancelErasure', 'documentStatusLabel']);
const functions = ast.instance.content.body.filter((node: any) => node.type === 'FunctionDeclaration' && names.has(node.id.name)).map((node: any) => source.slice(node.start, node.end)).join('\n');
const lifecycle = ast.instance.content.body.find((node: any) => node.type === 'ExpressionStatement' && node.expression?.callee?.name === 'onDestroy').expression.arguments[0];
const transpiler = new Bun.Transpiler({ loader: 'ts' });
const bind = new Function('env', `with(env){${transpiler.transformSync(functions)};return{transition,confirmErasure,cancelErasure,documentStatusLabel,destroy:(${source.slice(lifecycle.start, lifecycle.end)})};}`);
const preview = { subject_email: 'subject@example.test', document_status: 'draft', pdf_revision_documents: 2, pdf_revisions: 6 };
const pending = (receipt: string, stale = false) => ({ state: 'confirmation', confirmation: { receipt, preview, stale } });

function fixture() {
  const calls: unknown[][] = [], timers: Array<() => void> = [];
  const env: any = { disposed: false, refreshVersion: 0, transitionBusy: false, transitionUnknown: false, confirmationPending: null, transitionAbort: null, error: null, AbortController, DSRTransitionError,
    $ui: (text: string) => translateStaffText('sv', text), prompt: () => 'Reviewed',
    setTimeout: (callback: () => void, ms: number) => { expect(ms).toBe(25000); timers.push(callback); return timers.length; }, clearTimeout() {},
    transitionDSR: async (...args: unknown[]) => { calls.push(args); return pending('receipt.first'); }, refresh: async () => { calls.push(['refresh']); },
  };
  return { env, calls, timers, ...bind(env) };
}

test('the actual page handlers show a preview before any explicit confirmed write', async () => {
  const f = fixture(); await f.transition('request', 'fulfilled');
  expect(f.calls).toHaveLength(1); expect(f.calls[0].slice(0, 4)).toEqual(['request', 'fulfilled', '', undefined]);
  expect(f.env.confirmationPending.preview).toEqual(preview); expect(f.env.confirmationPending.receipt).toBe('receipt.first');
  await f.transition('other', 'fulfilled'); expect(f.calls).toHaveLength(1);
  f.cancelErasure(); expect(f.env.confirmationPending).toBeNull(); expect(f.calls).toHaveLength(1);
});

test('a stale confirmation displays the fresh preview and cannot resend until another click', async () => {
  const f = fixture(); await f.transition('request', 'fulfilled');
  f.env.transitionDSR = async (...args: unknown[]) => { f.calls.push(args); return pending('receipt.fresh', true); };
  await f.confirmErasure(); expect(f.calls).toHaveLength(2); expect(f.calls[1].slice(0, 4)).toEqual(['request', 'fulfilled', '', 'receipt.first']);
  expect(f.env.confirmationPending.receipt).toBe('receipt.fresh'); expect(f.env.confirmationPending.stale).toBe(true);
  await Promise.resolve(); expect(f.calls).toHaveLength(2);
  f.env.transitionDSR = async (...args: unknown[]) => { f.calls.push(args); return { state: 'committed', request: { id: 'request', status: 'fulfilled' } }; };
  await f.confirmErasure(); expect(f.calls[2].slice(0, 4)).toEqual(['request', 'fulfilled', '', 'receipt.fresh']);
  expect(f.calls.at(-1)).toEqual(['refresh']); expect(f.env.confirmationPending).toBeNull();
});

test('one unresolved confirmation owns the action and outcome unknown requires a request refresh', async () => {
  const f = fixture(); await f.transition('request', 'fulfilled');
  let reject!: (error: Error) => void;
  f.env.transitionDSR = (...args: unknown[]) => { f.calls.push(args); return new Promise((_resolve, failure) => { reject = failure; }); };
  const sending = f.confirmErasure(); await f.confirmErasure(); await f.transition('other', 'denied');
  expect(f.calls).toHaveLength(2); expect(f.env.transitionBusy).toBe(true);
  reject(new DSRTransitionError('unknown', 'Refresh requests')); await sending;
  expect(f.env.transitionUnknown).toBe(true); expect(f.env.confirmationPending).toBeNull();
  await f.transition('request', 'fulfilled'); expect(f.calls).toHaveLength(2);
});

test('unmount clears the transient receipt, aborts the request and ignores late results', async () => {
  const f = fixture(); let finish!: (value: unknown) => void;
  f.env.transitionDSR = (...args: unknown[]) => { f.calls.push(args); return new Promise(resolve => { finish = resolve; }); };
  const checking = f.transition('request', 'fulfilled'); const signal = f.env.transitionAbort.signal;
  f.destroy(); expect(signal.aborted).toBe(true); expect(f.env.confirmationPending).toBeNull();
  finish(pending('do-not-adopt')); await checking; expect(f.env.confirmationPending).toBeNull(); expect(f.calls).toHaveLength(1);
});

test('confirmation copy and document status are localized, subject text is escaped and receipts are never rendered or persisted', () => {
  for (const text of ['Confirm irreversible erasure', 'Confirm erasure', 'Subject', 'Linked document status', 'PDF history to erase', 'Refresh requests', 'The erasure scope changed or the confirmation expired. Review this fresh preview and confirm again.']) {
    expect(translateStaffText('sv', text)).not.toBe(text);
  }
  expect(translateStaffText('sv', '{documents} documents · {revisions} revisions', { documents: 2, revisions: 6 })).toBe('2 dokument · 6 versioner');
  expect(fixture().documentStatusLabel('draft')).toBe('Utkast');
  expect(source).not.toContain('message.includes'); expect(source).not.toContain('window.confirm');
  expect(source).not.toContain('localStorage'); expect(source).not.toContain('sessionStorage'); expect(source).not.toContain('{@html');
  expect(source.slice(source.indexOf('</script>'))).not.toContain('.receipt');
  for (const generate of ['client', 'server'] as const) expect(compile(source, { filename: filename.pathname, generate }).warnings).toEqual([]);
});
