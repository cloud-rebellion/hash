import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { Editor } from '@tiptap/core';
import { APIError } from '../../api/client';

const source = readFileSync(new URL('./Editor.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const effects = tree.instance.content.body.filter((node: any) => node.type === 'ExpressionStatement' && node.expression.callee?.name === '$effect');
function expression(node: any) { return new Bun.Transpiler({ loader: 'ts' }).transformSync(`const callback = ${source.slice(node.start, node.end)};`).replace(/export\s*\{[^}]*\};?/, ''); }
const bindEffect = new Function('env', `with(env) { ${expression(effects[1].expression.arguments[0])}; return callback; }`);
const bindCleanEffect = new Function('env', `with(env) { ${expression(effects[0].expression.arguments[0])}; return callback; }`);
let update: any;
function find(node: any) {
  if (!node || typeof node !== 'object') return;
  if (node.type === 'NewExpression' && node.callee.name === 'Editor') update = node.arguments[0].properties.find((property: any) => property.key.name === 'onUpdate')?.value;
  for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(find); else if (value && typeof value === 'object') find(value);
}
find(tree.instance); if (!update) throw new Error('Actual editor update callback missing');
const bindUpdate = new Function('env', `with(env) { ${expression(update)}; return callback; }`);
const nativeFunctions = ['scheduleSave', 'persist', 'manualSave'].map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  return source.slice(node.start, node.end);
}).join('\n');
const nativeCode = new Bun.Transpiler({ loader: 'ts' }).transformSync(nativeFunctions);
const bindSaves = new Function('env', `with(env) { ${nativeCode}; return { scheduleSave, persist, manualSave }; }`);

function fixture() {
  const timers = new Map<number, () => Promise<void>>(), calls: any[] = [], clean: boolean[] = [];
  let next = 0, effect: () => void;
  const env: any = {
    disposed: false, externalBusy: false, saveConflict: false, collaborationRejected: false, saving: false, saveQueued: false,
    dirty: false, editRevision: 0, saveTimer: null, reconnectTimer: null, wasExternallyBusy: false, externalQuiesced: false,
    connected: true, syncReady: true, canonicalGeneration: '1', showImport: 'none', showTableModal: false, error: null, APIError,
    doc: { id: 'doc', org_id: 'workspace', status: 'draft', updated_at: 'first', blocks_json: { text: 'original' } },
    untrack: (callback: () => void) => callback(), checkpointRequests: { cancel() {} },
    setTimeout(callback: () => Promise<void>, delay: number) { expect(delay).toBe(700); timers.set(++next, callback); return next; },
    clearTimeout(id: number) { timers.delete(id); },
    requestCheckpoint: async () => ({ peerID: 'peer', token: 'token', generation: env.canonicalGeneration }),
    fromProseMirror: (value: unknown) => value,
    saveCollaborativeDocument: (id: string, patch: any) => new Promise((resolve, reject) => calls.push({ id, patch, resolve, reject })),
    onChange(updated: any) { env.doc = { ...updated }; effect(); },
    onEditorStateChange(value: boolean) { clean.push(value); },
    provider: { params: { expected_updated_at: 'first' }, connect() {}, disconnect() {} },
  };
  const onUpdate = bindUpdate(env), options = { editable: true };
  // Use the installed TipTap method itself, not a model of its default emitUpdate behavior.
  const tiptap = { options, state: { tr: {} }, setOptions(value: any) { Object.assign(options, value); }, emit(name: string) { if (name === 'update') onUpdate(); } };
  env.editor = { getJSON: () => env.doc.blocks_json,
    setEditable: (...args: Parameters<Editor['setEditable']>) => Editor.prototype.setEditable.apply(tiptap as unknown as Editor, args) };
  Object.assign(env, bindSaves(env)); effect = bindEffect(env);
  const cleanEffect = bindCleanEffect(env);
  return { env, timers, calls, clean, options, effect, cleanEffect, onUpdate,
    async autosave() { const row = timers.entries().next().value; if (!row) throw new Error('No scheduled save'); timers.delete(row[0]); const pending = row[1](); await Promise.resolve(); return { pending }; } };
}

function receipt(f: ReturnType<typeof fixture>, index = 0) {
  f.calls[index].resolve({ document: { ...f.env.doc, updated_at: 'saved-' + index }, generation: (BigInt(f.calls[index].patch.generation) + 1n).toString() });
}

test('initial permission synchronization is quiet and never marks unchanged content dirty', () => {
  const f = fixture(); f.effect(); f.cleanEffect();
  expect(f.env.dirty).toBe(false); expect(f.env.editRevision).toBe(0); expect(f.timers.size).toBe(0); expect(f.clean.at(-1)).toBe(true);
});

test('acknowledged autosave and parent document replacement cannot schedule a feedback save', async () => {
  const f = fixture(); f.onUpdate(); expect(f.timers.size).toBe(1);
  const { pending } = await f.autosave(); expect(f.calls).toHaveLength(1); receipt(f); await pending;
  f.effect(); f.cleanEffect();
  expect(f.env.doc.updated_at).toBe('saved-0'); expect(f.env.canonicalGeneration).toBe('2');
  expect(f.env.dirty).toBe(false); expect(f.env.editRevision).toBe(1); expect(f.timers.size).toBe(0);
  expect(f.clean.at(-1)).toBe(true); expect(f.calls).toHaveLength(1);
  for (let i = 0; i < 5; i++) { f.env.doc = { ...f.env.doc }; f.effect(); }
  expect(f.timers.size).toBe(0); expect(f.calls).toHaveLength(1);
});

test('manual save cancels its original timer and remains clean after the receipt', async () => {
  const f = fixture(); f.onUpdate(); f.env.manualSave(); await Promise.resolve();
  expect(f.timers.size).toBe(0); expect(f.calls).toHaveLength(1); receipt(f);
  for (let i = 0; i < 6; i++) await Promise.resolve(); f.effect(); f.cleanEffect();
  expect(f.env.dirty).toBe(false); expect(f.timers.size).toBe(0); expect(f.clean.at(-1)).toBe(true);
});

test('a real later content update still schedules and persists a new canonical generation', async () => {
  const f = fixture(); f.onUpdate(); let save = await f.autosave(); receipt(f); await save.pending;
  f.env.doc.blocks_json = { text: 'a real later edit' }; f.onUpdate(); expect(f.env.dirty).toBe(true);
  save = await f.autosave(); expect(f.calls).toHaveLength(2); expect(f.calls[1].patch.generation).toBe('2');
  expect(f.calls[1].patch.blocks_json).toEqual({ text: 'a real later edit' }); receipt(f, 1); await save.pending;
  expect(f.env.canonicalGeneration).toBe('3'); expect(f.env.dirty).toBe(false); expect(f.timers.size).toBe(0);
});

test('peer acknowledgement and external lock transitions do not manufacture content changes', () => {
  const f = fixture(); f.env.doc = { ...f.env.doc, updated_at: 'peer-accepted' }; f.env.canonicalGeneration = '3'; f.effect();
  expect(f.env.editRevision).toBe(0); expect(f.timers.size).toBe(0);
  f.env.externalBusy = true; f.effect(); expect(f.options.editable).toBe(false); expect(f.env.externalQuiesced).toBe(true);
  f.env.externalBusy = false; f.effect(); expect(f.options.editable).toBe(true); expect(f.timers.size).toBe(0);
  f.env.saveConflict = true; f.effect(); expect(f.options.editable).toBe(false); expect(f.env.dirty).toBe(false);
});
