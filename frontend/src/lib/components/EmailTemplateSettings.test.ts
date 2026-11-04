import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { translateStaffText } from '../staffPreferences';

const source = readFileSync(new URL('./EmailTemplateSettings.svelte', import.meta.url), 'utf8');
test('the actual rendered HTML preview has no interactive or parent privileges', () => {
  const root = parse(source) as unknown as Record<string, unknown>;
  const frames: Record<string, unknown>[] = [];
  function walk(node: unknown) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(walk); return; }
    const value = node as Record<string, unknown>;
    if (value.type === 'Element' && value.name === 'iframe') frames.push(value);
    for (const key of ['html', 'children', 'else']) walk(value[key]);
  }
  walk(root); expect(frames).toHaveLength(1);
  const attrs = frames[0].attributes as { name: string; value: true | { type: string; data?: string }[] }[];
  function text(name: string) { const value = attrs.find(item => item.name === name)?.value; return Array.isArray(value) ? value.map(item => item.data ?? '').join('') : value; }
  expect(text('sandbox')).toBe(''); expect(text('tabindex')).toBe('-1'); expect(text('referrerpolicy')).toBe('no-referrer');
  expect(source).toContain('<div inert>'); expect(source).not.toContain('{@html'); expect(text('class')).toContain('pointer-events-none');
});
test('the actual built-in action edits the draft and never saves or sends by itself', () => {
  const body = source.match(/function resetToBuiltIn\(\) \{([\s\S]*?)\n  \}/)?.[1]; expect(body).toBeDefined();
  const calls: unknown[][] = []; const editor = { edit: (...args: unknown[]) => calls.push(args) };
  new Function('editorLocked', 'editor', body!)(true, editor); expect(calls).toHaveLength(0);
  new Function('editorLocked', 'editor', body!)(false, editor);
  expect(calls).toEqual([['subject_template', ''], ['html_template', ''], ['text_template', '']]);
});
test('new email controls and errors are Swedish through the real staff preferences API', () => {
  expect(translateStaffText('sv', 'Email content')).toBe('E-postinnehåll');
  expect(translateStaffText('sv', 'Required content preserved · revision {revision}', { revision: 7 })).toBe('Obligatoriskt innehåll bevarat · version 7');
  expect(translateStaffText('sv', 'Only workspace owners can manage email templates.')).toContain('ägare');
  expect(translateStaffText('en', 'Email templates')).toBe('Email templates');
});

test('sample-send uses current saved identity and every original-owner dirty/conflict/busy barrier', () => {
  const tree: any = parse(source, { modern: true }); let guard: any;
  function walk(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.name === 'EmailTemplateSampleSend') { const value = node.attributes.find((a: any) => a.name === 'disabled').value; guard = (Array.isArray(value) ? value[0] : value).expression; }
    for (const value of Object.values(node)) { if (Array.isArray(value)) value.forEach(walk); else if (value && typeof value === 'object') walk(value); }
  }
  walk(tree.fragment); expect(guard).toBeDefined();
  const disabled = new Function('env', `with(env) { return ${source.slice(guard.start, guard.end)}; }`);
  const env = { busy: false, $editor: { dirty: false, authorized: true, conflict: false } }; expect(disabled(env)).toBe(false);
  for (const flag of ['dirty', 'conflict']) { (env.$editor as any)[flag] = true; expect(disabled(env)).toBe(true); (env.$editor as any)[flag] = false; }
  env.$editor.authorized = false; expect(disabled(env)).toBe(true); env.$editor.authorized = true; env.busy = true; expect(disabled(env)).toBe(true);
  expect(source).toContain("{#key $editor.selected.kind + ':' + $editor.selected.revision}");
});
