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
  const env = { busy: false, quotaLanguageBlocked: false, $editor: { dirty: false, authorized: true, conflict: false } }; expect(disabled(env)).toBe(false);
  for (const flag of ['dirty', 'conflict']) { (env.$editor as any)[flag] = true; expect(disabled(env)).toBe(true); (env.$editor as any)[flag] = false; }
  env.$editor.authorized = false; expect(disabled(env)).toBe(true); env.$editor.authorized = true; env.busy = true; expect(disabled(env)).toBe(true);
  env.busy = false; env.quotaLanguageBlocked = true; expect(disabled(env)).toBe(true);
  expect(source).toContain("{#key $editor.selected.kind + ':' + $editor.selected.revision}");
});


test('actual preference actions preserve template input and invalidate only quota preview after confirmed reads or possible writes', async () => {
  const tree: any = parse(source, { modern: true });
  const functions = ['loadEmailLanguage', 'saveEmailLanguage'].map(name => { const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name); return source.slice(node.start, node.end); }).join('\n');
  const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions);
  let loads = 0, saves = 0, invalidations = 0;
  const env: any = { alive: true, languageBlocked: false, $preferences: { unconfirmed: false },
    preferences: { load: async () => { loads++; return true; }, save: async () => { saves++; return true; } },
    editor: { draft: { text_template: 'Keep this literal wording' }, invalidateQuotaPreview: () => { invalidations++; }, load: () => { throw Error('Do not discard template inputs'); }, edit: () => { throw Error('Do not translate template prose'); } } };
  const actions = new Function('env', `with(env) { ${code}; return {loadEmailLanguage,saveEmailLanguage}; }`)(env);
  expect(await actions.saveEmailLanguage()).toBe(true); expect(await actions.loadEmailLanguage()).toBe(true); expect(invalidations).toBe(2);
  expect(env.editor.draft.text_template).toBe('Keep this literal wording'); expect(loads).toBe(1); expect(saves).toBe(1);
  env.preferences.save = async () => false; env.$preferences.unconfirmed = true; await actions.saveEmailLanguage(); expect(invalidations).toBe(3);
  env.languageBlocked = true; await actions.saveEmailLanguage(); await actions.loadEmailLanguage(); expect(loads).toBe(1); expect(saves).toBe(1);
  env.languageBlocked = false; env.alive = false; await actions.loadEmailLanguage(); expect(loads).toBe(1);
});
test('workspace language labels and unknown-outcome guidance are Swedish through the real staff API', () => {
  expect(translateStaffText('sv', 'Workspace email language')).toBe('Arbetsytans e-postspråk');
  expect(translateStaffText('sv', 'Saved language: {language}', { language: 'Svenska' })).toBe('Sparat språk: Svenska');
  expect(translateStaffText('sv', 'Saving the email language is unconfirmed. Load the saved value before another save.')).toContain('inte bekräftat');
  expect(translateStaffText('sv', 'Catalog preview only. Voiding a document does not send this email.')).toContain('skickas inte');
});
