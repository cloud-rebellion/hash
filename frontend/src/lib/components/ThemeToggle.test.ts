import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { compile, parse } from 'svelte/compiler';
import { get } from 'svelte/store';
import { createStaffPreferences } from '../staffPreferences';

const source = readFileSync(new URL('./ThemeToggle.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
function nodes(node: any): any[] {
  if (!node || typeof node !== 'object') return [];
  return [node, ...Object.values(node).flatMap(value => Array.isArray(value) ? value.flatMap(nodes) : nodes(value))];
}
const buttons = nodes(tree.fragment).filter(node => node.name === 'button');
const fn = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === 'chooseTheme');
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(source.slice(fn.start, fn.end));
const bind = new Function('env', `with(env) { ${code}; return { chooseTheme }; }`);
function evaluate(attribute: string, button: any, env: any) {
  const value = button.attributes.find((a: any) => a.name === attribute).value;
  const expression = (Array.isArray(value) ? value[0] : value).expression;
  return new Function('env', `with(env) { return (${source.slice(expression.start, expression.end)}); }`)(env);
}

test('real header button handlers retain system appearance until a click, then persist the selected explicit mode', () => {
  const writes: [string, string][] = [], listeners = new Set<() => void>();
  const media = { matches: true, subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; } };
  const preferences = createStaffPreferences(() => ({
    storage: { getItem: () => null, setItem: (key, value) => { writes.push([key, value]); } }, systemDark: media,
  }));
  const close = preferences.initializeStaffPreferences();
  const env: any = { setStaffTheme: preferences.setStaffTheme, get $staffResolvedTheme() { return get(preferences.staffResolvedTheme); } };
  Object.assign(env, bind(env));
  expect(get(preferences.staffTheme)).toBe('system');
  expect(buttons.map(button => evaluate('aria-pressed', button, env))).toEqual([false, true]);
  expect(writes).toEqual([]);
  media.matches = false; for (const listener of listeners) listener();
  expect(buttons.map(button => evaluate('aria-pressed', button, env))).toEqual([true, false]);
  evaluate('onclick', buttons[1], env)();
  expect(get(preferences.staffTheme)).toBe('dark');
  expect(writes).toEqual([['hash_staff_theme', 'dark']]);
  for (const listener of listeners) listener();
  expect(buttons.map(button => evaluate('aria-pressed', button, env))).toEqual([false, true]);
  evaluate('onclick', buttons[0], env)();
  expect(get(preferences.staffTheme)).toBe('light');
  expect(writes.at(-1)).toEqual(['hash_staff_theme', 'light']);
  expect(buttons.map(button => evaluate('aria-pressed', button, env))).toEqual([true, false]);
  close(); expect(listeners.size).toBe(0);
});

test('both icon controls remain named native buttons and are immediately before the profile in the authenticated header', () => {
  expect(buttons).toHaveLength(2);
  for (const button of buttons) {
    expect(button.attributes.find((a: any) => a.name === 'type').value[0].data).toBe('button');
    expect(button.attributes.some((a: any) => a.name === 'aria-label')).toBe(true);
    expect(button.attributes.some((a: any) => a.name === 'aria-pressed')).toBe(true);
    expect(nodes(button).find(node => node.name === 'Sun' || node.name === 'Moon')?.attributes.some((a: any) => a.name === 'aria-hidden')).toBe(true);
  }
  const layout = parse(readFileSync(new URL('../../routes/+layout.svelte', import.meta.url), 'utf8'), { modern: true });
  const group = nodes(layout.fragment).find(node => node.name === 'div' && node.fragment?.nodes.some((child: any) => child.name === 'ThemeToggle'));
  expect(group.fragment.nodes.filter((node: any) => node.type === 'Component').map((node: any) => node.name)).toEqual(['ThemeToggle', 'ProfileMenu']);
  for (const generate of ['client', 'server'] as const) {
    const result = compile(source, { filename: 'ThemeToggle.svelte', generate });
    expect(result.warnings.filter(warning => warning.code.startsWith('a11y'))).toEqual([]);
  }
});
