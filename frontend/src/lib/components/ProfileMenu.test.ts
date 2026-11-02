import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';

const source = readFileSync(new URL('./ProfileMenu.svelte', import.meta.url), 'utf8');
const tree: any = parse(source, { modern: true });
const functions = ['closeMenu', 'outside', 'handleKeydown'].map(name => {
  const node = tree.instance.content.body.find((node: any) => node.type === 'FunctionDeclaration' && node.id.name === name);
  return source.slice(node.start, node.end);
});
const code = new Bun.Transpiler({ loader: 'ts' }).transformSync(functions.join('\n'));
const bind = new Function('env', `with(env) { ${code}; return { closeMenu, outside, handleKeydown }; }`);

function fixture() {
  const focused: string[] = [], items = ['settings', 'api', 'help', 'logout'].map(name => ({ focus: () => focused.push(name) }));
  const trigger = { focus: () => focused.push('trigger') };
  const panel = { contains: (node: unknown) => items.includes(node as any), querySelectorAll: () => items };
  const env: any = { open: false, trigger, panel, tick: async () => {}, container: { contains: (node: unknown) => node === trigger || node === panel || items.includes(node as any) } };
  return { env, items, focused, ...bind(env) };
}

test('the actual account menu opens with arrow keys, cycles existing links and closes with Escape restoring focus', async () => {
  const f = fixture(); let prevented = 0;
  await f.handleKeydown({ key: 'ArrowDown', target: f.env.trigger, preventDefault: () => prevented++ });
  expect(f.env.open).toBe(true); expect(f.focused).toEqual(['settings']);
  await f.handleKeydown({ key: 'ArrowUp', target: f.items[0], preventDefault: () => prevented++ });
  expect(f.focused.at(-1)).toBe('logout');
  await f.handleKeydown({ key: 'ArrowDown', target: f.items.at(-1), preventDefault: () => prevented++ });
  expect(f.focused.at(-1)).toBe('settings');
  await f.handleKeydown({ key: 'Escape', preventDefault: () => prevented++ });
  expect(f.env.open).toBe(false); expect(f.focused.at(-1)).toBe('trigger'); expect(prevented).toBe(4);
  await f.handleKeydown({ key: 'ArrowUp', target: f.env.trigger, preventDefault() {} });
  expect(f.focused.at(-1)).toBe('logout');
});

test('outside activation closes the panel while inside activation and native Tab/select keys remain unaffected', async () => {
  const f = fixture(); f.env.open = true;
  f.outside({ target: f.items[0] }); expect(f.env.open).toBe(true);
  f.outside({ target: {} }); expect(f.env.open).toBe(false); expect(f.focused).toEqual([]);
  f.env.open = true; let prevented = false;
  await f.handleKeydown({ key: 'Tab', target: f.items[0], preventDefault: () => { prevented = true; } });
  await f.handleKeydown({ key: 'ArrowDown', target: { tagName: 'SELECT' }, preventDefault: () => { prevented = true; } });
  expect(prevented).toBe(false);
});

function nodes(node: any): any[] {
  if (!node || typeof node !== 'object') return [];
  return [node, ...Object.values(node).flatMap(value => Array.isArray(value) ? value.flatMap(nodes) : nodes(value))];
}
function text(node: any, name: string) {
  const value = node.attributes?.find((attr: any) => attr.name === name)?.value;
  return Array.isArray(value) && value[0]?.type === 'Text' ? value[0].data : undefined;
}

test('the actual profile links and preference controls are wired, owner key management is scoped, and logout stays inside the panel', () => {
  const all = nodes(tree.fragment), button = all.find(node => node.name === 'button');
  expect(text(button, 'type')).toBe('button'); expect(text(button, 'aria-controls')).toBe('hash-account-panel');
  expect(button.attributes.some((attr: any) => attr.name === 'aria-expanded')).toBe(true);
  expect(source).toContain("{email || $ui('Account')}");
  expect(source).toContain("$ui('Account menu') + (email ? ': ' + email : '')");
  const hrefs = all.filter(node => node.name === 'a').map(node => text(node, 'href'));
  expect(hrefs).toEqual(['/settings', '/settings/api-keys', '/help#mcp', '/help']);
  const ownerGuard = all.find(node => node.type === 'IfBlock' && source.slice(node.test.start, node.test.end) === "role === 'owner'");
  expect(ownerGuard).toBeDefined(); expect(nodes(ownerGuard.consequent).some(node => text(node, 'href') === '/settings/api-keys')).toBe(true);
  expect(all.filter(node => node.name === 'LogoutButton')).toHaveLength(1);
  const panel = all.find(node => node.name === 'div' && text(node, 'id') === 'hash-account-panel');
  expect(panel.attributes.some((attr: any) => attr.name === 'hidden')).toBe(true);
  expect(source).not.toContain('{#if open}');
  const selects = all.filter(node => node.name === 'select'); expect(selects.map(node => text(node, 'id'))).toEqual(['hash-staff-language']);
  expect(all.filter(node => node.name === 'option').map(node => text(node, 'value'))).toEqual(['en', 'sv']);
  const layout = readFileSync(new URL('../../routes/+layout.svelte', import.meta.url), 'utf8');
  expect(layout).toContain('<ProfileMenu email={me?.email} role={me?.role} currentPath={path} />');
  expect(layout).not.toContain('<LogoutButton');
  expect(layout).not.toContain("{ href: '/settings'");
  expect(layout).toContain('lang={$staffLocale}');
});
