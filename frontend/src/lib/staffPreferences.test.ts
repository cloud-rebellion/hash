import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { readFileSync } from 'node:fs';
import { createStaffPreferences, translateStaffText, type StaffPreferencesEnvironment } from './staffPreferences';
import { swedishStaffMessages } from './staffMessages';

function fixture(saved: Record<string, string> = {}, dark = false) {
  const values = new Map(Object.entries(saved));
  const writes: [string, string][] = [];
  const applied: string[] = [];
  const listeners = new Set<() => void>();
  const media = {
    matches: dark,
    subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
  const env: StaffPreferencesEnvironment = {
    storage: { getItem: key => values.get(key) ?? null, setItem(key, value) { values.set(key, value); writes.push([key, value]); } },
    systemDark: media, applyTheme: theme => { applied.push(theme); },
  };
  return { env, values, writes, applied, listeners,
    preferences: createStaffPreferences(() => env),
    changeSystem(value: boolean) { media.matches = value; for (const listener of listeners) listener(); },
  };
}

test('SSR has stable English/system defaults without reading browser globals', () => {
  const p = createStaffPreferences(() => undefined);
  expect(get(p.staffLocale)).toBe('en'); expect(get(p.staffTheme)).toBe('system');
  expect(get(p.staffResolvedTheme)).toBe('light'); expect(p.initializeStaffPreferences()).toBeFunction();
  expect(get(p.ui)('Documents')).toBe('Documents');
});

test('valid staff preferences reload independently of signer language', () => {
  const f = fixture({ hash_staff_locale: 'sv', hash_staff_theme: 'dark', hash_locale: 'en' });
  const dispose = f.preferences.initializeStaffPreferences();
  expect(get(f.preferences.staffLocale)).toBe('sv'); expect(get(f.preferences.staffTheme)).toBe('dark');
  expect(get(f.preferences.staffResolvedTheme)).toBe('dark'); expect(get(f.preferences.ui)('Documents')).toBe('Dokument');
  f.preferences.setStaffLocale('en'); f.preferences.setStaffTheme('light');
  expect(f.writes).toEqual([['hash_staff_locale', 'en'], ['hash_staff_theme', 'light']]);
  expect(f.values.get('hash_locale')).toBe('en'); dispose();
});

test('invalid persisted choices fall back to English and native system appearance', () => {
  for (const saved of [{}, { hash_staff_locale: 'zz', hash_staff_theme: 'sepia' }, { hash_staff_locale: 'SV', hash_staff_theme: ' dark ' }]) {
    const f = fixture(saved, true); const dispose = f.preferences.initializeStaffPreferences();
    expect(get(f.preferences.staffLocale)).toBe('en'); expect(get(f.preferences.staffTheme)).toBe('system');
    expect(get(f.preferences.staffResolvedTheme)).toBe('dark'); expect(f.writes).toHaveLength(0); dispose();
  }
});

test('blocked storage keeps working in-tab choices and native appearance', () => {
  const f = fixture({}, true);
  f.env.storage = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
  const dispose = f.preferences.initializeStaffPreferences();
  expect(get(f.preferences.staffResolvedTheme)).toBe('dark');
  f.preferences.setStaffLocale('sv'); f.preferences.setStaffTheme('light');
  expect(get(f.preferences.ui)('Settings')).toBe('Inställningar');
  expect(get(f.preferences.staffResolvedTheme)).toBe('light'); dispose();
});

test('system appearance follows native changes and explicit appearance wins until switched back', () => {
  const f = fixture(); const dispose = f.preferences.initializeStaffPreferences();
  expect(f.listeners.size).toBe(1); f.changeSystem(true); expect(get(f.preferences.staffResolvedTheme)).toBe('dark');
  f.preferences.setStaffTheme('light'); f.changeSystem(false); f.changeSystem(true);
  expect(get(f.preferences.staffResolvedTheme)).toBe('light');
  f.preferences.setStaffTheme('system'); expect(get(f.preferences.staffResolvedTheme)).toBe('dark');
  dispose(); expect(f.listeners.size).toBe(0);
  f.changeSystem(false); expect(get(f.preferences.staffResolvedTheme)).toBe('dark');
});

test('unavailable media support and listener refusal safely use light appearance', () => {
  for (const env of [{}, { systemDark: { matches: false, subscribe() { throw new Error('unsupported'); } } }]) {
    const p = createStaffPreferences(() => env); expect(() => p.initializeStaffPreferences()()).not.toThrow();
    expect(get(p.staffResolvedTheme)).toBe('light'); p.setStaffTheme('dark'); expect(get(p.staffResolvedTheme)).toBe('dark');
  }
});

test('malformed setter values neither change state nor persist', () => {
  const f = fixture(); f.preferences.setStaffLocale('fr' as never); f.preferences.setStaffTheme('sepia' as never);
  expect(get(f.preferences.staffLocale)).toBe('en'); expect(get(f.preferences.staffTheme)).toBe('system'); expect(f.writes).toHaveLength(0);
});

test('translations stay reactive, preserve unknown labels and substitute values literally', () => {
  const f = fixture(); const seen: string[] = []; const unsubscribe = f.preferences.ui.subscribe(t => { seen.push(t('Documents')); });
  f.preferences.setStaffLocale('sv'); f.preferences.setStaffLocale('en'); unsubscribe();
  expect(seen).toEqual(['Documents', 'Dokument', 'Documents']);
  expect(translateStaffText('sv', 'New label')).toBe('New label');
  expect(translateStaffText('sv', 'New contract from {name}', { name: '$& <Company>' })).toBe('Nytt avtal från $& <Company>');
  expect(translateStaffText('en', 'Hello {name}', { name: 'A' })).toBe('Hello A');
  expect(translateStaffText('sv', 'toString')).toBe('toString');
});

test('every Swedish staff translation is present and preserves replacement names', () => {
  const placeholders = (value: string) => [...value.matchAll(/\{([^{}]+)\}/g)].map(match => match[1]).sort();
  for (const [english, swedish] of Object.entries(swedishStaffMessages)) {
    expect(swedish.trim().length).toBeGreaterThan(0); expect(placeholders(swedish)).toEqual(placeholders(english));
  }
});

test('dark appearance defines the complete existing semantic color palette without filtering document previews', () => {
  const css = readFileSync(new URL('../app.css', import.meta.url), 'utf8');
  const light = css.match(/\[data-theme='light'\]\s*\{([^}]+)\}/)?.[1] ?? '';
  const dark = css.match(/\[data-theme='dark'\]\s*\{([^}]+)\}/)?.[1] ?? '';
  const tokens = (block: string) => [...block.matchAll(/(--t-[a-z-]+):/g)].map(match => match[1]).sort();
  expect(tokens(dark)).toEqual(tokens(light)); expect(tokens(dark).length).toBeGreaterThan(15);
  expect(light).toContain('color-scheme: light'); expect(dark).toContain('color-scheme: dark'); expect(dark).not.toContain('filter:');
});
