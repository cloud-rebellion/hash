// Staff preferences are independent of the signer ceremony and its legal language.
import { derived, readonly, writable } from 'svelte/store';
import { swedishStaffMessages } from './staffMessages';

export type StaffLocale = 'en' | 'sv';
export type StaffTheme = 'system' | 'light' | 'dark';
export type StaffResolvedTheme = 'light' | 'dark';
export type StaffTextParameters = Record<string, string | number>;

const LOCALE_KEY = 'hash_staff_locale';
const THEME_KEY = 'hash_staff_theme';

export interface StaffPreferencesEnvironment {
  storage?: Pick<Storage, 'getItem' | 'setItem'>;
  systemDark?: { matches: boolean; subscribe: (listener: () => void) => () => void };
  applyTheme?: (theme: StaffResolvedTheme) => void;
}

function browserEnvironment(): StaffPreferencesEnvironment | undefined {
  if (typeof window === 'undefined') return undefined;
  let storage: StaffPreferencesEnvironment['storage'];
  let systemDark: StaffPreferencesEnvironment['systemDark'];
  try { storage = window.localStorage; } catch { /* Storage can be blocked. */ }
  try {
    const query = window.matchMedia('(prefers-color-scheme: dark)');
    systemDark = {
      get matches() { return query.matches; },
      subscribe(listener) {
        if (typeof query.addEventListener === 'function') {
          query.addEventListener('change', listener);
          return () => query.removeEventListener('change', listener);
        }
        query.addListener(listener);
        return () => query.removeListener(listener);
      },
    };
  } catch { /* Unsupported media queries fall back to light. */ }
  return {
    storage, systemDark,
    applyTheme(theme) {
      document.documentElement.dataset.theme = theme;
      document.documentElement.style.colorScheme = theme;
    },
  };
}

export function translateStaffText(locale: StaffLocale, text: string, params?: StaffTextParameters): string {
  let translated = locale === 'sv' && Object.hasOwn(swedishStaffMessages, text)
    ? swedishStaffMessages[text] : text;
  for (const [key, value] of Object.entries(params ?? {})) {
    translated = translated.replaceAll(`{${key}}`, () => String(value));
  }
  return translated;
}

// The factory makes the same browser behavior testable without browser globals.
export function createStaffPreferences(environment: () => StaffPreferencesEnvironment | undefined = browserEnvironment) {
  const locale = writable<StaffLocale>('en');
  const theme = writable<StaffTheme>('system');
  const resolvedTheme = writable<StaffResolvedTheme>('light');
  let selectedTheme: StaffTheme = 'system';

  function applyTheme(env = environment()) {
    const resolved = selectedTheme === 'system'
      ? (env?.systemDark?.matches ? 'dark' : 'light') : selectedTheme;
    resolvedTheme.set(resolved);
    env?.applyTheme?.(resolved);
  }
  function read(env: StaffPreferencesEnvironment | undefined, key: string) {
    try { return env?.storage?.getItem(key); } catch { return null; }
  }
  function persist(key: string, value: string) {
    try { environment()?.storage?.setItem(key, value); } catch { /* Keep the in-tab choice. */ }
  }
  function setLocale(value: StaffLocale) {
    if (value !== 'en' && value !== 'sv') return;
    locale.set(value);
    persist(LOCALE_KEY, value);
  }
  function setTheme(value: StaffTheme) {
    if (value !== 'system' && value !== 'light' && value !== 'dark') return;
    selectedTheme = value;
    theme.set(value);
    persist(THEME_KEY, value);
    applyTheme();
  }
  function initialize() {
    const env = environment();
    if (!env) return () => {};
    const savedLocale = read(env, LOCALE_KEY);
    locale.set(savedLocale === 'sv' ? 'sv' : 'en');
    const savedTheme = read(env, THEME_KEY);
    selectedTheme = savedTheme === 'light' || savedTheme === 'dark' ? savedTheme : 'system';
    theme.set(selectedTheme);
    applyTheme(env);
    try { return env.systemDark?.subscribe(() => applyTheme(env)) ?? (() => {}); }
    catch { return () => {}; }
  }
  return {
    staffLocale: readonly(locale), staffTheme: readonly(theme), staffResolvedTheme: readonly(resolvedTheme),
    setStaffLocale: setLocale, setStaffTheme: setTheme, initializeStaffPreferences: initialize,
    ui: derived(locale, value => (text: string, params?: StaffTextParameters) => translateStaffText(value, text, params)),
  };
}

export const {
  staffLocale, staffTheme, staffResolvedTheme, setStaffLocale, setStaffTheme, initializeStaffPreferences, ui,
} = createStaffPreferences();
