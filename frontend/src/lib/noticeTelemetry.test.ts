import { expect, test } from 'bun:test';
import { captureFlarePDFViewError, installFlareBrowserCapture, installRuntimeFlareBrowserCapture } from './flare-client';
import { handleError } from '../hooks.client';

test('notice pages initialize no telemetry and an existing app reporter pauses before reading events then resumes and retires', async () => {
 const original = new Map<string, PropertyDescriptor | undefined>(), listeners = new Map<string, Set<any>>(), requests: string[] = [];
 const location = { origin: 'https://hash.test', pathname: '/notice/11111111-1111-4111-8111-111111111111', get hash() { throw Error('telemetry must not inspect fragment'); }, get href() { throw Error('telemetry must not inspect URL'); } };
 const put = (key: string, value: unknown) => { original.set(key, Object.getOwnPropertyDescriptor(globalThis, key)); Object.defineProperty(globalThis, key, { value, writable: true, configurable: true }); };
 class ResourceElement { constructor(readonly tagName: string) {} }
 put('location', location); put('Element', ResourceElement); put('window', { addEventListener(name: string, fn: any) { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name)!.add(fn); }, removeEventListener(name: string, fn: any) { listeners.get(name)?.delete(fn); } });
 put('fetch', async (_url: unknown, init: RequestInit) => { requests.push(String(init.body)); return new Response(null, { status: 202 }); }); const stops: (() => void)[] = [];
 const emit = (name: string, event: object) => { for (const fn of listeners.get(name) ?? []) fn(event); };
 const normalError = (line: number) => { const value = new Error('private error text'); value.stack = 'Error: private\n at original (https://hash.test/_app/immutable/chunks/app.ABC123.js:' + line + ':9)'; return { error: value, target: null }; };
 try {
  stops.push(installRuntimeFlareBrowserCapture()); captureFlarePDFViewError(); handleError({} as never);
  stops.push(installFlareBrowserCapture({ dsn: 'https://browser-ingest@flare.test/hash', environment: 'test', release: 'exact-test' }));
  await Promise.resolve(); expect(requests).toEqual([]); expect([...listeners.values()].reduce((sum, rows) => sum + rows.size, 0)).toBe(0);
  location.pathname = '/documents'; const stop = installFlareBrowserCapture({ dsn: 'https://browser-ingest@flare.test/hash', environment: 'test', release: 'exact-test' }); stops.push(stop);
  emit('error', normalError(17)); expect(requests).toHaveLength(1); expect(requests[0]).not.toContain('private error text');
  location.pathname = '/notice/11111111-1111-4111-8111-111111111111'; let inspected = 0;
  const privateEvent = { get target() { inspected++; throw Error('private event'); }, get error() { inspected++; throw Error('private event'); }, get reason() { inspected++; throw Error('private event'); }, get detail() { inspected++; throw Error('private event'); } };
  for (const name of ['error', 'unhandledrejection', 'flare:exception']) emit(name, privateEvent);
  captureFlarePDFViewError(); handleError({} as never); await Promise.resolve(); expect(inspected).toBe(0); expect(requests).toHaveLength(1);
  location.pathname = '/documents'; emit('error', normalError(19)); expect(requests).toHaveLength(2);
  const retained = [...(listeners.get('error') ?? [])]; stop(); expect([...listeners.values()].reduce((sum, rows) => sum + rows.size, 0)).toBe(0); for (const fn of retained) fn(normalError(21)); expect(requests).toHaveLength(2);
 } finally { for (const stop of stops.reverse()) stop(); for (const [name, value] of original) { if (value) Object.defineProperty(globalThis, name, value); else Reflect.deleteProperty(globalThis, name); } }
});
