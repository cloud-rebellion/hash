import { expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { isNoticePath, isStaffAuthPath, needsSession, routeCategory, routeSurface, showsStaffChrome } from './routeSurface';

test('every top-level route directory is classified', () => {
  const dir = new URL('../routes/', import.meta.url);
  const names = readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  expect(names.length).toBeGreaterThan(10);
  for (const name of names) expect(routeSurface('/' + name)).not.toBe('unknown');
});

test('surfaces', () => {
  expect(routeSurface('/')).toBe('home');
  for (const p of ['/login', '/register', '/verify-email', '/forgot-password', '/reset-password', '/login/']) expect(routeSurface(p)).toBe('auth-screen');
  for (const p of ['/sign/tok', '/completed/t', '/notice/n', '/legal/terms', '/auth/login']) expect(routeSurface(p)).toBe('public');
  for (const p of ['/verify', '/verify/', '/verify/x']) expect(routeSurface(p)).toBe('verify');
  for (const p of ['/dashboard', '/documents/1', '/templates/html/new', '/settings/members', '/help']) expect(routeSurface(p)).toBe('staff');
  for (const p of ['/signatures', '/verifyx', '/nope', '/documents/%2e%2e/x', '/a%2Fb', '/%E0%A4%A']) expect(routeSurface(p)).toBe('unknown');
});

test('L1: a public root with an encoded separator in its dynamic segment stays public', () => {
  for (const p of ['/sign/a%2Fb', '/sign/tok%5C', '/notice/a%2Fb', '/completed/t%00', '/%73ign/a%2Fb', '/legal/%2e%2e']) {
    expect(routeSurface(p)).toBe('public');
    expect(needsSession(p)).toBe(false);
    expect(showsStaffChrome(p)).toBe(false);
  }
  expect(isNoticePath('/notice/a%2Fb')).toBe(true);
  expect(routeCategory('/sign/a%2Fb')).toBe('signer');
  for (const p of ['/documents%2F..%2Fsign', '/dashboard/a%2Fb', '/si%2Fgn/x']) expect(needsSession(p)).toBe(false);
  expect(routeSurface('/documents/..%2Fdata-subject%2Fexport')).toBe('unknown');
});

test('chrome and session needs are separate', () => {
  expect(showsStaffChrome('/verify')).toBe(true);
  expect(needsSession('/verify')).toBe(false);
  expect(showsStaffChrome('/dashboard') && needsSession('/dashboard')).toBe(true);
  expect(showsStaffChrome('/login')).toBe(false);
  expect(showsStaffChrome('/sign/x')).toBe(false);
  expect(needsSession('/nope')).toBe(false);
});

test('helpers and telemetry categories', () => {
  expect(isStaffAuthPath('/reset-password')).toBe(true);
  expect(isNoticePath('/notice/abc')).toBe(true);
  expect(isNoticePath('/noticeboard')).toBe(false);
  expect(routeCategory('/')).toBe('home');
  expect(routeCategory('/sign/secret-token')).toBe('signer');
  expect(routeCategory('/verify')).toBe('verify');
  expect(routeCategory('/help')).toBe('other');
});

test('no other module classifies routes by prefix', () => {
  const lib = new URL('./', import.meta.url);
  for (const file of ['sessionExpiry.ts', 'flare-client.ts', 'staffAuth.ts']) {
    expect(readFileSync(new URL(file, lib), 'utf8')).not.toMatch(/startsWith\('\/(sign|notice|legal|completed|auth|verify|dashboard)/);
  }
  const layout = readFileSync(new URL('../routes/+layout.svelte', import.meta.url), 'utf8');
  expect(layout).not.toMatch(/startsWith\('\/(sign|notice|legal|completed|auth|verify)/);
});
