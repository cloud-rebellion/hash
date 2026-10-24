import { expect, test } from 'bun:test';
import { consumeStaffAuthToken, isStaffAuthPath, staffPasswordError } from './staffAuth';

test('account links consume one fragment token into memory and remove fragment/query/history state first', () => {
  const token = 'aB_9-'.repeat(9), calls: unknown[][] = [];
  const location = { pathname: '/reset-password', hash: '#token=' + token };
  const got = consumeStaffAuthToken(location, { replaceState: (...args: unknown[]) => { calls.push(args); location.hash = ''; } });
  expect(calls).toEqual([[null, '', '/reset-password']]);
  expect(got).toBe(token); expect(location.hash).toBe('');
  for (const fragment of ['', '#', '#token=short', '#token=' + token + '&token=' + token, '#token=' + token + '&returnTo=https://private.test', '#token=%00' + token, '#token=%E0%A4%A', '#token=' + 'x'.repeat(1025)]) {
    let stripped = false;
    expect(consumeStaffAuthToken({ pathname: '/verify-email', hash: fragment }, { replaceState() { stripped = true; } })).toBeNull();
    expect(stripped).toBe(true);
  }
});

test('fragment removal failure never returns a token to a page that still exposes it', () => {
  expect(() => consumeStaffAuthToken({ pathname: '/verify-email', hash: '#token=' + 'x'.repeat(43) }, { replaceState() { throw new Error('history unavailable'); } })).toThrow();
});

test('new passwords count Unicode characters, preserve exact whitespace and bound UTF8 bytes', () => {
  expect(staffPasswordError(' normal passphrase ', ' normal passphrase ')).toBeNull();
  expect(staffPasswordError(' normal passphrase ', 'normal passphrase')).toContain('match');
  expect(staffPasswordError('🦊'.repeat(11), '🦊'.repeat(11))).toContain('12');
  expect(staffPasswordError('🦊'.repeat(12), '🦊'.repeat(12))).toBeNull();
  expect(staffPasswordError('🦊'.repeat(256), '🦊'.repeat(256))).toBeNull();
  expect(staffPasswordError('🦊'.repeat(257), '🦊'.repeat(257))).toContain('too long');
  expect(staffPasswordError('x')).toBeNull(); // legacy login is not a new-password policy
  expect(staffPasswordError('')).toContain('Enter');
  expect(staffPasswordError('x'.repeat(1025))).toContain('too long');
});

test('only the fixed native account routes receive auth-page treatment', () => {
  for (const path of ['/login', '/register', '/verify-email', '/forgot-password', '/reset-password', '/reset-password/']) expect(isStaffAuthPath(path)).toBe(true);
  for (const path of ['/', '/login-other', '/sign/token', '/verify', '/settings', '//private.test/login']) expect(isStaffAuthPath(path)).toBe(false);
});
