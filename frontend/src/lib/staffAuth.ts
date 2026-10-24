export type StaffAuthMode = 'login' | 'register' | 'verify' | 'forgot' | 'reset';

export function isStaffAuthPath(path: string): boolean {
  return ['/login', '/register', '/verify-email', '/forgot-password', '/reset-password'].includes(path.replace(/\/+$/, ''));
}

// The fragment never enters a request URL, DOM field, storage or history state.
// Strip it even when malformed, before the caller starts any asynchronous work.
export function consumeStaffAuthToken(
  location: Pick<Location, 'hash' | 'pathname'>,
  history: Pick<History, 'replaceState'>
): string | null {
  const fragment = location.hash;
  history.replaceState(null, '', location.pathname);
  if (fragment.length > 1024 || !fragment.startsWith('#')) return null;
  const values = new URLSearchParams(fragment.slice(1));
  if ([...values.keys()].length !== 1 || values.getAll('token').length !== 1) return null;
  const token = values.get('token');
  return token && /^[A-Za-z0-9_-]{16,512}$/.test(token) ? token : null;
}

export function staffPasswordError(password: string, confirmation?: string): string | null {
  if (new TextEncoder().encode(password).byteLength > 1024) return 'This password is too long. Use a shorter passphrase.';
  if (confirmation !== undefined && [...password].length < 12) return 'Use at least 12 characters for your password.';
  if (!password) return 'Enter your password.';
  if (confirmation !== undefined && password !== confirmation) return 'The passwords do not match.';
  return null;
}
