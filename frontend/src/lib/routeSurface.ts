// The only place that classifies SPA routes. The root layout, the session-expiry
// guard, the return-path check and Flare telemetry all read this module. When a
// directory is added under src/routes, add it here; routeSurface.test.ts fails
// until you do.

export type RouteSurface = 'home' | 'auth-screen' | 'public' | 'verify' | 'staff' | 'unknown';

const AUTH_SCREENS = ['/login', '/register', '/verify-email', '/forgot-password', '/reset-password'];
// Public, no staff session: signer ceremony, completed files, notices, legal pages, backend auth.
const PUBLIC_PREFIXES = ['/sign', '/completed', '/notice', '/legal', '/auth'];
// Staff app. These are the only paths a login may return to.
export const STAFF_PREFIXES = ['/dashboard', '/documents', '/templates', '/settings', '/help'];
const FLARE_CATEGORIES: ReadonlyArray<readonly [string, string]> = [
  ['/sign', 'signer'], ['/completed', 'completed'], ['/auth', 'auth'], ['/legal', 'legal'], ['/dashboard', 'dashboard'],
  ['/documents', 'documents'], ['/templates', 'templates'], ['/settings', 'settings'], ['/verify', 'verify']
];

function underPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(prefix + '/');
}

/** Decodes each segment once, as the router does. Null for dot segments, encoded separators or malformed escapes. */
function normalize(raw: string): string | null {
  if (!raw.startsWith('/')) return null;
  const parts: string[] = [];
  for (const segment of raw.split('/').slice(1)) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); } catch { return null; }
    if (decoded === '.' || decoded === '..' || /[\\/\u0000-\u001f\u007f]/.test(decoded)) return null;
    parts.push(decoded);
  }
  while (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return '/' + parts.join('/');
}

/** The decoded first segment, or null. Used when the full path has an encoded separator in a dynamic segment. */
function firstSegment(raw: string): string | null {
  if (!raw.startsWith('/')) return null;
  try { return decodeURIComponent(raw.split('/')[1] ?? ''); } catch { return null; }
}

function isPublicRoot(segment: string | null): boolean {
  return segment !== null && PUBLIC_PREFIXES.some((p) => '/' + segment === p);
}

export function routeSurface(pathname: string): RouteSurface {
  const path = normalize(pathname);
  // /sign/a%2Fb still renders the public [token] page, so a public root wins over a strict-parse failure.
  if (path === null) return isPublicRoot(firstSegment(pathname)) ? 'public' : 'unknown';
  if (path === '/') return 'home';
  if (AUTH_SCREENS.includes(path)) return 'auth-screen';
  if (PUBLIC_PREFIXES.some((p) => underPrefix(path, p))) return 'public';
  if (underPrefix(path, '/verify')) return 'verify';
  if (STAFF_PREFIXES.some((p) => underPrefix(path, p))) return 'staff';
  return 'unknown';
}

export function isStaffAuthPath(pathname: string): boolean {
  return routeSurface(pathname) === 'auth-screen';
}

export function isNoticePath(pathname: string): boolean {
  const path = normalize(pathname);
  return path !== null ? underPrefix(path, '/notice') : firstSegment(pathname) === 'notice';
}

/** Staff navigation chrome. The public verify page keeps it; it is not a session page. */
export function showsStaffChrome(pathname: string): boolean {
  const surface = routeSurface(pathname);
  return surface === 'verify' || surface === 'staff' || surface === 'unknown';
}

/** True only where a 401 from /api/v1 means the staff session ended. */
export function needsSession(pathname: string): boolean {
  return routeSurface(pathname) === 'staff';
}

/** Fixed telemetry route class. Never contains path segments. */
export function routeCategory(pathname: string): string {
  const path = normalize(pathname);
  if (path === '/') return 'home';
  const root = path ?? '/' + (firstSegment(pathname) ?? '');
  for (const [prefix, category] of FLARE_CATEGORIES) {
    if (path === null ? root === prefix : underPrefix(root, prefix)) return category;
  }
  return 'other';
}
