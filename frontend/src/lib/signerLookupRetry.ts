// The server token lookup (first statement of every signer POST handler) is
// read-only and refuses with exactly this status, body and Retry-After before any
// signing work starts, so nothing can have been recorded. Only that refusal is
// retried. "signing is temporarily unavailable", network errors and every other
// response are returned or thrown to the caller untouched.
const lookupRefusal = 'signer access is temporarily unavailable';

// True when a response body is the lookup refusal, so the page can show a
// translated sentence instead of raw JSON.
export function isLookupRefusalBody(text: string): boolean {
  try { return JSON.parse(text)?.error === lookupRefusal; } catch { return false; }
}

async function isLookupRefusal(res: Response): Promise<boolean> {
  if (res.status !== 503 || res.headers.get('Retry-After') !== '1') return false;
  try { return (await res.clone().json())?.error === lookupRefusal; } catch { return false; }
}

export async function postWithLookupRetry(
  post: () => Promise<Response>,
  opts: { retries?: number; delayMs?: number; sleep?: (ms: number) => Promise<void>; current?: () => boolean } = {}
): Promise<Response> {
  const { retries = 2, delayMs = 1000, sleep = ms => new Promise<void>(r => setTimeout(r, ms)), current = () => true } = opts;
  let res = await post();
  for (let attempt = 0; attempt < retries && await isLookupRefusal(res); attempt++) {
    await sleep(delayMs);
    if (!current()) return res;
    res = await post();
  }
  return res;
}
