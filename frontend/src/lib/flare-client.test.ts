import { expect, test } from 'bun:test';
import { captureFlarePDFViewError, installFlareBrowserCapture, installRuntimeFlareBrowserCapture } from './flare-client';
import { handleError } from '../hooks.client';

const activeToken = 'Aa_z-9'.repeat(8).slice(0, 43);
const completedToken = 'Bb_X-8'.repeat(8).slice(0, 43);
const privateText = 'PRIVATE contract terms, AI prompt, comment and mail body';
const validConfig = { enabled: true, dsn: 'https://browser-ingest@flare.test/hash', environment: 'test', release: 'exact-test-release', service: 'hash-browser' };

class ResourceElement {
  constructor(readonly tagName: string, private attributes: Record<string, string>) {}
  getAttribute(name: string) { throw new Error('Capture must not read resource URLs: ' + name + JSON.stringify(this.attributes)); }
}

type FetchFixture = (input: RequestInfo | URL, options?: RequestInit) => Promise<Response>;

// The actual exported module serializes every asserted envelope. This fixture
// supplies browser surfaces; the local-receiver test below also uses real HTTP.
function browserFixture() {
  const listeners = new Map<string, Set<EventListenerOrEventListenerObject>>();
  const events: { endpoint: string; body: Blob }[] = [];
  let beaconCalls = 0;
  const requests: { endpoint: string; options: RequestInit }[] = [];
  const original = new Map<string, PropertyDescriptor | undefined>();
  const stops: (() => void)[] = [];
  const page = { origin: 'https://hash.test', pathname: '/completed/' + completedToken, href: 'https://hash.test/completed/' + completedToken };
  let fetchFixture: FetchFixture = async () => new Response(null, { status: 202 });
  const install = (name: string, value: unknown) => {
    if (!original.has(name)) original.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  };
  install('window', {
    addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)!.add(listener);
    },
    removeEventListener(type: string, listener: EventListenerOrEventListenerObject) { listeners.get(type)?.delete(listener); }
  });
  install('location', page);
  install('Element', ResourceElement);
  install('navigator', { sendBeacon() {
    beaconCalls++;
    throw new Error('Beacon is forbidden: its credential mode includes cookies');
  } });
  install('fetch', (input: RequestInfo | URL, options: RequestInit = {}) => {
    requests.push({ endpoint: String(input), options });
    if (options.method === 'POST') events.push({ endpoint: String(input), body: new Blob([String(options.body)], { type: 'text/plain' }) });
    return fetchFixture(input, options);
  });
  return {
    events, requests,
    beaconCalls() { return beaconCalls; },
    setFetch(value: FetchFixture) { fetchFixture = value; },
    setPath(path: string) { page.pathname = path; page.href = page.origin + path; },
    listenerCount() { return [...listeners.values()].reduce((sum, set) => sum + set.size, 0); },
    snapshotListeners(type: string) { return [...(listeners.get(type) ?? [])]; },
    capture(options: Partial<Parameters<typeof installFlareBrowserCapture>[0]> = {}) {
      const stop = installFlareBrowserCapture({ dsn: validConfig.dsn, environment: validConfig.environment, release: validConfig.release, ...options });
      stops.push(stop); return stop;
    },
    runtime() { const stop = installRuntimeFlareBrowserCapture(); stops.push(stop); return stop; },
    emit(type: string, event: object) {
      for (const listener of [...(listeners.get(type) ?? [])]) {
        if (typeof listener === 'function') listener(event as Event);
        else listener.handleEvent(event as Event);
      }
    },
    close() {
      for (const stop of stops.reverse()) stop();
      for (const [name, descriptor] of original) {
        if (descriptor) Object.defineProperty(globalThis, name, descriptor);
        else Reflect.deleteProperty(globalThis, name);
      }
    }
  };
}

async function settle() { await new Promise(resolve => setTimeout(resolve, 0)); }

test('native account pages never initialize telemetry or emit through already-installed callbacks', async () => {
  for (const path of ['/login', '/register', '/verify-email', '/forgot-password', '/reset-password']) {
    const browser = browserFixture();
    try {
      browser.capture(); // an app-layout listener may survive client navigation
      browser.setPath(path);
      const requests = browser.requests.length;
      browser.runtime();
      browser.capture();
      browser.emit('error', { error: new Error('PRIVATE PASSWORD TOKEN') });
      browser.emit('unhandledrejection', { reason: new Error('PRIVATE PASSWORD TOKEN') });
      captureFlarePDFViewError();
      expect(handleError(privateHookInput().input)).toBeUndefined();
      await settle();
      expect(browser.requests).toHaveLength(requests);
      expect(browser.events).toHaveLength(0);
    } finally { browser.close(); }
  }
});
async function waitFor(condition: () => boolean) {
  for (let i = 0; i < 100 && !condition(); i++) await new Promise(resolve => setTimeout(resolve, 2));
  expect(condition()).toBe(true);
}
function configResponse(value: unknown = validConfig, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
function diagnosticError(line = 17) {
  const error = new Error(privateText + ' /sign/' + activeToken);
  error.name = 'PRIVATE /completed/' + completedToken;
  error.stack = 'Error: ' + privateText + '\n' +
    '    at PRIVATE_FUNCTION (https://hash.test/_app/immutable/chunks/portal.ABC123.js?token=SECRET#PRIVATE:' + line + ':9)\n' +
    '    at private (https://hash.test/completed/' + completedToken + ':4:2)\n' +
    '    at private (https://other.test/_app/immutable/chunks/foreign.js:1:2)\n' +
    '    at private (data:text/javascript,PRIVATE:1:2)';
  return error;
}
function assertPrivateAbsent(raw: string) {
  for (const value of [activeToken, completedToken, privateText, 'PRIVATE_FUNCTION', 'SECRET', 'other.test', 'data:text', 'private@example.test']) expect(raw).not.toContain(value);
}

test('Flare sends fixed error categories and only safe same-origin immutable code frames', async () => {
  const browser = browserFixture();
  let toJSONCalled = false;
  let stackGetterCalled = false;
  try {
    browser.capture();
    browser.emit('error', { error: diagnosticError(), target: null });
    browser.emit('unhandledrejection', { reason: {
      contract: privateText, url: '/sign/' + activeToken, email: 'private@example.test',
      toJSON() { toJSONCalled = true; throw new Error(privateText); },
      get stack() { stackGetterCalled = true; throw new Error(privateText); }
    } });
    browser.emit('error', { target: new ResourceElement('SCRIPT', { src: '/completed/' + completedToken + '?secret=SECRET' }) });
    browser.emit('flare:exception', { detail: { error: diagnosticError(), componentStack: '    at PRIVATE_FUNCTION (https://hash.test/_app/immutable/nodes/3.ABC123.js:8:4)' } });
    expect(browser.events).toHaveLength(4);
    const payloads = [];
    for (const entry of browser.events) {
      const raw = await entry.body.text(); assertPrivateAbsent(raw); payloads.push(JSON.parse(raw));
      expect(entry.endpoint).toBe('https://flare.test/api/hash/events?sentry_key=browser-ingest&sentry_version=7');
    }
    expect(toJSONCalled).toBe(false); expect(stackGetterCalled).toBe(false); expect(browser.beaconCalls()).toBe(0);
    expect(payloads.map(p => p.message)).toEqual(['Browser JavaScript error', 'Unhandled browser rejection', 'Browser resource load failed', 'Browser render boundary failed']);
    expect(payloads[0].exception.values[0].stacktrace.frames).toEqual([{ filename: 'https://hash.test/_app/immutable/chunks/portal.ABC123.js', lineno: 17, colno: 9, in_app: true }]);
    expect(payloads[1].exception.values[0].stacktrace.frames).toEqual([]);
    expect(payloads[2].tags.resource_type).toBe('script');
    expect(payloads[3].exception.values[0].stacktrace.frames[0].filename).toBe('https://hash.test/_app/immutable/nodes/3.ABC123.js');
    for (const payload of payloads) {
      expect(payload.request).toBeUndefined();
      expect(payload.tags.service).toBe('hash-browser'); expect(payload.tags.route).toBe('completed');
      expect(payload.environment).toBe('test'); expect(payload.release).toBe('exact-test-release');
    }
  } finally { browser.close(); }
});

test('Flare deduplicates fixed diagnostics, bounds the event rate and raw stack scan', async () => {
  const browser = browserFixture();
  try {
    browser.capture({ maxEventsPerMinute: 2 });
    browser.emit('error', { error: diagnosticError(1), target: null });
    browser.emit('error', { error: diagnosticError(1), target: null });
    browser.emit('error', { error: diagnosticError(2), target: null });
    browser.emit('error', { error: diagnosticError(3), target: null });
    expect(browser.events).toHaveLength(2);
    const stop = browser.capture(); stop(); // A second installation cannot remove the first owner.
    expect(browser.listenerCount()).toBe(4);
  } finally { browser.close(); }
  const bounded = browserFixture();
  try {
    bounded.capture();
    const error = diagnosticError();
    error.stack = privateText.repeat(1000) + '\n    at private (https://hash.test/_app/immutable/chunks/late.js:1:2)';
    bounded.emit('error', { error, target: null });
    const raw = await bounded.events[0].body.text(); assertPrivateAbsent(raw);
    expect(JSON.parse(raw).exception.values[0].stacktrace.frames).toEqual([]);
    expect(raw.length).toBeLessThan(2048);
  } finally { bounded.close(); }
});

test('Flare credential-free fetch never calls Beacon and private transport failures never throw', async () => {
  const browser = browserFixture();
  try {
    browser.capture();
    browser.setFetch(async () => { throw new Error(privateText); });
    expect(() => browser.emit('unhandledrejection', { reason: privateText })).not.toThrow();
    await settle();
    expect(browser.requests).toHaveLength(1); expect(browser.beaconCalls()).toBe(0);
    const request = browser.requests[0];
    assertPrivateAbsent(String(request.options.body));
    expect(request.options).toMatchObject({ method: 'POST', credentials: 'omit', mode: 'no-cors', keepalive: true, headers: { 'Content-Type': 'text/plain' } });
    expect(request.options.headers).not.toHaveProperty('Authorization');
    expect(JSON.parse(String(request.options.body)).tags.operation).toBe('browser.promise');
  } finally { browser.close(); }
});

test('Flare runtime config and actual serialized event reach a local HTTP receiver without user data', async () => {
  const actualFetch = globalThis.fetch;
  const received: { path: string; method: string; raw: string; cookie: string | null; authorization: string | null; contentType: string | null }[] = [];
  let origin = '';
  const receiver = Bun.serve({ hostname: '127.0.0.1', port: 0, async fetch(request) {
    const path = new URL(request.url).pathname;
    received.push({ path, method: request.method, raw: await request.text(), cookie: request.headers.get('Cookie'), authorization: request.headers.get('Authorization'), contentType: request.headers.get('Content-Type') });
    if (path === '/api/telemetry/config') return configResponse({ ...validConfig, dsn: origin.replace('http://', 'http://browser-ingest@') + '/hash', environment: 'development' });
    return new Response(null, { status: 202 });
  } });
  origin = 'http://127.0.0.1:' + receiver.port;
  const browser = browserFixture();
  try {
    browser.setFetch((input, options) => actualFetch(String(input) === '/api/telemetry/config' ? origin + String(input) : input, options));
    const stop = browser.runtime();
    await waitFor(() => browser.listenerCount() === 4);
    expect(browser.requests[0]).toMatchObject({ endpoint: '/api/telemetry/config', options: { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error' } });
    browser.emit('error', { error: diagnosticError(), target: null });
    await waitFor(() => received.length === 2);
    expect(browser.beaconCalls()).toBe(0);
    const event = received[1];
    expect(event.path).toBe('/api/hash/events'); expect(event.method).toBe('POST');
    expect(event.contentType).toBe('text/plain'); expect(event.cookie).toBeNull(); expect(event.authorization).toBeNull();
    assertPrivateAbsent(event.raw);
    const payload = JSON.parse(event.raw);
    expect(payload.message).toBe('Browser JavaScript error'); expect(payload.release).toBe(validConfig.release); expect(payload.environment).toBe('development');
    expect(payload.exception.values[0].stacktrace.frames).toHaveLength(1);
    stop(); expect(browser.listenerCount()).toBe(0);
    browser.emit('unhandledrejection', { reason: privateText });
    await settle(); expect(received).toHaveLength(2);
  } finally { browser.close(); await receiver.stop(true); }
});

test('Flare config failures and invalid or oversized public config install no listeners', async () => {
  const cases: (() => Promise<Response>)[] = [
    async () => { throw new Error(privateText); },
    async () => configResponse(validConfig, 503),
    async () => configResponse({ enabled: false }),
    async () => configResponse({ ...validConfig, service: 'private-service' }),
    async () => configResponse({ ...validConfig, extra: privateText }),
    async () => configResponse({ ...validConfig, dsn: 'https://key:private@flare.test/hash' }),
    async () => configResponse({ ...validConfig, dsn: 'http://browser-ingest@127.0.0.1/hash', environment: 'production' }),
    async () => configResponse({ ...validConfig, release: privateText }),
    async () => new Response('x'.repeat(4097), { headers: { 'Content-Type': 'application/json' } }),
    async () => new Response(JSON.stringify(validConfig), { headers: { 'Content-Type': 'text/plain' } })
  ];
  for (const response of cases) {
    const browser = browserFixture();
    try {
      browser.setFetch(response); browser.runtime(); await settle();
      expect(browser.listenerCount()).toBe(0); expect(browser.events).toHaveLength(0);
      expect(browser.requests).toHaveLength(1);
    } finally { browser.close(); }
  }
});

test('Flare unmount aborts pending configuration and refuses late listener installation', async () => {
  const browser = browserFixture();
  let resolveConfig!: (response: Response) => void;
  try {
    browser.setFetch(() => new Promise(resolve => { resolveConfig = resolve; }));
    const stop = browser.runtime();
    expect(browser.listenerCount()).toBe(0); expect(browser.requests).toHaveLength(1);
    const signal = browser.requests[0].options.signal!;
    stop(); expect(signal.aborted).toBe(true);
    resolveConfig(configResponse()); await settle();
    expect(browser.listenerCount()).toBe(0);
    browser.emit('error', { error: diagnosticError(), target: null });
    expect(browser.events).toHaveLength(0);
  } finally { browser.close(); }
});

test('Flare cleanup closes captured callback references as well as removing listeners', () => {
  const browser = browserFixture();
  try {
    const stop = browser.capture();
    const heldListeners = browser.snapshotListeners('error');
    stop(); stop(); expect(browser.listenerCount()).toBe(0);
    for (const listener of heldListeners) {
      if (typeof listener === 'function') listener({ error: diagnosticError(), target: null } as unknown as Event);
    }
    expect(browser.events).toHaveLength(0);
  } finally { browser.close(); }
});


test('Flare unmount cancels an already-started bounded config body read', async () => {
  const browser = browserFixture();
  let canceled = false;
  let bodyRead = false;
  try {
    browser.setFetch(async () => new Response(new ReadableStream<Uint8Array>({
      pull() { bodyRead = true; },
      cancel() { canceled = true; }
    }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } }));
    const stop = browser.runtime();
    await waitFor(() => bodyRead);
    stop(); await waitFor(() => canceled);
    expect(browser.listenerCount()).toBe(0); expect(browser.events).toHaveLength(0);
  } finally { browser.close(); }
});


test('Flare metadata refusal cancels the actual untouched config body before unmount', async () => {
  for (const tc of [
    { status: 503, headers: { 'Content-Type': 'application/json' } },
    { status: 200, headers: { 'Content-Type': 'text/plain' } },
    { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Length': '4097' } },
    { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Length': 'invalid' } }
  ]) {
    const browser = browserFixture();
    let readCalls = 0;
    let cancelCalls = 0;
    try {
      browser.setFetch(async () => new Response(new ReadableStream<Uint8Array>({
        pull() { readCalls++; },
        cancel() { cancelCalls++; }
      }, { highWaterMark: 0 }), tc));
      browser.runtime();
      await waitFor(() => cancelCalls === 1);
      await settle();
      expect(readCalls).toBe(0); expect(cancelCalls).toBe(1);
      expect(browser.requests[0].options.signal!.aborted).toBe(true);
      expect(browser.listenerCount()).toBe(0); expect(browser.events).toHaveLength(0);
    } finally { browser.close(); }
  }
});

test('Flare invalid UTF8 and over-budget streaming config cancel the actual reader before EOF', async () => {
  for (const bytes of [new Uint8Array([0xff]), new Uint8Array(4097).fill(32)]) {
    const browser = browserFixture();
    let cancelCalls = 0;
    try {
      browser.setFetch(async () => new Response(new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(bytes); },
        // Deliberately no close: a decoder/size refusal must cancel the live
        // reader rather than leave the response waiting until unmount/timeout.
        cancel() { cancelCalls++; }
      }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } }));
      browser.runtime();
      await waitFor(() => cancelCalls === 1);
      await settle();
      expect(cancelCalls).toBe(1);
      expect(browser.requests[0].options.signal!.aborted).toBe(true);
      expect(browser.listenerCount()).toBe(0); expect(browser.events).toHaveLength(0);
    } finally { browser.close(); }
  }
});


// These invoke the actual SvelteKit export, never a reconstructed callback.
// Its argument is deliberately hostile: no supplied diagnostic can be read.
function privateHookInput() {
  let reads = 0;
  const input = Object.fromEntries(['error', 'event', 'status', 'message'].map(key => [key, undefined]));
  for (const key of Object.keys(input)) Object.defineProperty(input, key, { get() { reads++; throw new Error(privateText); } });
  Object.defineProperty(input, 'toJSON', { value() { reads++; throw new Error(privateText); } });
  return { input: input as unknown as Parameters<typeof handleError>[0], reads: () => reads };
}

test('SvelteKit handled render errors use the installed private-safe sender and default fallback', async () => {
  const browser = browserFixture();
  const poisoned = privateHookInput();
  try {
    browser.capture({ maxEventsPerMinute: 1 });
    expect(handleError(poisoned.input)).toBeUndefined();
    expect(handleError(poisoned.input)).toBeUndefined();
    browser.emit('error', { error: diagnosticError(), target: null });
    expect(poisoned.reads()).toBe(0);
    expect(browser.requests).toHaveLength(1); expect(browser.events).toHaveLength(1);
    const raw = await browser.events[0].body.text(); assertPrivateAbsent(raw);
    const payload = JSON.parse(raw);
    expect(payload.tags.operation).toBe('browser.render'); expect(payload.tags.category).toBe('render_error');
    expect(payload.message).toBe('Browser render boundary failed');
    expect(payload.exception.values[0].stacktrace.frames).toEqual([]);
    expect(browser.requests[0].options).toMatchObject({ credentials: 'omit', mode: 'no-cors', keepalive: true });
  } finally { browser.close(); }
});

test('SvelteKit pre-mount render error makes one bounded attempt without listeners or retained input', async () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  let resolveConfig!: (response: Response) => void;
  try {
    browser.setFetch((input) => String(input) === '/api/telemetry/config'
      ? new Promise(resolve => { resolveConfig = resolve; }) : Promise.resolve(new Response(null, { status: 202 })));
    for (let i = 0; i < 30; i++) expect(handleError(poisoned.input)).toBeUndefined();
    expect(browser.requests).toHaveLength(1); expect(browser.events).toHaveLength(0);
    expect(browser.requests[0]).toMatchObject({ endpoint: '/api/telemetry/config', options: { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error' } });
    resolveConfig(configResponse());
    await waitFor(() => browser.events.length === 1);
    await settle();
    expect(browser.listenerCount()).toBe(0); expect(poisoned.reads()).toBe(0);
    expect(browser.requests[0].options.signal!.aborted).toBe(true);
    const raw = await browser.events[0].body.text(); assertPrivateAbsent(raw);
    expect(JSON.parse(raw).tags.operation).toBe('browser.render');
    expect(JSON.parse(raw).release).toBe(validConfig.release);
    expect(handleError(poisoned.input)).toBeUndefined(); await settle();
    expect(browser.requests).toHaveLength(2); // one config GET and one event POST, no retries
  } finally { browser.close(); }
});

test('SvelteKit pre-mount attempt joins an installed sender rate limit and cleanup never revives it', async () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  let resolveConfig!: (response: Response) => void;
  try {
    browser.setFetch((input) => String(input) === '/api/telemetry/config'
      ? new Promise(resolve => { resolveConfig = resolve; }) : Promise.resolve(new Response(null, { status: 202 })));
    handleError(poisoned.input);
    const stop = browser.capture({ maxEventsPerMinute: 1 });
    resolveConfig(configResponse()); await waitFor(() => browser.events.length === 1); await settle();
    handleError(poisoned.input);
    browser.emit('error', { error: diagnosticError(), target: null });
    expect(browser.events).toHaveLength(1); expect(browser.listenerCount()).toBe(4);
    stop(); expect(browser.listenerCount()).toBe(0);
    handleError(poisoned.input); await settle();
    expect(browser.events).toHaveLength(1); expect(browser.requests).toHaveLength(2);
    expect(poisoned.reads()).toBe(0);
  } finally { browser.close(); }
});

test('SvelteKit render reporting fails soft for unavailable invalid or disabled runtime config', async () => {
  for (const reply of [
    async () => { throw new Error(privateText); },
    async () => configResponse({ enabled: false }),
    async () => configResponse({ ...validConfig, extra: privateText }),
    async () => configResponse(validConfig, 503),
    async () => new Response('x'.repeat(4097), { headers: { 'Content-Type': 'application/json' } })
  ]) {
    const browser = browserFixture(); const poisoned = privateHookInput();
    try {
      browser.setFetch(reply);
      expect(() => handleError(poisoned.input)).not.toThrow(); await settle(); await settle();
      expect(handleError(poisoned.input)).toBeUndefined();
      expect(poisoned.reads()).toBe(0); expect(browser.events).toHaveLength(0);
      expect(browser.requests).toHaveLength(1); expect(browser.listenerCount()).toBe(0);
      expect(browser.requests[0].options.signal!.aborted).toBe(true);
    } finally { browser.close(); }
  }
});

test('SvelteKit pre-mount pagehide aborts and cancels the actual pending config reader', async () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  let bodyRead = false; let canceled = 0;
  try {
    browser.setFetch(async () => new Response(new ReadableStream<Uint8Array>({
      pull() { bodyRead = true; }, cancel() { canceled++; }
    }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } }));
    expect(handleError(poisoned.input)).toBeUndefined(); await waitFor(() => bodyRead);
    browser.emit('pagehide', {}); await waitFor(() => canceled === 1); await settle();
    expect(browser.requests[0].options.signal!.aborted).toBe(true);
    expect(browser.listenerCount()).toBe(0); expect(browser.events).toHaveLength(0);
    expect(poisoned.reads()).toBe(0);
  } finally { browser.close(); }
});

test('SvelteKit pre-mount config keeps the original five-second deadline without waiting five seconds', async () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  const actualTimer = globalThis.setTimeout;
  let expire: (() => void) | undefined; let bodyRead = false; let canceled = 0;
  try {
    globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
      const [callback, timeout] = args;
      if (timeout === 5000) { expire = () => { if (typeof callback === 'function') callback(...args.slice(2)); }; return 0 as unknown as ReturnType<typeof setTimeout>; }
      return actualTimer(...args);
    }) as typeof setTimeout;
    browser.setFetch(async () => new Response(new ReadableStream<Uint8Array>({
      pull() { bodyRead = true; }, cancel() { canceled++; }
    }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } }));
    handleError(poisoned.input); await waitFor(() => bodyRead);
    expect(typeof expire).toBe('function'); expire!();
    await waitFor(() => canceled === 1); await settle();
    expect(browser.requests[0].options.signal!.aborted).toBe(true);
    expect(browser.listenerCount()).toBe(0); expect(browser.events).toHaveLength(0);
  } finally { globalThis.setTimeout = actualTimer; browser.close(); }
});

test('SvelteKit hook stays nonthrowing with no window or broken reporting setup', () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  const owner = window;
  try {
    Object.defineProperty(globalThis, 'window', { configurable: true, writable: true, value: undefined });
    expect(handleError(poisoned.input)).toBeUndefined(); expect(browser.requests).toHaveLength(0);
    Object.defineProperty(globalThis, 'window', { configurable: true, writable: true, value: owner });
    owner.addEventListener = () => { throw new Error(privateText); };
    expect(() => handleError(poisoned.input)).not.toThrow();
    expect(poisoned.reads()).toBe(0); expect(browser.requests).toHaveLength(0);
  } finally { browser.close(); }
});


test('caught PDF view errors share the installed sender rate budget and serialize only a closed category', async () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  try {
    browser.capture({ maxEventsPerMinute: 2 });
    expect(captureFlarePDFViewError()).toBeUndefined();
    expect(handleError(poisoned.input)).toBeUndefined();
    captureFlarePDFViewError();
    browser.emit('error', { error: diagnosticError(), target: null });
    expect(browser.events).toHaveLength(2); expect(browser.requests).toHaveLength(2);
    const raw = await browser.events[0].body.text(); assertPrivateAbsent(raw);
    const payload = JSON.parse(raw);
    expect(payload.message).toBe('Browser PDF view failed');
    expect(payload.tags.operation).toBe('browser.pdf_view'); expect(payload.tags.category).toBe('pdf_view_error');
    expect(payload.exception.values[0]).toEqual({ type: 'PDFViewError', value: 'Browser PDF view failed', stacktrace: { frames: [] } });
    expect(browser.requests[0].options).toMatchObject({ method: 'POST', credentials: 'omit', mode: 'no-cors', keepalive: true });
    expect(payload.request).toBeUndefined(); expect(poisoned.reads()).toBe(0);
  } finally { browser.close(); }
});

test('pre-mount PDF view failure shares exactly one startup attempt with handled render errors', async () => {
  const browser = browserFixture(); const poisoned = privateHookInput();
  let resolveConfig!: (response: Response) => void;
  try {
    browser.setFetch((input) => String(input) === '/api/telemetry/config'
      ? new Promise(resolve => { resolveConfig = resolve; }) : Promise.resolve(new Response(null, { status: 202 })));
    captureFlarePDFViewError(); handleError(poisoned.input);
    for (let i = 0; i < 30; i++) captureFlarePDFViewError();
    expect(browser.requests).toHaveLength(1); expect(browser.events).toHaveLength(0);
    resolveConfig(configResponse()); await waitFor(() => browser.events.length === 1); await settle();
    const raw = await browser.events[0].body.text(); assertPrivateAbsent(raw);
    expect(JSON.parse(raw).tags.operation).toBe('browser.pdf_view');
    expect(browser.requests[0].options.signal!.aborted).toBe(true); expect(browser.listenerCount()).toBe(0);
    captureFlarePDFViewError(); handleError(poisoned.input); await settle();
    expect(browser.requests).toHaveLength(2); expect(browser.events).toHaveLength(1);
  } finally { browser.close(); }
});

test('pending PDF view report uses a newly installed owner budget and does not retain it after cleanup', async () => {
  const browser = browserFixture(); let resolveConfig!: (response: Response) => void;
  try {
    browser.setFetch((input) => String(input) === '/api/telemetry/config'
      ? new Promise(resolve => { resolveConfig = resolve; }) : Promise.resolve(new Response(null, { status: 202 })));
    captureFlarePDFViewError(); const stop = browser.capture({ maxEventsPerMinute: 1 });
    resolveConfig(configResponse()); await waitFor(() => browser.events.length === 1); await settle();
    handleError(privateHookInput().input); captureFlarePDFViewError();
    expect(browser.events).toHaveLength(1);
    stop(); expect(browser.listenerCount()).toBe(0); captureFlarePDFViewError(); await settle();
    expect(browser.requests).toHaveLength(2); expect(browser.events).toHaveLength(1);
  } finally { browser.close(); }
});

test('caught PDF view report fails soft with disabled config or pagehide during a live config read', async () => {
  const disabled = browserFixture();
  try {
    disabled.setFetch(async () => configResponse({ enabled: false }));
    expect(() => captureFlarePDFViewError()).not.toThrow(); await settle(); await settle();
    captureFlarePDFViewError(); expect(disabled.requests).toHaveLength(1);
    expect(disabled.events).toHaveLength(0); expect(disabled.listenerCount()).toBe(0);
  } finally { disabled.close(); }
  const browser = browserFixture(); let bodyRead = false; let canceled = 0;
  try {
    browser.setFetch(async () => new Response(new ReadableStream<Uint8Array>({
      pull() { bodyRead = true; }, cancel() { canceled++; }
    }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } }));
    captureFlarePDFViewError(); await waitFor(() => bodyRead);
    browser.emit('pagehide', {}); await waitFor(() => canceled === 1); await settle();
    expect(browser.requests[0].options.signal!.aborted).toBe(true);
    expect(browser.events).toHaveLength(0); expect(browser.listenerCount()).toBe(0);
  } finally { browser.close(); }
});
