// Optional dependency-free Flare browser capture. Configuration comes from the
// deployed server, not an ingest key or release baked into a previous SPA build.
// Only fixed failure categories and same-origin compiled-code locations leave
// the page. Error text, rejection values, resource URLs and user state do not.
import { isStaffAuthPath } from './staffAuth';

export interface FlareBrowserCaptureOptions {
	dsn?: string;
	environment?: string;
	release?: string;
	maxEventsPerMinute?: number;
	captureResourceErrors?: boolean;
}

interface ParsedDsn { endpoint: string }
interface StackFrame {
	filename: string;
	lineno: number;
	colno?: number;
	in_app: true;
}
type FailureCategory = 'javascript_error' | 'unhandled_rejection' | 'resource_error' | 'render_error' | 'pdf_view_error';
type HandledFailureCategory = 'render_error' | 'pdf_view_error';
type ResourceCategory = 'script' | 'stylesheet' | 'image' | 'other';

const maxFrames = 32;
const maxStackChars = 16 << 10;
const maxFrameURLChars = 512;
const maxConfigBytes = 4096;
const configTimeoutMs = 5000;
const duplicateWindowMs = 10_000;
const defaultMaxEventsPerMinute = 20;
const captureMarker = '__flareBrowserCaptureInstalled';
const renderStartupMarker = '__hashFlareRenderStartupAttempted';
let renderReporter: { owner: Window; send: (category: HandledFailureCategory) => void } | undefined;
const environmentNames = new Set(['development', 'test', 'staging', 'production', 'unknown']);
const failureDetails: Record<FailureCategory, { type: string; message: string; operation: string }> = {
	javascript_error: { type: 'BrowserError', message: 'Browser JavaScript error', operation: 'browser.javascript' },
	unhandled_rejection: { type: 'UnhandledRejection', message: 'Unhandled browser rejection', operation: 'browser.promise' },
	resource_error: { type: 'ResourceError', message: 'Browser resource load failed', operation: 'browser.resource' },
	render_error: { type: 'RenderError', message: 'Browser render boundary failed', operation: 'browser.render' },
	pdf_view_error: { type: 'PDFViewError', message: 'Browser PDF view failed', operation: 'browser.pdf_view' }
};

function validIdentity(value: unknown): value is string {
	return typeof value === 'string' && /^[A-Za-z0-9._@+-]{1,128}$/.test(value);
}

function parseDsn(raw: string, environment: string): ParsedDsn | null {
	if (raw.length > 1024) return null;
	try {
		const url = new URL(raw);
		const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
		if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local && environment === 'development')) return null;
		if (!url.username || url.password || url.search || url.hash) return null;
		const path = url.pathname.replace(/\/+$/, '');
		if (path.length > 256 || !/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(path)) return null;
		const slash = path.lastIndexOf('/');
		const projectID = path.slice(slash + 1);
		if (!/^[A-Za-z0-9_-]{1,64}$/.test(projectID)) return null;
		const key = decodeURIComponent(url.username);
		if (!/^[A-Za-z0-9_-]{1,64}$/.test(key)) return null;
		const basePath = slash > 0 ? path.slice(0, slash) : '';
		return { endpoint: url.origin + basePath + '/api/' + encodeURIComponent(projectID) + '/events?sentry_key=' + encodeURIComponent(key) + '&sentry_version=7' };
	} catch {
		return null;
	}
}

function eventID(): string {
	if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID().replace(/-/g, '');
	if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
		const bytes = new Uint8Array(16);
		crypto.getRandomValues(bytes);
		return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
	}
	return (Date.now().toString(16) + Math.random().toString(16).slice(2)).slice(0, 32).padEnd(32, '0');
}

// Route classes are fixed. Neither raw path segments nor a page URL are sent.
// Capability entry and native account pages never initialize or emit telemetry.
// Check pathname only: never inspect the credential fragment.
function noticeCapabilityPage(): boolean {
	return typeof location !== 'undefined' && (location.pathname.startsWith('/notice/') || isStaffAuthPath(location.pathname));
}

function pageCategory(): string {
	if (typeof location === 'undefined') return 'unknown';
	const path = location.pathname;
	if (path === '/') return 'home';
	for (const [prefix, category] of [
		['/sign', 'signer'], ['/completed', 'completed'], ['/auth', 'auth'],
		['/legal', 'legal'], ['/dashboard', 'dashboard'], ['/documents', 'documents'],
		['/templates', 'templates'], ['/settings', 'settings'], ['/verify', 'verify']
	]) {
		if (path === prefix || path.startsWith(prefix + '/')) return category;
	}
	return 'other';
}

// Reading own data properties avoids invoking getters/toJSON on rejected values.
// In particular no Error.message/name or arbitrary rejected object is read.
function ownString(value: unknown, key: string): string | undefined {
	if (!value || (typeof value !== 'object' && typeof value !== 'function')) return undefined;
	try {
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		return descriptor && typeof descriptor.value === 'string' ? descriptor.value : undefined;
	} catch {
		return undefined;
	}
}

function errorStack(value: unknown): string | undefined {
	try { return value instanceof Error ? ownString(value, 'stack') : undefined; } catch { return undefined; }
}

function codeFilename(raw: string): string | undefined {
	if (typeof location === 'undefined' || raw.length > maxFrameURLChars) return undefined;
	try {
		const url = new URL(raw, location.origin);
		if (url.origin !== location.origin || url.username || url.password) return undefined;
		// SvelteKit's immutable build output only; uploaded files, signer routes,
		// data/blob URLs, arbitrary resources and function names are never frames.
		if (!/^\/_app\/immutable\/[A-Za-z0-9_./-]{1,240}\.(?:js|mjs)$/.test(url.pathname)) return undefined;
		if (url.pathname.split('/').some(segment => segment === '.' || segment === '..')) return undefined;
		return url.origin + url.pathname;
	} catch {
		return undefined;
	}
}

function parseStack(stack: string | undefined): StackFrame[] {
	if (!stack) return [];
	const frames: StackFrame[] = [];
	// Slice before splitting/scanning or retaining a dedup signature. The raw
	// stack is not sent or retained, including its private first message line.
	for (const line of stack.slice(0, maxStackChars).split('\n').slice(0, maxFrames)) {
		if (line.length > 1024) continue;
		let match = line.trim().match(/^at\s+(?:.*?\s+\()?(.+?):(\d+)(?::(\d+))?\)?$/);
		if (!match) match = line.trim().match(/^(?:.*?)@(.+?):(\d+)(?::(\d+))?$/);
		if (!match) continue;
		const filename = codeFilename(match[1]);
		const lineno = Number(match[2]);
		const colno = match[3] === undefined ? undefined : Number(match[3]);
		if (!filename || !Number.isSafeInteger(lineno) || lineno < 1 || lineno > 0x7fffffff) continue;
		if (colno !== undefined && (!Number.isSafeInteger(colno) || colno < 0 || colno > 0x7fffffff)) continue;
		frames.push({ filename, lineno, colno, in_app: true });
	}
	return frames;
}

function installSender(dsn: ParsedDsn, options: FlareBrowserCaptureOptions) {
	const configuredMax = options.maxEventsPerMinute;
	const maxEvents = typeof configuredMax === 'number' && Number.isFinite(configuredMax)
		? Math.max(1, Math.min(Math.floor(configuredMax), 100)) : defaultMaxEventsPerMinute;
	let windowStarted = Date.now();
	let sentInWindow = 0;
	let closed = false;
	const recent = new Map<string, number>();
	return {
		close() { closed = true; recent.clear(); },
		send(category: FailureCategory, stack?: string, resource?: ResourceCategory) {
			if (closed || noticeCapabilityPage()) return;
			try {
				const now = Date.now();
				if (now - windowStarted >= 60_000) { windowStarted = now; sentInWindow = 0; recent.clear(); }
				if (sentInWindow >= maxEvents) return;
				const details = failureDetails[category];
				const frames = parseStack(stack);
				const route = pageCategory();
				const signature = category + ':' + route + ':' + (resource ?? '') + ':' + JSON.stringify(frames);
				const previous = recent.get(signature);
				if (previous !== undefined && now - previous < duplicateWindowMs) return;
				recent.set(signature, now);
				sentInWindow++;
				const payload = JSON.stringify({
					event_id: eventID(), platform: 'javascript', level: 'error',
					environment: options.environment, release: options.release, timestamp: now / 1000,
					message: details.message,
					exception: { values: [{ type: details.type, value: details.message, stacktrace: { frames } }] },
					tags: { source: 'flare-browser-capture', service: 'hash-browser', operation: details.operation, category, route, ...(resource ? { resource_type: resource } : {}) }
				});
				// Beacon always uses credentials: include. Fetch is the sole transport
				// so reports cannot send Flare cookies, even on same-site deployments.
				if (typeof fetch === 'function') {
					void fetch(dsn.endpoint, { method: 'POST', body: payload, headers: { 'Content-Type': 'text/plain' }, mode: 'no-cors', credentials: 'omit', keepalive: true }).catch(() => {});
				}
			} catch { /* Reporting failure must never surface or recursively report. */ }
		}
	};
}

export function installFlareBrowserCapture(options: FlareBrowserCaptureOptions): () => void {
	if (typeof window === 'undefined' || noticeCapabilityPage() || !validIdentity(options.environment) || !environmentNames.has(options.environment) || !validIdentity(options.release) || typeof options.dsn !== 'string') return () => {};
	const dsn = parseDsn(options.dsn, options.environment);
	if (!dsn) return () => {};
	const marked = window as Window & { [captureMarker]?: boolean };
	if (marked[captureMarker]) return () => {};
	marked[captureMarker] = true;
	const sender = installSender(dsn, options);
	const reporter = { owner: window, send: (category: HandledFailureCategory) => sender.send(category) };
	renderReporter = reporter;
	const onError = (event: ErrorEvent) => {
		if (noticeCapabilityPage()) return;
		try {
			if (event.target instanceof Element) return;
			sender.send('javascript_error', errorStack(event.error));
		} catch { sender.send('javascript_error'); }
	};
	const onRejection = (event: PromiseRejectionEvent) => {
		if (noticeCapabilityPage()) return;
		try { sender.send('unhandled_rejection', errorStack(event.reason)); } catch { sender.send('unhandled_rejection'); }
	};
	const onResourceError = (event: Event) => {
		if (noticeCapabilityPage()) return;
		try {
			if (!(event.target instanceof Element)) return;
			const element = event.target.tagName.toLowerCase();
			const resource: ResourceCategory = element === 'script' ? 'script' : element === 'link' ? 'stylesheet' : element === 'img' ? 'image' : 'other';
			sender.send('resource_error', undefined, resource);
		} catch { sender.send('resource_error', undefined, 'other'); }
	};
	const onBoundary = (event: Event) => {
		if (noticeCapabilityPage()) return;
		try {
			const detail = (event as CustomEvent<unknown>).detail;
			sender.send('render_error', ownString(detail, 'componentStack'));
		} catch { sender.send('render_error'); }
	};
	window.addEventListener('error', onError);
	window.addEventListener('unhandledrejection', onRejection);
	if (options.captureResourceErrors !== false) window.addEventListener('error', onResourceError, true);
	window.addEventListener('flare:exception', onBoundary);
	let closed = false;
	return () => {
		if (closed) return;
		closed = true;
		sender.close();
		if (renderReporter === reporter) renderReporter = undefined;
		window.removeEventListener('error', onError);
		window.removeEventListener('unhandledrejection', onRejection);
		if (options.captureResourceErrors !== false) window.removeEventListener('error', onResourceError, true);
		window.removeEventListener('flare:exception', onBoundary);
		delete marked[captureMarker];
	};
}

// Only closed categories cross handled-error boundaries. Neither producer
// accepts an error, response, event, URL, observation or document payload.
export function captureFlareRenderError(): void { captureHandledFlareFailure('render_error'); }
export function captureFlarePDFViewError(): void { captureHandledFlareFailure('pdf_view_error'); }

// Both producers share the installed sender and the same single early attempt.
function captureHandledFlareFailure(category: HandledFailureCategory): void {
	let releaseStartup = () => {};
	try {
		if (typeof window === 'undefined' || noticeCapabilityPage()) return;
		const owner = window;
		if (renderReporter?.owner === owner) { renderReporter.send(category); return; }
		// Before onMount there is no normal sender. At most one bounded attempt
		// per page covers that failure; no raw error or pending-event queue is kept.
		const marked = owner as Window & { [renderStartupMarker]?: boolean };
		if (marked[renderStartupMarker] || typeof fetch !== 'function') return;
		marked[renderStartupMarker] = true;
		const controller = new AbortController();
		const abort = () => { try { controller.abort(); } catch { /* Fail-soft. */ } };
		const timeout = setTimeout(abort, configTimeoutMs);
		releaseStartup = () => {
			abort();
			try { clearTimeout(timeout); } catch { /* Fail-soft. */ }
			try { owner.removeEventListener('pagehide', abort); } catch { /* Fail-soft. */ }
		};
		owner.addEventListener('pagehide', abort, { once: true });
		void (async () => {
			try {
				const response = await fetch('/api/telemetry/config', { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal });
				if (controller.signal.aborted || window !== owner) return;
				const config = await readRuntimeConfig(response, controller.signal);
				if (!config || controller.signal.aborted || window !== owner) return;
				// Mount may have installed capture while the bounded config was read.
				// Use that owner's existing rate/dedup budget whenever it is present.
				if (renderReporter?.owner === owner) { renderReporter.send(category); return; }
				const dsn = parseDsn(config.dsn!, config.environment!);
				if (!dsn) return;
				const sender = installSender(dsn, config);
				try { sender.send(category); } finally { sender.close(); }
			} catch { /* Reporting must never replace SvelteKit's fallback error. */ }
			finally { releaseStartup(); }
		})();
	} catch { releaseStartup(); /* Missing or broken browser APIs remain fail-soft. */ }
}

async function readRuntimeConfig(response: Response, signal: AbortSignal): Promise<FlareBrowserCaptureOptions | undefined> {
	const body = response.body;
	if (!body) return undefined;
	let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
	let accepted = false;
	const cancelBody = () => {
		try {
			// Cancellation closes the readable side immediately. Do not await an
			// arbitrary underlying cancel promise beyond the fetch owner's timer.
			void (reader ? reader.cancel() : body.cancel()).catch(() => {});
		} catch { /* The outer owner also aborts the actual fetch transport. */ }
	};
	signal.addEventListener('abort', cancelBody, { once: true });
	try {
		if (!response.ok || signal.aborted) return undefined;
		const contentType = response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();
		if (contentType !== 'application/json') return undefined;
		const declared = response.headers.get('Content-Length');
		if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxConfigBytes)) return undefined;
		reader = body.getReader();
		const decoder = new TextDecoder('utf-8', { fatal: true });
		let bytes = 0;
		let text = '';
		for (;;) {
			if (signal.aborted) return undefined;
			const chunk = await reader.read();
			if (signal.aborted) return undefined;
			if (chunk.done) break;
			bytes += chunk.value.byteLength;
			if (bytes > maxConfigBytes) return undefined;
			text += decoder.decode(chunk.value, { stream: true });
		}
		text += decoder.decode();
		const config: unknown = JSON.parse(text);
		if (!config || typeof config !== 'object' || Array.isArray(config)) return undefined;
		const row = config as Record<string, unknown>;
		if (row.enabled !== true || Object.keys(row).some(key => !['enabled', 'dsn', 'environment', 'release', 'service'].includes(key))) return undefined;
		if (row.service !== 'hash-browser' || !validIdentity(row.environment) || !environmentNames.has(row.environment) || !validIdentity(row.release) || typeof row.dsn !== 'string') return undefined;
		if (!parseDsn(row.dsn, row.environment)) return undefined;
		accepted = true;
		return { dsn: row.dsn, environment: row.environment, release: row.release };
	} catch {
		return undefined;
	} finally {
		if (!accepted) cancelBody();
		signal.removeEventListener('abort', cancelBody);
		reader?.releaseLock();
	}
}

// Synchronous disposer fits Svelte onMount. A late/failed config response never
// installs listeners after unmount, and pending fetch/body reads are aborted.
export function installRuntimeFlareBrowserCapture(): () => void {
	if (typeof window === 'undefined' || typeof fetch !== 'function' || noticeCapabilityPage()) return () => {};
	const controller = new AbortController();
	let closed = false;
	let stopCapture = () => {};
	const timeout = setTimeout(() => controller.abort(), configTimeoutMs);
	void (async () => {
		try {
			const response = await fetch('/api/telemetry/config', { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal });
			if (closed || controller.signal.aborted) return;
			const config = await readRuntimeConfig(response, controller.signal);
			if (!closed && !controller.signal.aborted && config) stopCapture = installFlareBrowserCapture(config);
		} catch { /* Missing/invalid/unavailable config leaves capture disabled. */ }
		finally { controller.abort(); clearTimeout(timeout); }
	})();
	return () => {
		if (closed) return;
		closed = true;
		clearTimeout(timeout);
		controller.abort();
		stopCapture();
	};
}
