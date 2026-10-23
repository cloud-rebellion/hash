import { expect, test } from 'bun:test';
import { takeNoticeFragment } from '../noticeAccess';
import { deferred } from '../amendmentFixtures';
const source = await Bun.file(new URL('./NoticeReader.svelte', import.meta.url)).text();
const start = source.indexOf(' function consumeEntry()'), close = source.indexOf(' async function closePDF()', start), end = source.indexOf(' async function load(', close);
if (start < 0 || close < start || end < close) throw Error('Actual notice lifecycle callbacks missing');
const transpiler = new Bun.Transpiler({ loader: 'ts' });
const entryCode = transpiler.transformSync(source.slice(start, close)) + '\n return { capability: entryCapability, invalid: entryInvalid };';
const closeCode = transpiler.transformSync(source.slice(close, end));
test('actual notice entry removes the full fragment synchronously before parsing or any async work', () => {
 for (const malformed of [false, true]) { const token = 'hn1.' + 'A'.repeat(43), steps: string[] = []; const location = { hash: '#access=' + token + (malformed ? '&extra=refuse' : ''), pathname: '/notice/id', search: '' }; const window = { location, history: { state: { existing: true }, replaceState(_state: unknown, _title: string, url: string) { steps.push('removed'); expect(url).toBe('/notice/id'); location.hash = ''; } } }; const result = new Function('window', 'takeNoticeFragment', entryCode)(window, (fragment: string) => { steps.push('parsed'); expect(location.hash).toBe(''); return takeNoticeFragment(fragment); }); expect(steps).toEqual(['removed', 'parsed']); expect(result).toEqual({ capability: malformed ? null : token, invalid: malformed }); }
});
test('actual notice viewer closes transport, then original PDF owner, before clearing sensitive bytes', async () => {
 const reading = deferred<void>(), retiring = deferred<void>(), ownerEntered = deferred<void>(); const bytes = new Uint8Array([1, 2, 3]); let aborted = false;
 const env: any = { retirement: null, readGeneration: 0, pdfAbort: { abort() { aborted = true; } }, closing: false, pdfRead: reading.promise, tick: async () => {}, previewOwner: { retire() { ownerEntered.resolve(); return retiring.promise; } }, bytes, selected: { position: 0 }, opening: true, disposed: false, blocked: false, error: null };
 new Function('env', 'with(env){' + closeCode + ';env.closePDF=closePDF;}')(env); const closing = env.closePDF(); expect(aborted).toBe(true); expect(env.bytes).toBe(bytes); reading.resolve(); await ownerEntered.promise; expect(env.bytes).toBe(bytes); expect([...bytes]).toEqual([1, 2, 3]); retiring.resolve(); await closing; expect(env.bytes).toBeNull(); expect([...bytes]).toEqual([0, 0, 0]); expect(env.previewOwner).toBeNull();
});
test('actual notice viewer refuses further work if its PDF owner cannot retire', async () => {
 const bytes = new Uint8Array([1, 2, 3]); const env: any = { retirement: null, readGeneration: 0, pdfAbort: null, closing: false, pdfRead: null, tick: async () => {}, previewOwner: { retire: async () => { throw Error('private native failure'); } }, bytes, selected: { position: 0 }, opening: false, disposed: false, blocked: false, error: null };
 new Function('env', 'with(env){' + closeCode + ';env.closePDF=closePDF;}')(env); await env.closePDF(); expect(env.blocked).toBe(true); expect(env.bytes).toBe(bytes); expect([...bytes]).toEqual([1, 2, 3]); expect(env.error).not.toContain('private');
});
