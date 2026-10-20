import { expect, test } from 'bun:test';
import { PackageSendStatusController } from './packageSendStatus';

function fixture() {
  let id = 0;
  const timers = new Map<number, { ms: number; callback: () => void }>();
  type Request = { documentID: string; signal: AbortSignal; aborted: Promise<void>; resolve(status: string): void };
  const requests: Request[] = [];
  const admissions = new Map<number, ((request: Request) => void)[]>();
  function admitted(index: number): Promise<Request> {
    if (requests[index]) return Promise.resolve(requests[index]);
    return new Promise(resolve => admissions.set(index, [...(admissions.get(index) ?? []), resolve]));
  }
  const statuses: string[] = [], errors: string[] = [];
  const controller = new PackageSendStatusController((target, signal) => new Promise(resolve => {
    const aborted = new Promise<void>(complete => signal.addEventListener('abort', () => complete(), { once: true }));
    const request = { documentID: target.documentID, signal, aborted, resolve }, index = requests.length;
    requests.push(request);
    for (const admission of admissions.get(index) ?? []) admission(request);
    admissions.delete(index);
  }), {
    set: (callback, ms) => { timers.set(++id, { callback, ms }); return id as unknown as ReturnType<typeof setTimeout>; },
    clear: timer => { timers.delete(timer as unknown as number); }
  });
  return { controller, requests, admitted, statuses, errors, timers,
    start: () => controller.start({ documentID: 'saved-document', attemptID: 'persisted-attempt' }, status => { statuses.push(status); }, message => errors.push(message)),
    fire(ms: number) { const entry = [...timers].find(([, timer]) => timer.ms === ms); expect(entry).toBeDefined(); timers.delete(entry![0]); entry![1].callback(); }
  };
}

test('queued202 observes sealing then sent through reads and retires its timers', async () => {
  const f = fixture(); f.start(); await f.admitted(0);
  expect(f.requests).toHaveLength(1); f.requests[0].resolve('sealing'); await f.controller.joined();
  expect(f.statuses).toEqual(['sealing']); f.fire(2000); await f.admitted(1);
  f.requests[1].resolve('sent'); await f.controller.joined();
  expect(f.statuses).toEqual(['sealing', 'sent']); expect(f.errors).toEqual([]); expect(f.timers.size).toBe(0);
  await f.controller.dispose();
});
test('navigation joins an outstanding read and discards even its late successful callback', async () => {
  const f = fixture(); f.start(); await f.admitted(0); let retired = false;
  const joined = f.controller.dispose().then(() => { retired = true; });
  expect(f.requests[0].signal.aborted).toBe(true); await f.requests[0].aborted; expect(retired).toBe(false);
  f.requests[0].resolve('sent'); await joined;
  expect(f.statuses).toEqual([]); expect(f.errors).toEqual([]); expect(f.timers.size).toBe(0);
});
test('a mutated caller target cannot switch the document after observation admission', async () => {
  const f = fixture(), target = { documentID: 'original-document' };
  f.controller.start(target, status => { f.statuses.push(status); }, message => f.errors.push(message));
  target.documentID='another-document'; await f.admitted(0);
  expect(f.requests[0].documentID).toBe('original-document'); f.requests[0].resolve('sent'); await f.controller.joined(); await f.controller.dispose();
});
test('read timeout stops checking without publishing a late status or retrying Send', async () => {
  const f = fixture(); f.start(); await f.admitted(0); f.fire(10000);
  expect(f.requests[0].signal.aborted).toBe(true); f.requests[0].resolve('sent'); await f.controller.joined();
  expect(f.statuses).toEqual([]); expect(f.errors).toHaveLength(1); expect(f.timers.size).toBe(0); await f.controller.dispose();
});
test('an indefinitely sealing package has twelve bounded reads and then needs deliberate inspection', async () => {
  const f = fixture(); f.start(); await f.admitted(0);
  for (let i = 0; i < 12; i++) {
    f.requests[i].resolve('sealing'); await f.controller.joined();
    if (i !== 11) { f.fire(2000); await f.admitted(i + 1); }
  }
  expect(f.requests).toHaveLength(12); expect(f.errors[0]).toContain('paused'); expect(f.timers.size).toBe(0); await f.controller.dispose();
});
