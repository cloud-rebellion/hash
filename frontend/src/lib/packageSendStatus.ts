import { getDocument, inspectPackageSendAttempt } from './api/client';

export type PackageSendStatusTarget = Readonly<{ documentID: string; attemptID?: string }>;
type Read = (target: PackageSendStatusTarget, signal: AbortSignal) => Promise<string>;
type Clock = { set(callback: () => void, ms: number): ReturnType<typeof setTimeout>; clear(timer: ReturnType<typeof setTimeout>): void };
const clock: Clock = { set: (callback, ms) => setTimeout(callback, ms), clear: timer => clearTimeout(timer) };
const statuses = new Set(['draft', 'sealing', 'sent', 'in_progress', 'changes_requested', 'finalizing', 'completed', 'declined', 'voided', 'expired']);

// Reads observations only. No caller receives a recipient credential or a Send
// permission, and no retry path performs a mutation.
export async function readPackageSendStatus(target: PackageSendStatusTarget, signal: AbortSignal): Promise<string> {
  const { documentID, attemptID } = target;
  const observed = attemptID ? await inspectPackageSendAttempt(documentID, attemptID, signal) : null;
  const document = await getDocument(documentID, signal);
  if (signal.aborted || document.id !== documentID || !statuses.has(document.status)
    || observed === 'completed' && ['draft', 'sealing'].includes(document.status)) {
    throw new Error('Send state changed during inspection. Refresh the saved document.');
  }
  // An active observation can become sent between the two GETs. The fresh
  // authenticated document observation may show that forward transition.
  return document.status;
}

// One joined read at a time, at most twelve checks, each with a ten-second
// read budget and two seconds between checks.
// Navigation aborts admission immediately and waits for the actual pending
// callback to settle. Epoch checks discard even a transport ignoring abort.
export class PackageSendStatusController {
  private epoch = 0;
  private closed = false;
  private key = '';
  private timer: ReturnType<typeof setTimeout> | null = null;
  private deadline: ReturnType<typeof setTimeout> | null = null;
  private abort: AbortController | null = null;
  private pending: Promise<void> = Promise.resolve();
  constructor(private read: Read = readPackageSendStatus, private time: Clock = clock) {}
  start(target: PackageSendStatusTarget, observed: (status: string) => Promise<void> | void, failed: (message: string) => void) {
    const owned = Object.freeze({ documentID: target.documentID, ...(target.attemptID ? { attemptID: target.attemptID } : {}) });
    const key = JSON.stringify([owned.documentID, owned.attemptID ?? '']);
    if (this.closed || key === this.key) return;
    const predecessor = this.stop();
    const epoch = this.epoch;
    this.key = key;
    const current = () => !this.closed && epoch === this.epoch;
    const run = async (count: number): Promise<void> => {
      if (!current()) return;
      const request = new AbortController(); this.abort = request;
      this.deadline = this.time.set(() => request.abort(), 10000);
      try {
        const status = await this.read(owned, request.signal);
        if (!current()) return;
        if (request.signal.aborted || !statuses.has(status)) throw new Error('Unverified Send status');
        await observed(status);
        if (!current() || status !== 'sealing') return;
        if (count === 12) {
          failed('Hash is still securing the package. Automatic checking has paused; use Check Send status to inspect it again.');
          return;
        }
        this.timer = this.time.set(() => {
          this.timer = null;
          if (current()) this.pending = this.pending.then(() => run(count + 1));
        }, 2000);
      } catch {
        if (current()) failed('Automatic Send status checking stopped. Use Check Send status to inspect the saved document.');
      } finally {
        if (this.deadline !== null) this.time.clear(this.deadline);
        this.deadline = null;
        if (this.abort === request) this.abort = null;
      }
    };
    this.pending = predecessor.then(() => run(1));
  }
  stop(): Promise<void> {
    this.epoch++; this.key = '';
    if (this.timer !== null) this.time.clear(this.timer);
    if (this.deadline !== null) this.time.clear(this.deadline);
    this.timer = this.deadline = null;
    this.abort?.abort(); this.abort = null;
    return this.pending.catch(() => {});
  }
  joined(): Promise<void> { return this.pending; }
  dispose(): Promise<void> { this.closed = true; return this.stop(); }
}
