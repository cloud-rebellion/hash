import { AttachmentPreviewFamily } from './documentAttachmentPreview';
import { MAX_SIGNER_PDF_BYTES, MAX_SIGNER_PDF_PAGES, readBoundedSignerResponse, type SignerPDFObservation } from './signerPDF';

export type SignerPackageMember = Readonly<{ title: string; category: string; pdf_sha256: string; bytes: number; pages: number }>;
export type SignerPackage = Readonly<{
  schema: 'hash-recipient-package-v1'; package_id: string; revision: string;
  manifest_sha256: string; legal_commitment_sha256: string;
  main: SignerPackageMember; annexes: readonly SignerPackageMember[];
  incorporation: Readonly<{ version: 'hash-package-incorporation-v1'; sha256: string; text: string }>;
}>;
export type SignerPackageScope = Readonly<{
  token: string; key: string; documentID: string; recipientID: string; noticeDigest: string;
  observation?: SignerPDFObservation;
}>;
export type SignerPackageResponse = {
  manifest_sha256: string; legal_commitment_sha256: string;
  incorporation_version: string; incorporation_sha256: string; consent: true;
};

const SHA = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();
const unavailable = 'The contract package could not be verified. Reload it before continuing.';
function object(v: unknown): v is Record<string, unknown> { return !!v && typeof v === 'object' && !Array.isArray(v); }
function id(v: unknown): v is string { return typeof v === 'string' && ID.test(v) && v !== '00000000-0000-0000-0000-000000000000'; }
function label(v: unknown, limit: number, empty = false): v is string {
  return typeof v === 'string' && v.trim() === v && (empty || v.length > 0)
    && encoder.encode(v).length <= limit && !/[\u0000-\u001f\u007f-\u009f]/u.test(v);
}
function active(signal: AbortSignal) { if (signal.aborted) throw new DOMException('The package view was closed.', 'AbortError'); }
function member(v: unknown): SignerPackageMember {
  if (!object(v) || !label(v.title, 512) || !label(v.category, 128, true)
    || typeof v.pdf_sha256 !== 'string' || !SHA.test(v.pdf_sha256)
    || !Number.isSafeInteger(v.bytes) || Number(v.bytes) < 1 || Number(v.bytes) > MAX_SIGNER_PDF_BYTES
    || !Number.isInteger(v.pages) || Number(v.pages) < 1 || Number(v.pages) > MAX_SIGNER_PDF_PAGES) throw new Error(unavailable);
  return Object.freeze({ title: v.title, category: v.category, pdf_sha256: v.pdf_sha256, bytes: Number(v.bytes), pages: Number(v.pages) });
}

// Public descriptors are observations. The server still derives every private
// capture, recipient and object pin when bytes or a response are requested.
export function checkedSignerPackageDescriptorsV1(value: unknown): SignerPackage | null {
  if (!object(value) || !Object.hasOwn(value, 'package')) throw new Error(unavailable);
  if (value.package === null) return null;
  const v = value.package;
  if (!object(v) || v.schema !== 'hash-recipient-package-v1' || !id(v.package_id)
    || typeof v.revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(v.revision) || BigInt(v.revision) > 9223372036854775807n
    || typeof v.manifest_sha256 !== 'string' || !SHA.test(v.manifest_sha256)
    || typeof v.legal_commitment_sha256 !== 'string' || !SHA.test(v.legal_commitment_sha256)
    || !Array.isArray(v.annexes) || v.annexes.length > 16 || !object(v.incorporation)
    || v.incorporation.version !== 'hash-package-incorporation-v1'
    || typeof v.incorporation.sha256 !== 'string' || !SHA.test(v.incorporation.sha256)
    || !label(v.incorporation.text, 4096)) throw new Error(unavailable);
  const main = member(v.main), annexes = v.annexes.map(member);
  if ([main, ...annexes].reduce((n, m) => n + m.bytes, 0) > MAX_SIGNER_PDF_BYTES
    || [main, ...annexes].reduce((n, m) => n + m.pages, 0) > MAX_SIGNER_PDF_PAGES) throw new Error(unavailable);
  return Object.freeze({ schema: v.schema, package_id: v.package_id, revision: v.revision,
    manifest_sha256: v.manifest_sha256, legal_commitment_sha256: v.legal_commitment_sha256,
    main, annexes: Object.freeze(annexes), incorporation: Object.freeze({ version: v.incorporation.version, sha256: v.incorporation.sha256, text: v.incorporation.text }) });
}

export function checkedSignerPackage(value: unknown,scope: SignerPackageScope):SignerPackage|null {
 const next=checkedSignerPackageDescriptorsV1(value);if(next===null)return null;
 const main=next.main;
  if (!scope.observation || scope.observation.document_id !== scope.documentID || scope.observation.recipient_id !== scope.recipientID
    || main.pdf_sha256 !== scope.observation.pdf_sha256
    || scope.observation.page_count !== undefined && main.pages !== scope.observation.page_count) throw new Error(unavailable);
 return next;
}

function verifyScope(headers: Headers, scope: SignerPackageScope) {
  if (headers.get('X-Hash-Document-Id') !== scope.documentID || headers.get('X-Hash-Recipient-Id') !== scope.recipientID
    || headers.get('X-Hash-Notice-Digest') !== scope.noticeDigest) throw new Error(unavailable);
}
export function signerPackageKey(scope: SignerPackageScope, value: SignerPackage): string {
  return JSON.stringify([scope.key, value.package_id, value.revision, value.manifest_sha256, value.legal_commitment_sha256,
    value.incorporation.version, value.incorporation.sha256]);
}
export function signerPackageResponse(value: SignerPackage): SignerPackageResponse {
  return { manifest_sha256: value.manifest_sha256, legal_commitment_sha256: value.legal_commitment_sha256,
    incorporation_version: value.incorporation.version, incorporation_sha256: value.incorporation.sha256, consent: true };
}
export async function fetchSignerPackage(scope: SignerPackageScope, signal: AbortSignal, fetcher: typeof fetch = fetch): Promise<SignerPackage | null> {
  active(signal);
  const response = await fetcher(`/sign/${encodeURIComponent(scope.token)}/package`, { signal, cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
  try {
    active(signal);
    if (!response.ok || response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw new Error(unavailable);
    verifyScope(response.headers, scope);
    const bytes = await readBoundedSignerResponse(response, 64 * 1024, signal);
    const value = checkedSignerPackage(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), scope);
    if (value) {
      const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value.incorporation.text));
      const sha = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
      active(signal);
      if (sha !== value.incorporation.sha256) throw new Error(unavailable);
    }
    return value;
  } catch (error) { await response.body?.cancel().catch(() => {}); throw error; }
}

export async function fetchSignerPackagePDF(scope: SignerPackageScope, value: SignerPackage, position: number, signal: AbortSignal, fetcher: typeof fetch = fetch): Promise<Uint8Array> {
  active(signal);
  if (!Number.isInteger(position) || position < 0 || position > value.annexes.length) throw new Error(unavailable);
  const selected = position === 0 ? value.main : value.annexes[position - 1];
  const etag = `"${value.manifest_sha256}.${value.legal_commitment_sha256}"`;
  const response = await fetcher(`/sign/${encodeURIComponent(scope.token)}/package/members/${position}/pdf`, {
    signal, cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/pdf', 'If-Match': etag }
  });
  try {
    active(signal);
    if (!response.ok || response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/pdf') throw new Error(unavailable);
    verifyScope(response.headers, scope);
    const expected = { ETag: etag, 'Content-Length': String(selected.bytes), 'X-Hash-Package-Manifest-SHA256': value.manifest_sha256,
      'X-Hash-Package-Legal-Commitment-SHA256': value.legal_commitment_sha256, 'X-Hash-Package-Member-Position': String(position),
      'X-Hash-PDF-SHA256': selected.pdf_sha256, 'X-Hash-PDF-Bytes': String(selected.bytes), 'X-Hash-PDF-Pages': String(selected.pages) };
    if (Object.entries(expected).some(([key, expected]) => response.headers.get(key) !== expected)) throw new Error(unavailable);
    if (position > 0 && (response.headers.has('X-Hash-HTML-Source-Commitment') || response.headers.has('X-Hash-Materialization-Revision'))) throw new Error(unavailable);
    return await readSignerPackagePDFBodyV1(response,selected,signal);
  } catch (error) { await response.body?.cancel().catch(() => {}); throw error; }
}

export type SignerPackagePreview = {
  selection: { key: string; position: number; title: string; pages: number; bytes: Uint8Array } | null;
  opening: boolean; closing: boolean; blocked: boolean; error: string | null;
};
export const initialSignerPackagePreview = (): SignerPackagePreview => ({ selection: null, opening: false, closing: false, blocked: false, error: null });
const recipientPreviewFamily = new AttachmentPreviewFamily();
function join(a: Promise<void>, b: Promise<void>) {
  const p = Promise.allSettled([a, b]).then(values => { for (const v of values) if (v.status === 'rejected') throw v.reason; });
  void p.catch(() => {}); return p;
}
// One selected annex at a time, including pending fetch/hash and actual PDF.js
// retirement across route changes. The main field viewer has its own owner.
export class SignerPackagePreviewController {
  state = initialSignerPackagePreview(); private revision = 0; private abort: AbortController | null = null;
  private work: Promise<void> = Promise.resolve(); private retirement: Promise<void> = Promise.resolve(); private disposed = false;
  constructor(private fetchPDF: typeof fetchSignerPackagePDF, private retireView: () => Promise<void>, private changed: (state: SignerPackagePreview) => void,
    private family = recipientPreviewFamily) {}
  observeRetirement(retirement: Promise<void>) { this.retirement = join(this.retirement, retirement); this.family.join(retirement); }
  private update(value: Partial<SignerPackagePreview>) { this.state = { ...this.state, ...value }; if (!this.disposed) this.changed(this.state); }
  private queue(scope?: SignerPackageScope, value?: SignerPackage, position?: number) {
    const predecessor = this.family.current(), revision = ++this.revision;
    this.abort?.abort(); this.update({ opening: !!value, closing: !value, error: this.state.blocked ? this.state.error : null });
    const request = this.work.then(async () => {
      if (this.state.blocked) { this.update({ opening: false, closing: false }); return; }
      try { await predecessor; await this.retirement; await this.retireView(); await this.retirement; }
      catch (error) { void this.family.join(Promise.reject(error)); this.update({ blocked: true, opening: false, closing: false, error: 'The attachment view could not be closed. Reload this page before continuing.' }); return; }
      this.state.selection?.bytes.fill(0); this.update({ selection: null });
      if (revision !== this.revision || this.disposed || !scope || !value || position === undefined) { if (revision === this.revision) this.update({ opening: false, closing: false }); return; }
      const abort = new AbortController(); this.abort = abort;
      try {
        const bytes = await this.fetchPDF(scope, value, position, abort.signal);
        if (this.disposed || revision !== this.revision || abort.signal.aborted) { bytes.fill(0); return; }
        const m = position === 0 ? value.main : value.annexes[position - 1];
        this.update({ selection: { key: signerPackageKey(scope, value) + ':' + position, position, title: m.title, pages: m.pages, bytes }, opening: false, closing: false });
      } catch { if (revision === this.revision && !this.disposed) this.update({ opening: false, closing: false, error: unavailable }); }
    });
    this.work = request.catch(() => {}); return request;
  }
  open(scope: SignerPackageScope, value: SignerPackage, position: number) {
    if (!Number.isInteger(position) || position < 0 || position > value.annexes.length) return Promise.reject(new Error(unavailable));
    return this.queue(scope, value, position);
  }
  close() { return this.queue(); }
  dispose() { const p = this.close(); this.disposed = true; return this.family.join(p); }
}

// Pure byte validation. It does not confer route, tenant, credential or storage
// authority. Both callers validate their distinct authenticated header scope.
export async function readSignerPackagePDFBodyV1(response:Response,selected:SignerPackageMember,signal:AbortSignal):Promise<Uint8Array>{
 if(!Number.isSafeInteger(selected.bytes)||selected.bytes<1||selected.bytes>MAX_SIGNER_PDF_BYTES||!SHA.test(selected.pdf_sha256))throw new Error(unavailable);
    const reader = response.body?.getReader(); if (!reader) throw new Error(unavailable);
    const bytes = new Uint8Array(selected.bytes); let length = 0, verified = false;
    const abort = () => { void reader.cancel().catch(() => {}); };
    signal.addEventListener('abort', abort, { once: true });
    try {
      while (true) {
        const chunk = await reader.read(); active(signal);
        if (chunk.done) break;
        if (chunk.value.length > bytes.length - length) throw new Error(unavailable);
        bytes.set(chunk.value, length); length += chunk.value.length;
      }
      if (length !== bytes.length) throw new Error(unavailable);
      const digest = await crypto.subtle.digest('SHA-256', bytes); active(signal);
      const sha = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
      if (sha !== selected.pdf_sha256) throw new Error(unavailable);
      verified = true; return bytes;
    } finally {
      signal.removeEventListener('abort', abort); await reader.cancel().catch(() => {}); reader.releaseLock();
      if (!verified) bytes.fill(0);
    }
}
