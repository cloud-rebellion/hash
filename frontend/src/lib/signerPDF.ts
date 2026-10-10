// Public observations bind a recipient's PDF and fields to the context read.
// They contain no storage credentials or source content.
export type SignerPDFObservation = {
  document_id: string;
  recipient_id: string;
  pdf_sha256: string;
  page_count?: number;
  html_source_commitment?: string;
  materialization_revision?: number;
};

export type SignerPDFScope = {
  token: string;
  noticeDigest: string;
  observation: SignerPDFObservation;
};

export type SignerPDFField = {
  id: string;
  document_id: string;
  recipient_id?: string;
  type: string;
  page: number;
  x_pct: number;
  y_pct: number;
  w_pct: number;
  h_pct: number;
  required: boolean;
  label?: string;
  value?: string;
  options?: { choices?: string[] };
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const ZERO_UUID = '00000000-0000-0000-0000-000000000000';
export const MAX_SIGNER_PDF_BYTES = 50 * 1024 * 1024;
export const MAX_SIGNER_PDF_PAGES = 500;
const MAX_FIELDS_JSON_BYTES = 24 * 1024 * 1024;
const encoder = new TextEncoder();

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function validID(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value) && value !== ZERO_UUID;
}

export function validateSignerPDFObservation(value: unknown, documentID: string, recipientID: string): SignerPDFObservation {
  if (!object(value) || !validID(value.document_id) || !validID(value.recipient_id)
    || value.document_id !== documentID || value.recipient_id !== recipientID
    || typeof value.pdf_sha256 !== 'string' || !SHA.test(value.pdf_sha256)) {
    throw new Error('The current document could not be verified. Please reopen your signing link.');
  }
  const hasSource = value.html_source_commitment !== undefined;
  if (hasSource && (typeof value.html_source_commitment !== 'string' || !SHA.test(value.html_source_commitment))) {
    throw new Error('The current document source could not be verified.');
  }
  if (value.page_count !== undefined && (!Number.isInteger(value.page_count) || Number(value.page_count) < 1 || Number(value.page_count) > MAX_SIGNER_PDF_PAGES)) {
    throw new Error('The document page count is unavailable or exceeds the viewing limit.');
  }
  if (value.materialization_revision !== undefined && (!Number.isSafeInteger(value.materialization_revision) || Number(value.materialization_revision) < 1)) {
    throw new Error('The current document version could not be verified.');
  }
  const registered = value.page_count !== undefined || value.materialization_revision !== undefined;
  if (registered && (!hasSource || value.page_count === undefined || value.materialization_revision === undefined)) {
    throw new Error('The current document version is incomplete.');
  }
  return {
    document_id: value.document_id, recipient_id: value.recipient_id, pdf_sha256: value.pdf_sha256,
    ...(value.page_count !== undefined ? { page_count: Number(value.page_count) } : {}),
    ...(hasSource ? { html_source_commitment: value.html_source_commitment as string } : {}),
    ...(value.materialization_revision !== undefined ? { materialization_revision: Number(value.materialization_revision) } : {})
  };
}

export function signerPDFScopeKey(token: string, noticeDigest: string, observation: SignerPDFObservation | undefined): string {
  return signerCeremonyKey(token, noticeDigest, observation?.document_id ?? '', observation?.recipient_id ?? '', observation);
}

export function signerCeremonyKey(token: string, noticeDigest: string, documentID: string, recipientID: string, observation?: SignerPDFObservation): string {
  return JSON.stringify([token, noticeDigest, documentID, recipientID,
    observation?.document_id, observation?.recipient_id,
    observation?.pdf_sha256, observation?.page_count, observation?.html_source_commitment, observation?.materialization_revision]);
}

export function verifySignerPDFHeaders(headers: Headers, observation: SignerPDFObservation): void {
  const expected: [string, string | undefined][] = [
    ['X-Hash-Document-Id', observation.document_id], ['X-Hash-Recipient-Id', observation.recipient_id],
    ['X-Hash-PDF-SHA256', observation.pdf_sha256], ['X-Hash-PDF-Pages', observation.page_count?.toString()],
    ['X-Hash-HTML-Source-Commitment', observation.html_source_commitment],
    ['X-Hash-Materialization-Revision', observation.materialization_revision?.toString()]
  ];
  if (expected.some(([name, value]) => headers.get(name) !== (value ?? null))) {
    throw new Error('The document changed while it was loading. Please reopen your signing link.');
  }
}

function assertActive(signal: AbortSignal): void {
  if (signal.aborted) throw new DOMException('The document view was closed.', 'AbortError');
}

export async function readBoundedSignerResponse(response: Response, maxBytes: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  assertActive(signal);
  const advertised = response.headers.get('Content-Length');
  if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > maxBytes)) {
    await response.body?.cancel();
    throw new Error('The document response exceeds the viewing limit.');
  }
  if (!response.body) throw new Error('The document response is empty.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      const result = await reader.read();
      assertActive(signal);
      if (result.done) break;
      size += result.value.byteLength;
      if (size > maxBytes) throw new Error('The document response exceeds the viewing limit.');
      chunks.push(result.value);
    }
    if (size === 0) throw new Error('The document response is empty.');
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

export async function signerResponseError(response: Response, signal: AbortSignal): Promise<string> {
  const fallback = `The request failed (${response.status}).`;
  try {
    const body = new TextDecoder().decode(await readBoundedSignerResponse(response, 64 * 1024, signal)).trim();
    try {
      const parsed: unknown = JSON.parse(body);
      if (object(parsed) && typeof parsed.error === 'string' && parsed.error.trim()) return parsed.error.trim();
    } catch { /* Plain text errors remain visible. */ }
    return body || fallback;
  } catch (error) {
    assertActive(signal);
    return fallback;
  }
}

export async function fetchSignerPDF(scope: SignerPDFScope, signal: AbortSignal, fetcher: typeof fetch = fetch): Promise<Uint8Array<ArrayBuffer>> {
  const response = await fetcher(`/sign/${scope.token}/pdf`, { signal, cache: 'no-store', credentials: 'same-origin' });
  assertActive(signal);
  if (!response.ok) throw new Error(await signerResponseError(response, signal));
  try { verifySignerPDFHeaders(response.headers, scope.observation); }
  catch (error) { await response.body?.cancel(); throw error; }
  if (response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/pdf') {
    await response.body?.cancel();
    throw new Error('The document response is not a PDF.');
  }
  const bytes = await readBoundedSignerResponse(response, MAX_SIGNER_PDF_BYTES, signal);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  assertActive(signal);
  const sha = Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, '0')).join('');
  if (sha !== scope.observation.pdf_sha256) throw new Error('The loaded PDF does not match the current document. Please reopen your signing link.');
  return bytes;
}

export async function readSignerFieldResponse(response: Response, observation: SignerPDFObservation, signal: AbortSignal): Promise<Record<string, unknown>> {
  assertActive(signal);
  if (!response.ok) throw new Error(await signerResponseError(response, signal));
  try { verifySignerPDFHeaders(response.headers, observation); }
  catch (error) { await response.body?.cancel(); throw error; }
  if (response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
    await response.body?.cancel();
    throw new Error('The document fields could not be verified.');
  }
  const data: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readBoundedSignerResponse(response, MAX_FIELDS_JSON_BYTES, signal)));
  assertActive(signal);
  if (!object(data)) throw new Error('The document fields could not be verified.');
  return data;
}

export function validateSignerPDFFields(value: unknown, observation: SignerPDFObservation, pageCount: number): SignerPDFField[] {
  if (!Array.isArray(value) || value.length > 1000 || !Number.isInteger(pageCount) || pageCount < 1 || pageCount > MAX_SIGNER_PDF_PAGES) {
    throw new Error('The document fields exceed the viewing limit.');
  }
  const seen = new Set<string>();
  return value.map((field: unknown) => {
    if (!object(field) || !validID(field.id) || seen.has(field.id) || field.document_id !== observation.document_id
      || field.recipient_id !== undefined && field.recipient_id !== observation.recipient_id
      || !['signature', 'text', 'date', 'checkbox', 'dropdown', 'initial'].includes(String(field.type))
      || typeof field.required !== 'boolean' || !Number.isInteger(field.page) || Number(field.page) < 1 || Number(field.page) > pageCount
      || !['x_pct', 'y_pct', 'w_pct', 'h_pct'].every(name => typeof field[name] === 'number' && Number.isFinite(field[name]))
      || Number(field.x_pct) < 0 || Number(field.y_pct) < 0 || Number(field.w_pct) <= 0 || Number(field.h_pct) <= 0
      || Number(field.x_pct) + Number(field.w_pct) > 100 || Number(field.y_pct) + Number(field.h_pct) > 100
      || field.label !== undefined && typeof field.label !== 'string'
      || field.value !== undefined && (typeof field.value !== 'string' || encoder.encode(field.value).byteLength > 4096)
      || field.options !== undefined && (!object(field.options) || encoder.encode(JSON.stringify(field.options)).byteLength > 16 * 1024)) {
      throw new Error('A document field does not match this recipient or PDF. Please reopen your signing link.');
    }
    const options = field.options as Record<string, unknown> | undefined;
    if (field.type === 'dropdown' && (!Array.isArray(options?.choices) || options.choices.length < 1 || options.choices.length > 100
      || !options.choices.every(choice => typeof choice === 'string' && !!choice.trim() && encoder.encode(choice).byteLength <= 512)
      || new Set(options.choices).size !== options.choices.length)) throw new Error('A document field has invalid choices.');
    seen.add(field.id);
    return { ...field } as SignerPDFField;
  });
}

export function confirmSignerPDFField(previous: SignerPDFField, updated: SignerPDFField): void {
  const immutable = ['id', 'document_id', 'recipient_id', 'type', 'page', 'x_pct', 'y_pct', 'w_pct', 'h_pct', 'required', 'label', 'options'] as const;
  if (immutable.some(name => JSON.stringify(previous[name]) !== JSON.stringify(updated[name]))) {
    throw new Error('The document field changed while saving. Please reopen your signing link.');
  }
}

type DestroyablePDF = { loadingTask: { destroy(): Promise<void> } };

// The live key is read again after every await, including callbacks that arrive
// before Svelte has had a chance to run the previous effect's cleanup.
export class SignerPDFSession {
  readonly controller = new AbortController();
  readonly key: string;
  private document?: DestroyablePDF;
  constructor(readonly scope: SignerPDFScope, private liveKey: () => string) {
    this.key = signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation);
  }
  current(): boolean { return !this.controller.signal.aborted && this.key === this.liveKey(); }
  assertCurrent(): void { if (!this.current()) throw new DOMException('The document view was closed.', 'AbortError'); }
  attach(document: DestroyablePDF): void {
    if (!this.current()) { void document.loadingTask.destroy().catch(() => {}); this.assertCurrent(); }
    this.document = document;
  }
  destroy(): void {
    this.controller.abort();
    void this.document?.loadingTask.destroy().catch(() => {});
    this.document = undefined;
  }
}

export async function renderSignerPDFPages<D extends { numPages: number }>(document: D, observation: SignerPDFObservation, renderer: {
  current(): void;
  width(document: D, page: number): Promise<number>;
  mount(pages: { num: number; w: number; h: number }[]): Promise<void>;
  canvas(page: number): HTMLCanvasElement | undefined;
  render(document: D, page: number, canvas: HTMLCanvasElement, scale: number): Promise<{ width: number; height: number }>;
}): Promise<{ num: number; w: number; h: number }[]> {
  renderer.current();
  if (!Number.isInteger(document.numPages) || document.numPages < 1 || document.numPages > MAX_SIGNER_PDF_PAGES
    || observation.page_count !== undefined && document.numPages !== observation.page_count) throw new Error('The loaded PDF has an unexpected page count.');
  const pages: { num: number; w: number; h: number }[] = [];
  const scales: number[] = [];
  for (let num = 1; num <= document.numPages; num++) {
    const width = await renderer.width(document, num);
    renderer.current();
    if (!Number.isFinite(width) || width <= 0) throw new Error('A document page could not be rendered.');
    const scale = Math.min(760 / width, 2);
    scales[num] = scale;
    pages.push({ num, w: width * scale, h: 0 });
  }
  await renderer.mount(pages);
  renderer.current();
  for (const page of pages) {
    const canvas = renderer.canvas(page.num);
    if (!canvas) throw new Error('A document page could not be displayed.');
    const size = await renderer.render(document, page.num, canvas, scales[page.num]);
    renderer.current();
    if (!Number.isFinite(size.width) || !Number.isFinite(size.height) || size.width <= 0 || size.height <= 0) throw new Error('A document page could not be rendered.');
    page.w = size.width; page.h = size.height;
  }
  return pages;
}
