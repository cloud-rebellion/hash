import type { DSRRequest } from './client';

export interface DSRErasurePreview {
  subject_email: string;
  document_status: string;
  pdf_revision_documents: number;
  pdf_revisions: number;
}

export interface DSRErasureConfirmation {
  receipt: string;
  preview: DSRErasurePreview;
  stale: boolean;
}

export type DSRTransitionResult =
  | { state: 'committed'; request: DSRRequest }
  | { state: 'confirmation'; confirmation: DSRErasureConfirmation };

export class DSRTransitionError extends Error {
  constructor(public outcome: 'refused' | 'unknown', message: string, public status = 0) { super(message); }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validReceipt(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[\s\x00-\x1f\x7f]/.test(value);
}

async function readBody(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > 65536) return null;
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { return null; }
  finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

function confirmation(data: Record<string, unknown>, stale: boolean): DSRErasureConfirmation | null {
  const preview = data.will_erase;
  if (!validReceipt(data.confirmation_receipt) || !record(preview)
      || typeof preview.subject_email !== 'string' || !preview.subject_email || preview.subject_email.length > 320 || /[\x00-\x1f\x7f]/.test(preview.subject_email)
      || typeof preview.document_status !== 'string' || !/^[a-z_]{1,32}$/.test(preview.document_status)
      || !Number.isSafeInteger(preview.pdf_revision_documents) || Number(preview.pdf_revision_documents) < 0
      || !Number.isSafeInteger(preview.pdf_revisions) || Number(preview.pdf_revisions) < Number(preview.pdf_revision_documents)) return null;
  return { receipt: data.confirmation_receipt, preview: {
    subject_email: preview.subject_email, document_status: preview.document_status,
    pdf_revision_documents: Number(preview.pdf_revision_documents), pdf_revisions: Number(preview.pdf_revisions),
  }, stale };
}

// Receipts are deliberately returned as a transient action result, never an
// error message, URL, log, localStorage value or reusable auto-retry instruction.
export async function requestDSRTransition(id: string, status: string, resolution_note = '', receipt?: string, signal?: AbortSignal): Promise<DSRTransitionResult> {
  if (receipt !== undefined && (!validReceipt(receipt) || status !== 'fulfilled')) {
    throw new DSRTransitionError('refused', 'Refresh the erasure preview before confirming.');
  }
  let response: Response;
  try {
    response = await fetch(`/api/v1/dsr/${encodeURIComponent(id)}`, {
      method: 'PATCH', credentials: 'include', cache: 'no-store', redirect: 'error', signal,
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, resolution_note, ...(receipt === undefined ? {} : { confirm: true, confirmation_receipt: receipt }) }),
    });
  } catch {
    throw new DSRTransitionError('unknown', 'The result could not be confirmed. Refresh the requests before trying again.');
  }
  const data = await readBody(response);
  if (response.status === 409 && record(data) && data.code === 'confirmation_required') {
    const next = confirmation(data, receipt !== undefined);
    if (status !== 'fulfilled' || !next) throw new DSRTransitionError('refused', 'The erasure preview could not be verified. Refresh the requests before trying again.', 409);
    return { state: 'confirmation', confirmation: next };
  }
  if (!response.ok) {
    if (response.status >= 500 || record(data) && data.code === 'dsr_commit_outcome_unknown') {
      throw new DSRTransitionError('unknown', 'The request may have been applied. Refresh the requests before trying again.', response.status);
    }
    const message = response.status === 401 ? 'Your session has expired. Please sign in again.'
      : record(data) && typeof data.error === 'string' && data.error.length <= 2048 ? data.error
      : 'The request could not be changed. Refresh the requests and review its current state.';
    throw new DSRTransitionError('refused', message, response.status);
  }
  if (!record(data) || data.id !== id || data.status !== status) {
    throw new DSRTransitionError('unknown', 'The result could not be confirmed. Refresh the requests before trying again.', response.status);
  }
  return { state: 'committed', request: data as unknown as DSRRequest };
}
