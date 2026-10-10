// Hash frontend API client.
import type { HTMLContractProfile, HTMLMaster, HTMLPartySlot } from '../htmlTemplate';

export interface TemplateResponse {
  id: string;
  org_id: string;
  name: string;
  source_kind: 'blocks' | 'pdf' | 'html';
  blocks_json?: unknown;
  variables_json: unknown;
  pdf_storage_key?: string;
  pdf_sha256?: string;
  page_count?: number;
  fields_json: unknown;
  version: number;
  content_sha256?: string;
  html_master_json?: HTMLMaster;
  html_approval?: { version: number; content_sha256: string; approved_by?: string; approved_at?: string };
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DocumentResponse {
  id: string;
  org_id: string;
  template_id?: string;
  name: string;
  status: string;
  routing_mode: string;
  source_kind: 'blocks' | 'pdf';
  pdf_sha256?: string;
  has_html_source?: boolean;
  html_review_required?: boolean;
  html_source_commitment?: string;
  html_materialization_revision?: number;
  requires_signature?: boolean;
  blocks_json?: BlockTree;
  variables_json: Record<string, string>;
  expires_at?: string;
  sent_at?: string;
  completed_at?: string;
  sender_id: string;
  metadata: Record<string, unknown>;
  default_locale: string;
  created_at: string;
  updated_at: string;
  is_envelope?: boolean;
  parent_envelope_id?: string | null;
  routing_tier?: string;
}

export interface BlockTree {
  version: number;
  blocks: Block[];
}

export interface Block {
  id: string;
  type: string;
  attrs?: Record<string, unknown>;
  text?: string;
  content?: Block[];
  rows?: string[][];
}

// friendlyError turns a failed response into an operator-safe message. It surfaces
// the backend's clean { "error": ... } field for actionable 4xx (permission, plan,
// conflict) but never leaks a raw 500 body (which can contain internal/DB strings).
async function friendlyError(res: Response): Promise<string> {
  let serverMsg = '';
  try {
    const data = await res.clone().json();
    if (data && typeof data.error === 'string') serverMsg = data.error;
  } catch {
    // non-JSON body; ignore so we never surface a raw HTML/DB string.
  }
  switch (res.status) {
    case 401:
      return 'Your session has expired. Please sign in again.';
    case 403:
      return serverMsg || 'You do not have permission to do that.';
    case 402:
      return serverMsg || 'Your plan does not include this feature.';
    case 404:
      return serverMsg || 'Not found.';
    case 409:
      return serverMsg || 'That action conflicts with the current state of the document.';
    case 500:
    case 502:
    case 503:
      return 'Something went wrong on our side. Please try again in a moment.';
    default:
      return serverMsg || `Request failed (${res.status}).`;
  }
}

export class APIError extends Error {
 constructor(public status: number, message: string) { super(message); }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const opts: RequestInit = {
    method,
    credentials: 'include',
    headers: { Accept: 'application/json' }
  };
  if (body !== undefined) {
    (opts.headers as Record<string, string>)['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    throw new APIError(res.status, await friendlyError(res));
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export async function listTemplates(): Promise<{ templates: TemplateResponse[]; total: number }> {
  return request('GET', '/api/v1/templates');
}

export async function getTemplate(id: string): Promise<TemplateResponse> {
  return request('GET', `/api/v1/templates/${encodeURIComponent(id)}`);
}

export interface HTMLTemplateInput {
  name: string;
  html_master_json: HTMLMaster;
  variables_json: Record<string, string>;
}
export async function createHTMLTemplate(input: HTMLTemplateInput): Promise<TemplateResponse> {
  return request('POST', '/api/v1/templates/html', input);
}
export async function updateHTMLTemplate(id: string, expectedVersion: number, input: HTMLTemplateInput): Promise<TemplateResponse> {
  return request('PATCH', `/api/v1/templates/${encodeURIComponent(id)}/html`, { ...input, expected_version: expectedVersion });
}
export interface HTMLTemplatePreview {
  bytes: Uint8Array;
  templateID: string;
  version: number;
  contentSHA256: string;
  materializationSHA256: string;
  pdfSHA256: string;
  pages: number;
  receipt: string;
  expiresAt: string;
}
export async function previewHTMLTemplate(id: string, version: number, contentSHA256: string, values: Record<string, string>, signal: AbortSignal): Promise<HTMLTemplatePreview> {
  const res = await fetch(`/api/v1/templates/${encodeURIComponent(id)}/html/preview`, {
    method: 'POST', credentials: 'include', cache: 'no-store', signal,
    headers: { Accept: 'application/pdf', 'Content-Type': 'application/json' },
    body: JSON.stringify({ expected_version: version, expected_content_sha256: contentSHA256, values }),
  });
  if (!res.ok) throw new APIError(res.status, await friendlyError(res));
  const returnedVersion = res.headers.get('X-Hash-Template-Version');
  const materializationSHA256 = res.headers.get('X-Hash-Materialization-SHA256') ?? '';
  const pdfSHA256 = res.headers.get('X-Hash-PDF-SHA256') ?? '';
  const pageHeader = res.headers.get('X-Hash-PDF-Pages') ?? '';
  const pages = Number(pageHeader);
  const receipt = res.headers.get('X-Hash-Preview-Receipt') ?? '';
  const expiresAt = res.headers.get('X-Hash-Preview-Expires-At') ?? '';
  if (res.headers.get('X-Hash-Template-Id') !== id || returnedVersion !== String(version)
      || res.headers.get('X-Hash-Template-Content-SHA256') !== contentSHA256 || !/^[a-f0-9]{64}$/.test(contentSHA256)
      || !/^[a-f0-9]{64}$/.test(materializationSHA256) || !/^[a-f0-9]{64}$/.test(pdfSHA256)
      || !/^[1-9][0-9]{0,2}$/.test(pageHeader) || pages > 500 || !receipt || receipt.length > 8192
      || /[\s\x00-\x1f\x7f]/.test(receipt) || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now()) {
    await res.body?.cancel().catch(() => {});
    throw new Error('The preview does not match this saved revision or has expired. Refresh the design before reviewing it.');
  }
  const bytes = await readVerifiedPDF(res, pdfSHA256);
  if (Date.parse(expiresAt) <= Date.now()) throw new Error('The preview expired while loading. Generate a new preview.');
  return { bytes, templateID: id, version, contentSHA256, materializationSHA256, pdfSHA256, pages, receipt, expiresAt };
}
export async function approveHTMLTemplate(id: string, version: number, contentSHA256: string, preview: HTMLTemplatePreview): Promise<{ template_id: string; version: number; content_sha256: string; approved_by: string; approved_at: string }> {
  return request('POST', `/api/v1/templates/${encodeURIComponent(id)}/html/approve`, {
    expected_version: version, expected_content_sha256: contentSHA256,
    preview_receipt: preview.receipt, expected_preview_pdf_sha256: preview.pdfSHA256,
  });
}

export interface HTMLDocumentInput {
  name: string;
  expected_template_version: number;
  expected_template_content_sha256: string;
  values: Record<string, string>;
  sections?: Record<string, string>;
}

export async function createHTMLTemplateDocument(templateID: string, input: HTMLDocumentInput): Promise<ImportResult & { review_required: boolean }> {
  return request('POST', `/api/v1/templates/${encodeURIComponent(templateID)}/html/documents`, {
    name: input.name,
    expected_template_version: input.expected_template_version,
    expected_template_content_sha256: input.expected_template_content_sha256,
    values: input.values,
    ...(input.sections === undefined ? {} : { sections: input.sections }),
  });
}

export async function reviewHTMLDocument(documentID: string, expectedUpdatedAt: string, expectedPDFSHA256: string, expectedHTMLSourceCommitment?: string): Promise<DocumentResponse> {
  return request('POST', `/api/v1/documents/${encodeURIComponent(documentID)}/html/review`, {
    expected_updated_at: expectedUpdatedAt,
    expected_pdf_sha256: expectedPDFSHA256,
    ...(expectedHTMLSourceCommitment ? { expected_html_source_commitment: expectedHTMLSourceCommitment } : {}),
  });
}

export interface HTMLDocumentSource {
  document_id: string; org_id: string; updated_at: string;
  html_source_commitment: string; materialization_revision: number;
  pdf_sha256: string; page_count: number;
  template_id: string; template_version: number; template_content_sha256: string;
  values: { name: string; required: boolean; max_chars: number; text: string }[];
  sections: { name: string; max_chars: number; text: string; default_text: string }[];
  changed_sections: string[]; can_edit: boolean;
  contract_profile?: HTMLContractProfile;
  contract_profile_digest?: string;
  contract_parties?: HTMLDocumentParty[];
}
export interface HTMLDocumentParty {
  slot: HTMLPartySlot; role: HTMLPartySlot; recipient_id: string;
  name: string; email: string; company_name: string; company_id: string; representative_authority: string;
}
export interface HTMLDocumentRevisionInput {
  expected_updated_at: string; expected_html_source_commitment: string;
  values: Record<string, string>; sections: Record<string, string>; summary: string;
}
export interface HTMLDocumentRevisionResult {
  document: DocumentResponse; materialization_revision: number; page_count: number;
  review_required: true; placement_reset: true;
}
export interface HTMLHistoryEntry {
  sequence: number; id: string; source_commitment: string; pdf_sha256: string; page_count: number;
  created_by: string; created_at: string; summary: string; current: boolean;
}
export async function getHTMLDocumentSource(documentID: string): Promise<HTMLDocumentSource> {
  return request('GET', `/api/v1/documents/${encodeURIComponent(documentID)}/html/source`);
}
export async function reviseHTMLDocument(documentID: string, input: HTMLDocumentRevisionInput): Promise<HTMLDocumentRevisionResult> {
  return request('POST', `/api/v1/documents/${encodeURIComponent(documentID)}/html/revisions`, input);
}
export async function getHTMLDocumentHistory(documentID: string): Promise<{ revisions: HTMLHistoryEntry[] }> {
  return request('GET', `/api/v1/documents/${encodeURIComponent(documentID)}/html/history`);
}
export async function getHTMLRevisionSource(documentID: string, sequence: number): Promise<HTMLDocumentSource> {
  if (!Number.isInteger(sequence) || sequence < 1) throw new Error('Select a valid immutable revision.');
  return request('GET', `/api/v1/documents/${encodeURIComponent(documentID)}/html/revisions/${sequence}/source`);
}
export async function fetchVerifiedHTMLRevisionPDF(documentID: string, revision: HTMLDocumentSource, signal: AbortSignal): Promise<Uint8Array> {
  if (!revision || revision.document_id !== documentID || !Number.isInteger(revision.materialization_revision) || revision.materialization_revision < 1) {
    throw new Error('Select a valid immutable revision for this document.');
  }
  const res = await fetch(`/api/v1/documents/${encodeURIComponent(documentID)}/html/revisions/${revision.materialization_revision}/pdf`, {
    credentials: 'include', cache: 'no-store', headers: { Accept: 'application/pdf' }, signal,
  });
  if (!res.ok) throw new APIError(res.status, await friendlyError(res));
  if (res.headers.get('X-Hash-Document-Id') !== documentID || res.headers.get('X-Hash-Materialization-Revision') !== String(revision.materialization_revision)
      || res.headers.get('X-Hash-HTML-Source-Commitment') !== revision.html_source_commitment || !/^[a-f0-9]{64}$/.test(revision.html_source_commitment)
      || res.headers.get('X-Hash-PDF-SHA256') !== revision.pdf_sha256 || !/^[a-f0-9]{64}$/.test(revision.pdf_sha256)
      || res.headers.get('X-Hash-PDF-Pages') !== String(revision.page_count) || !Number.isInteger(revision.page_count) || revision.page_count < 1 || revision.page_count > 500) {
    await res.body?.cancel().catch(() => {});
    throw new Error('The historical PDF does not match this immutable revision. Refresh history before opening it.');
  }
  return readVerifiedPDF(res, revision.pdf_sha256);
}

// Preview only bytes matching the observed artifact, before PDF parsing or a
// manual review action. Error HTML and an iframe load event are not PDF proof.
export async function fetchVerifiedDocumentPDF(documentID: string, expectedSHA256: string, signal: AbortSignal): Promise<Uint8Array> {
  if (!/^[a-f0-9]{64}$/.test(expectedSHA256)) throw new Error('The current PDF commitment is unavailable. Refresh this document.');
  const res = await fetch(`/api/v1/documents/${encodeURIComponent(documentID)}/pdf`, {
    credentials: 'include', cache: 'no-store', headers: { Accept: 'application/pdf' }, signal,
  });
  if (!res.ok) throw new APIError(res.status, await friendlyError(res));
  return readVerifiedPDF(res, expectedSHA256);
}

// Shared bounded byte/digest policy for document and saved-design previews.
async function readVerifiedPDF(res: Response, expectedSHA256: string): Promise<Uint8Array> {
  if (res.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/pdf' || !res.body) {
    throw new Error('The server did not return a PDF. Refresh this document before reviewing it.');
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.length;
      if (length > 50 * 1024 * 1024) throw new Error('This PDF exceeds the preview limit. Ask its owner to review it.');
      chunks.push(next.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.buffer)), (byte) => byte.toString(16).padStart(2, '0')).join('');
  if (!length || digest !== expectedSHA256) throw new Error('The PDF changed. Refresh this document and review its current PDF.');
  return bytes;
}

export async function uploadPDFTemplate(name: string, file: File): Promise<TemplateResponse> {
  const fd = new FormData();
  fd.append('name', name);
  fd.append('pdf', file);
  const res = await fetch('/api/v1/templates', {
    method: 'POST',
    credentials: 'include',
    body: fd
  });
  if (!res.ok) {
    throw new Error(await friendlyError(res));
  }
  return res.json();
}

export async function createBlocksTemplate(
  name: string,
  content?: { blocks_json?: BlockTree; variables_json?: Record<string, string> }
): Promise<TemplateResponse> {
  return request('POST', '/api/v1/templates', {
    name,
    source_kind: 'blocks',
    blocks_json: content?.blocks_json ?? { version: 1, blocks: [] },
    variables_json: content?.variables_json ?? {}
  });
}

// createStarterTemplate seeds a built-in starter (e.g. the Swedish services
// agreement, key 'services-agreement-sv') into the tenant's template library.
export async function createStarterTemplate(key: string, name?: string): Promise<TemplateResponse> {
  return request('POST', '/api/v1/templates/starter', { key, name });
}

export async function listDocuments(): Promise<{ documents: DocumentResponse[]; total: number }> {
  return request('GET', '/api/v1/documents');
}

export async function createBlocksDocument(name: string): Promise<DocumentResponse> {
  return request('POST', '/api/v1/documents', {
    name,
    source_kind: 'blocks',
    blocks_json: { version: 1, blocks: [] },
    variables_json: {}
  });
}

export async function createDocumentFromTemplate(
  name: string,
  templateID: string,
  sourceKind: 'blocks' | 'pdf',
  layout?: { expected_template_version: number; parties: PDFPartyBinding[] },
): Promise<DocumentResponse> {
  // Omit blocks_json/variables_json so the server seeds both from the template
  // (it copies them when the request leaves them empty).
  return request('POST', '/api/v1/documents', {
    name,
    source_kind: sourceKind,
    template_id: templateID,
    ...layout,
  });
}

export interface PDFPartyBinding {
  role: string;
  name: string;
  email: string;
  locale?: string;
}

export async function savePDFSigningTemplate(
  documentID: string,
  input: { name: string; expected_updated_at: string; expected_field_ids: string[]; parties: { recipient_id: string; role: string; label: string }[] },
): Promise<TemplateResponse> {
  return request('POST', `/api/v1/documents/${documentID}/pdf-template`, input);
}

export interface ImportResult {
  document: DocumentResponse;
  page_count: number;
}

// importProposalPDF creates a signable pdf-source document straight from an
// uploaded PDF (no template detour). Lands the document in the field designer.
export async function importProposalPDF(name: string, file: File): Promise<ImportResult> {
  const fd = new FormData();
  fd.append('name', name);
  fd.append('pdf', file);
  const res = await fetch('/api/v1/documents/import', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  });
  if (!res.ok) {
    throw new Error(await friendlyError(res));
  }
  return res.json();
}

// importProposalHTML renders a designed HTML page to a PDF (its own CSS/@page
// preserved) and creates a signable pdf-source document from it.
export async function importProposalHTML(
  name: string,
  html: string,
  landscape = false,
): Promise<ImportResult> {
  return request('POST', '/api/v1/documents/import', { name, html, landscape });
}

export async function getDocument(id: string): Promise<DocumentResponse> {
  return request('GET', `/api/v1/documents/${id}`);
}

export interface ChangeRequest {
  id: string;
  message: string;
  status: string;
  resolution?: string;
  block_id?: string;
  quote?: string;
  context?: string;
  proposed?: string;
  recipient_name?: string;
  recipient_email?: string;
  created_at: string;
}

export async function listChangeRequests(id: string): Promise<{ change_requests: ChangeRequest[] }> {
  return request('GET', `/api/v1/documents/${id}/change-requests`);
}

export async function approveChangeRequest(docID: string, crID: string): Promise<void> {
  await request('POST', `/api/v1/documents/${docID}/change-requests/${crID}/approve`);
}

export async function denyChangeRequest(docID: string, crID: string): Promise<void> {
  await request('POST', `/api/v1/documents/${docID}/change-requests/${crID}/deny`);
}

export async function setChangeApprovalMode(mode: 'accept' | 'auto_apply'): Promise<void> {
  await request('PATCH', '/api/v1/settings/change-approval-mode', { mode });
}

export interface DocComment {
  id: string;
  author_name: string;
  author_side: 'sender' | 'signer';
  body: string;
  created_at: string;
}

export async function listComments(id: string): Promise<{ comments: DocComment[] }> {
  return request('GET', `/api/v1/documents/${id}/comments`);
}

export async function postComment(id: string, body: string): Promise<DocComment> {
  return request('POST', `/api/v1/documents/${id}/comments`, { body });
}

// reviseDocument reopens a document a signer paused with a change request back to
// draft so the sender can edit and re-send it.
export async function reviseDocument(id: string): Promise<DocumentResponse> {
  return request('POST', `/api/v1/documents/${id}/revise`);
}

// documentSignatureFields walks a block document and returns the signature
// fields with their recipient role + label, so the sender UI can show which
// roles need a recipient before sending (one signature field = one signer).
export function documentSignatureFields(doc: DocumentResponse): { role: string; label: string }[] {
  const out: { role: string; label: string }[] = [];
  const walk = (blocks?: Block[]) => {
    for (const b of blocks ?? []) {
      if (b.type === 'signature_field') {
        out.push({
          role: ((b.attrs?.recipient_role as string) || 'signer'),
          label: ((b.attrs?.label as string) || 'Signature')
        });
      }
      if (b.content) walk(b.content);
    }
  };
  walk(doc.blocks_json?.blocks);
  return out;
}

export async function updateDocument(
  id: string,
  patch: {
    expected_updated_at: string;
    name?: string;
    blocks_json?: BlockTree;
    variables_json?: Record<string, string>;
    expires_at?: string;
    default_locale?: string;
    requires_signature?: boolean;
  }
): Promise<DocumentResponse> {
  return request('PATCH', `/api/v1/documents/${id}`, patch);
}

export async function appendBlock(docID: string, block: Omit<Block, 'id'>, expectedUpdatedAt: string): Promise<DocumentResponse> {
  return request('POST', `/api/v1/documents/${docID}/blocks`, { block, expected_updated_at: expectedUpdatedAt });
}

export async function saveCollaborativeDocument(id: string, input: {
  peer_id: string; checkpoint: string; generation: string;
  expected_updated_at: string; blocks_json: BlockTree;
}): Promise<{ document: DocumentResponse; generation: string }> {
  return request('POST', `/api/v1/documents/${id}/collab/save`, input);
}

export interface CollaborationRecoveryArchive {
  id: string;
  origin: 'persisted' | 'active_room';
  history_generation: string | null;
  observed_canonical_generation: string;
  created_at: string;
  expires_at: string;
  size_bytes: number;
}

export interface CollaborationRecoveryState {
  document: DocumentResponse;
  document_deleted: boolean;
  generation: string;
  archives: CollaborationRecoveryArchive[];
}

export async function getCollaborationRecovery(id: string): Promise<CollaborationRecoveryState> {
  return request('GET', `/api/v1/documents/${encodeURIComponent(id)}/collab/recovery`);
}

export async function recoverCollaboration(id: string, input: {
  generation: string; expected_updated_at: string; acknowledged: true;
}): Promise<{ document: DocumentResponse; generation: string }> {
  return request('POST', `/api/v1/documents/${encodeURIComponent(id)}/collab/recovery`, input);
}

export function collaborationArchiveURL(id: string, archiveID: string): string {
  return `/api/v1/documents/${encodeURIComponent(id)}/collab/recovery/archives/${encodeURIComponent(archiveID)}`;
}

export async function deleteCollaborationArchive(id: string, archiveID: string): Promise<void> {
  return request('DELETE', collaborationArchiveURL(id, archiveID), { acknowledged: true });
}

export async function updateBlock(docID: string, blockID: string, block: Block, expectedUpdatedAt: string): Promise<DocumentResponse> {
  return request('PATCH', `/api/v1/documents/${docID}/blocks/${blockID}`, { block, expected_updated_at: expectedUpdatedAt });
}

export async function deleteBlock(docID: string, blockID: string, expectedUpdatedAt: string): Promise<DocumentResponse> {
  return request('DELETE', `/api/v1/documents/${docID}/blocks/${blockID}`, { expected_updated_at: expectedUpdatedAt });
}

export async function reorderBlocks(docID: string, ids: string[], expectedUpdatedAt: string): Promise<DocumentResponse> {
  return request('POST', `/api/v1/documents/${docID}/blocks/reorder`, { block_ids: ids, expected_updated_at: expectedUpdatedAt });
}

export async function importHTML(docID: string, html: string, expectedUpdatedAt: string): Promise<DocumentResponse> {
  return request('POST', `/api/v1/documents/${docID}/import-html`, { html, expected_updated_at: expectedUpdatedAt });
}

export async function importMarkdown(docID: string, markdown: string, expectedUpdatedAt: string): Promise<DocumentResponse> {
  return request('POST', `/api/v1/documents/${docID}/import-md`, { markdown, expected_updated_at: expectedUpdatedAt });
}

export function previewURL(docID: string): string {
  return `/api/v1/documents/${docID}/preview`;
}

// --- Recipients -----------------------------------------------------------

export type RecipientStatus =
  | 'pending'
  | 'sent'
  | 'viewed'
  | 'signed'
  | 'accepted'
  | 'declined'
  | 'bounced';

export interface Recipient {
  id: string;
  document_id: string;
  role: string;
  email: string;
  name: string;
  order_index: number;
  locale: string;
  status: string;
  sent_at?: string;
  first_viewed_at?: string;
  signed_at?: string;
  created_at: string;
}

export interface RecipientInput {
  role: string;
  email: string;
  name: string;
  order_index: number;
  locale?: string;
}

export async function listRecipients(docID: string): Promise<Recipient[]> {
  const res = await request<{ recipients: Recipient[] }>(
    'GET',
    `/api/v1/documents/${docID}/recipients`,
  );
  return res.recipients ?? [];
}

export async function createRecipient(
  docID: string,
  input: RecipientInput,
): Promise<Recipient> {
  return request('POST', `/api/v1/documents/${docID}/recipients`, input);
}

export async function updateRecipient(
  docID: string,
  recipientID: string,
  input: Partial<RecipientInput>,
): Promise<Recipient> {
  return request(
    'PATCH',
    `/api/v1/documents/${docID}/recipients/${recipientID}`,
    input,
  );
}

export async function deleteRecipient(docID: string, recipientID: string): Promise<void> {
  await request('DELETE', `/api/v1/documents/${docID}/recipients/${recipientID}`);
}

// --- Billing --------------------------------------------------------------

export interface BillingPlan {
  id: string;
  slug: string;
  name: string;
  monthly_price_cents: number;
  yearly_price_cents: number;
  currency: string;
  document_quota_monthly: number;
  recipient_quota_monthly: number;
  features?: Record<string, boolean>;
}

export interface BillingSubscription {
  id?: string;
  status?: string;
  provider?: string;
  current_period_end?: string | null;
  cancel_at_period_end?: boolean;
}

export interface BillingInvoice {
  id: string;
  status: string;
  amount_cents: number;
  currency: string;
  hosted_invoice_url?: string;
  paid_at?: string | null;
  created_at: string;
}

export async function listBillingPlans(): Promise<{
  plans: BillingPlan[];
  billing_enabled: boolean;
  payments_enabled?: boolean;
  provider?: string;
}> {
  return request('GET', '/api/v1/billing/plans');
}

export async function getBillingSubscription(): Promise<{
  plan?: BillingPlan;
  subscription?: BillingSubscription;
  billing_enabled: boolean;
  payments_enabled?: boolean;
}> {
  return request('GET', '/api/v1/billing/subscription');
}

export async function listBillingInvoices(): Promise<{ invoices: BillingInvoice[] }> {
  return request('GET', '/api/v1/billing/invoices');
}

export async function startBillingCheckout(
  planSlug: string,
  interval: 'monthly' | 'yearly',
): Promise<{ checkout_url: string }> {
  return request('POST', '/api/v1/billing/checkout', { plan_slug: planSlug, interval });
}

export async function cancelBillingSubscription(): Promise<void> {
  await request('POST', '/api/v1/billing/cancel');
}

// --- Lifecycle: send / remind / void --------------------------------------

export interface SignerLink {
  recipient_id: string;
  email: string;
  name: string;
  role: string;
  url: string;
}

export interface SendResult {
  status: string;
  links: SignerLink[];
}

/**
 * SendError surfaces the structured detail the backend returns for the two
 * "you cannot send yet" cases the sender must act on: a 402 billing wall
 * (carries upgrade_url) and a 409 eIDAS guard (carries the tier gap and the
 * rules that matched). For every other failure `detail` is null and the
 * message is the raw body.
 */
export class SendError extends Error {
  status: number;
  upgradeURL?: string;
  requiredTier?: string;
  currentTier?: string;
  matchedRules?: string[];
  constructor(status: number, message: string) {
    super(message);
    this.name = 'SendError';
    this.status = status;
  }
}

export type LawfulBasis = 'contract';

export async function sendDocument(docID: string, lawfulBasis: LawfulBasis): Promise<SendResult> {
  const res = await fetch(`/api/v1/documents/${docID}/send`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lawful_basis: lawfulBasis }),
  });
  if (res.ok) {
    return (await res.json()) as SendResult;
  }
  // Parse the structured error so the panel can render an upgrade CTA or the
  // exact eIDAS tier gap rather than a flat string.
  let body: Record<string, unknown> = {};
  try {
    body = await res.json();
  } catch {
    /* non-JSON error body; fall through to status text */
  }
  const message =
    (typeof body.error === 'string' && body.error) || `${res.status} ${res.statusText}`;
  const err = new SendError(res.status, message);
  if (typeof body.upgrade_url === 'string') err.upgradeURL = body.upgrade_url;
  if (typeof body.required_tier === 'string') err.requiredTier = body.required_tier;
  if (typeof body.current_tier === 'string') err.currentTier = body.current_tier;
  if (Array.isArray(body.matched_rules)) err.matchedRules = body.matched_rules as string[];
  throw err;
}

export async function remindDocument(docID: string): Promise<{ reminded: number }> {
  return request('POST', `/api/v1/documents/${docID}/remind`);
}

export async function voidDocument(
  docID: string,
  reason?: string,
): Promise<{ status: string }> {
  return request('POST', `/api/v1/documents/${docID}/void`, reason ? { reason } : undefined);
}

// --- Audit timeline + signed artefacts ------------------------------------

export interface TimelineEntry {
  id: string;
  document_id: string;
  kind: string;
  actor_user_id?: string;
  actor_email?: string;
  recipient_id?: string;
  ip?: string;
  user_agent?: string;
  payload?: unknown;
  created_at: string;
  occurrences: number;
  grouped_kinds?: string[];
  diff_changes?: unknown;
}

export async function getTimeline(
  docID: string,
): Promise<{ entries: TimelineEntry[]; count: number }> {
  return request('GET', `/api/v1/documents/${docID}/timeline`);
}

export function finalPdfURL(docID: string): string {
  return `/api/v1/documents/${docID}/final-pdf`;
}

export function auditCertURL(docID: string): string {
  return `/api/v1/documents/${docID}/audit-cert`;
}

export function timelineCsvURL(docID: string): string {
  return `/api/v1/documents/${docID}/timeline.csv`;
}

export async function getMe(): Promise<{ user_id: string; org_id: string; email: string; role: string; change_approval_mode?: string }> {
  return request('GET', '/api/v1/me');
}

// --- Org members + RBAC roles --------------------------------------------

export interface Member {
  id: string;
  email: string;
  name: string;
  role: string; // owner | sender | viewer
  is_self: boolean;
  created_at: string;
}

export async function listMembers(): Promise<Member[]> {
  const res = await request<{ members: Member[] }>('GET', '/api/v1/members');
  return res.members ?? [];
}

export async function updateMemberRole(id: string, role: string): Promise<Member> {
  return request('PATCH', `/api/v1/members/${id}/role`, { role });
}

export interface DashboardKPIs {
  by_status: Record<string, number>;
  sent_24h: number;
  completed_30d: number;
  awaiting_signature: number;
  expiring_within_7d: number;
  time_to_sign_p50_sec: number;
  agent_authored_30d: number;
  human_authored_30d: number;
}

export async function getDashboard(): Promise<DashboardKPIs> {
  return request('GET', '/api/v1/dashboard');
}

export interface APIKeyResponse {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
  plaintext?: string; // only on create response
}

export async function listAPIKeys(): Promise<{ api_keys: APIKeyResponse[] }> {
  return request('GET', '/api/v1/api-keys');
}

export async function createAPIKey(input: { name: string; scopes: string[]; expires_at?: string }): Promise<APIKeyResponse> {
  return request('POST', '/api/v1/api-keys', input);
}

export async function deleteAPIKey(id: string): Promise<void> {
  return request('DELETE', `/api/v1/api-keys/${id}`);
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  events_subscribed: string[];
  active: boolean;
  created_at: string;
  /** Returned ONCE on create. The list endpoint never re-emits it. */
  secret?: string;
  secret_ref?: string;
}

export async function listWebhooks(): Promise<{ webhooks: WebhookEndpoint[] }> {
  return request('GET', '/api/v1/webhooks');
}

export async function createWebhook(url: string, events: string[]): Promise<WebhookEndpoint> {
  return request('POST', '/api/v1/webhooks', { url, events_subscribed: events });
}

export async function deleteWebhook(id: string): Promise<void> {
  return request('DELETE', `/api/v1/webhooks/${id}`);
}

export interface WebhookDelivery {
  id: string;
  event_id: string;
  status: string;
  attempts: number;
  last_status_code?: number;
  last_error?: string;
  created_at: string;
}

export async function listWebhookDeliveries(id: string): Promise<{ deliveries: WebhookDelivery[] }> {
  return request('GET', `/api/v1/webhooks/${id}/deliveries`);
}

// --- Org branding -----------------------------------------------------

export interface OrgBranding {
  primary_hex: string;
  accent_hex: string;
  surface_hex: string;
  text_hex: string;
  muted_hex: string;
  logo_url: string;
  logo_alt: string;
  font_heading: string;
  font_body: string;
  signature_color: string;
}

export async function getBranding(): Promise<OrgBranding> {
  return request('GET', '/api/v1/branding');
}

export async function saveBranding(b: Partial<OrgBranding>): Promise<OrgBranding> {
  return request('PUT', '/api/v1/branding', b);
}

// --- Compliance -------------------------------------------------------

export interface ComplianceFlag {
  id: string;
  document_id: string | null;
  template_id: string | null;
  update_title: string;
  affected_topic: string;
  severity: string;
  suggested_action: string;
  status: string;
  raised_at: string;
}

export async function seedCompliance(business_type: string, jurisdiction: string): Promise<unknown> {
  return request('POST', '/api/v1/compliance/seed', { business_type, jurisdiction });
}

export async function getComplianceBaseline(): Promise<unknown> {
  return request('GET', '/api/v1/compliance/baseline');
}

export async function listComplianceFlags(status?: string): Promise<{ flags: ComplianceFlag[] }> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : '';
  return request('GET', `/api/v1/compliance/flags${qs}`);
}

export async function setComplianceFlagStatus(id: string, status: string): Promise<unknown> {
  return request('PATCH', `/api/v1/compliance/flags/${id}`, { status });
}

export async function runComplianceFlagSweep(): Promise<unknown> {
  return request('POST', '/api/v1/compliance/flag-run');
}

// --- eIDAS rules ------------------------------------------------------

export interface EIDASRule {
  id: string;
  name: string;
  priority: number;
  required_tier: string;
  reason: string;
  active: boolean;
  predicate_json?: unknown;
  created_at: string;
}

export async function listEIDASRules(): Promise<{ rules: EIDASRule[] }> {
  return request('GET', '/api/v1/eidas-rules');
}

export async function deleteEIDASRule(id: string): Promise<void> {
  return request('DELETE', `/api/v1/eidas-rules/${id}`);
}

export async function seedSwedishEIDASDefaults(): Promise<unknown> {
  return request('POST', '/api/v1/eidas-rules/seed-sweden');
}

export interface EIDASRuleInput {
  name: string;
  priority: number;
  predicate_json: unknown;
  required_tier: string;
  reason: string;
  active: boolean;
}

export async function createEIDASRule(input: EIDASRuleInput): Promise<EIDASRule> {
  return request('POST', '/api/v1/eidas-rules', input);
}

export async function updateEIDASRule(
  id: string,
  input: Partial<EIDASRuleInput>,
): Promise<EIDASRule> {
  return request('PATCH', `/api/v1/eidas-rules/${id}`, input);
}

export interface EIDASPreviewInput {
  amount: number;
  country: string;
  document_type: string;
  variables?: Record<string, string>;
  current_tier?: string;
}

export interface EIDASPreviewResult {
  required_tier: string;
  matched_rules: { id: string; name: string; required_tier: string; reason: string }[];
  evaluated_count: number;
  would_block?: boolean;
}

export async function previewEIDASRules(
  input: EIDASPreviewInput,
): Promise<EIDASPreviewResult> {
  return request('POST', '/api/v1/eidas-rules/preview', input);
}

// --- BYOAI: per-org AI provider ------------------------------------------

export interface OrgAIProvider {
  configured: boolean;
  byoai_available: boolean;
  provider?: string;
  base_url?: string;
  model?: string;
  enabled: boolean;
  key_last4?: string;
  updated_at?: string;
}

export interface OrgAIProviderInput {
  provider: string;
  base_url: string;
  model: string;
  api_key: string; // blank on update = keep existing key
  enabled: boolean;
}

export async function getOrgAIProvider(): Promise<OrgAIProvider> {
  return request('GET', '/api/v1/ai/provider');
}

export async function setOrgAIProvider(input: OrgAIProviderInput): Promise<OrgAIProvider> {
  return request('PUT', '/api/v1/ai/provider', input);
}

export async function deleteOrgAIProvider(): Promise<void> {
  await request('DELETE', '/api/v1/ai/provider');
}

// --- PDF fillable fields (designer + signer) ------------------------------

export interface DocumentField {
  id: string;
  document_id: string;
  type: string; // signature | text | date | checkbox | dropdown | initial
  page: number;
  x_pct: number;
  y_pct: number;
  w_pct: number;
  h_pct: number;
  required: boolean;
  recipient_id?: string;
  label?: string;
  value?: string;
  completed_at?: string;
  options?: unknown;
}

export interface FieldInput {
  recipient_id?: string;
  type: string;
  page: number;
  x_pct: number;
  y_pct: number;
  w_pct: number;
  h_pct: number;
  required?: boolean;
  label?: string;
  options?: Record<string, unknown>;
  expected_pdf_sha256?: string;
  expected_html_source_commitment?: string;
}

export async function listFields(docID: string): Promise<DocumentField[]> {
  const res = await request<{ fields: DocumentField[] }>(
    'GET',
    `/api/v1/documents/${docID}/fields`,
  );
  return res.fields ?? [];
}

export async function addField(docID: string, input: FieldInput): Promise<DocumentField> {
  return request('POST', `/api/v1/documents/${docID}/fields`, input);
}

export async function deleteField(fieldID: string, pins?: { expected_pdf_sha256: string; expected_html_source_commitment: string }): Promise<void> {
  await request('DELETE', `/api/v1/fields/${fieldID}`, pins);
}

export function documentPdfURL(docID: string): string {
  return `/api/v1/documents/${docID}/pdf`;
}

// --- Data Subject Rights ---------------------------------------------

export interface DSRRequest {
  id: string;
  org_id: string;
  document_id: string | null;
  recipient_id: string | null;
  subject_email: string;
  subject_name: string;
  kind: string;
  status: string;
  requested_via: string;
  requested_note: string;
  resolution_note: string;
  requested_at: string;
  fulfilled_at: string | null;
  due_at: string;
}

export async function listDSR(status?: string): Promise<{ requests: DSRRequest[] }> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : '';
  return request('GET', `/api/v1/dsr${qs}`);
}

export async function transitionDSR(id: string, status: string, resolution_note = ''): Promise<DSRRequest> {
  return request('PATCH', `/api/v1/dsr/${id}`, { status, resolution_note });
}

export async function exportSubjectData(email: string): Promise<unknown> {
  return request('GET', `/api/v1/data-subject/export?email=${encodeURIComponent(email)}`);
}

// --- Per-document agent tokens ---------------------------------------

export interface DocAgentToken {
  id: string;
  prefix: string;
  name: string;
  scopes: string[];
  max_uses: number;
  used_count: number;
  created_at: string;
  expires_at: string | null;
  last_used_at?: string;
  revoked_at?: string;
  /** Returned ONCE on mint; subsequent reads omit it. */
  token?: string;
}

export async function listDocAgentTokens(docID: string): Promise<{ tokens: DocAgentToken[] }> {
  return request('GET', `/api/v1/documents/${docID}/agent-tokens`);
}

export async function mintDocAgentToken(
  docID: string,
  scopes: string[],
  ttl_days?: number
): Promise<DocAgentToken> {
  return request('POST', `/api/v1/documents/${docID}/agent-tokens`, { scopes, ttl_days });
}

export async function revokeDocAgentToken(tokenID: string): Promise<void> {
  return request('DELETE', `/api/v1/agent-tokens/${tokenID}`);
}

// --- Audit hash-chain verifier ---------------------------------------

export interface AuditChainFailure {
  event_id: string;
  index: number;
  stored_row_hash: string;
  recomputed_hash: string;
  prev_hash: string;
  kind: string;
  reason: string;
}

export interface AuditChainResult {
  ok: boolean;
  total_checked: number;
  first_bad_index: number;
  failures?: AuditChainFailure[];
}

export async function verifyAuditChain(limit = 5000): Promise<AuditChainResult> {
  return request('GET', `/api/v1/audit/verify-chain?limit=${limit}`);
}

// --- AI risk analysis ------------------------------------------------

export interface RiskFinding {
  block_id: string;
  category: string;
  severity: string;
  summary: string;
  suggestion: string;
}

export interface RiskAnalyzeResult {
  findings: RiskFinding[];
  raw_text?: string;
  provider?: string;
  model?: string;
  latency_ms?: number;
  shield_active?: boolean;
}

export async function runRiskAnalysis(
  docID: string,
  opts: { locale?: string; sender_context?: string } = {}
): Promise<RiskAnalyzeResult> {
  return request('POST', `/api/v1/documents/${docID}/risk-analysis`, {
    locale: opts.locale || 'en',
    sender_context: opts.sender_context || '',
  });
}

// --- Envelopes -------------------------------------------------------

export interface EnvelopeChild {
  id: string;
  name: string;
  status: string;
  envelope_position: number;
  final_pdf_sha256?: string;
}

export interface EnvelopeManifest {
  envelope_id: string;
  envelope_title: string;
  manifest_sha256: string;
  entries: Array<{
    child_id: string;
    title: string;
    position: number;
    status: string;
    content_snapshot_sha256: string;
  }>;
}

export async function listEnvelopeChildren(envelopeID: string): Promise<{ children: EnvelopeChild[] }> {
  return request('GET', `/api/v1/envelopes/${envelopeID}/children`);
}

export async function getEnvelopeManifest(envelopeID: string): Promise<EnvelopeManifest> {
  return request('GET', `/api/v1/envelopes/${envelopeID}/manifest`);
}

export async function attachToEnvelope(envelopeID: string, childID: string, position?: number): Promise<unknown> {
  return request('POST', `/api/v1/envelopes/${envelopeID}/attach`, {
    child_id: childID,
    position,
  });
}

export async function detachFromEnvelope(envelopeID: string, childID: string): Promise<unknown> {
  return request('POST', `/api/v1/envelopes/${envelopeID}/detach`, {
    child_id: childID,
  });
}

export async function reorderEnvelope(envelopeID: string, orderedChildIDs: string[]): Promise<unknown> {
  return request('POST', `/api/v1/envelopes/${envelopeID}/reorder`, {
    ordered_child_ids: orderedChildIDs,
  });
}

export async function promoteToEnvelope(docID: string): Promise<unknown> {
  return request('POST', `/api/v1/documents/${docID}/promote-to-envelope`);
}
