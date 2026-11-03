import { APIError } from './client';
import { emailTemplateKinds, editableEmailTemplateKinds, isBuiltInEmailTemplate, type EmailTemplate, type EmailTemplateCatalog, type EmailTemplateInput,
  type EmailTemplateKind, type EmailTemplatePreview } from '../emailTemplateEditor';

const variables = ['document_name', 'sender_name', 'sender_email', 'recipient_name', 'org_name'];
const bytes = (value: string) => new TextEncoder().encode(value).byteLength;
const object = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const revision = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
function validTemplate(value: unknown): value is EmailTemplate {
  return object(value) && emailTemplateKinds.includes(value.kind as EmailTemplateKind) && revision(value.revision)
    && typeof value.editable === 'boolean'
    && (value.editable ? editableEmailTemplateKinds.includes(value.kind as EmailTemplateKind) : isBuiltInEmailTemplate(value as unknown as EmailTemplate))
    && typeof value.subject_template === 'string' && bytes(value.subject_template) <= 256
    && typeof value.html_template === 'string' && bytes(value.html_template) <= 16384
    && typeof value.text_template === 'string' && bytes(value.text_template) <= 8192
    && value.mandatory_content === 'appended_by_hash' && Array.isArray(value.variables)
    && value.variables.length <= variables.length && new Set(value.variables).size === value.variables.length
    && value.variables.every(item => typeof item === 'string' && variables.includes(item));
}
async function jsonResponse(method: 'GET' | 'PUT' | 'POST', path: string, signal: AbortSignal, body?: EmailTemplateInput): Promise<unknown> {
  const response = await fetch(path, {
    method, signal, credentials: 'include', cache: 'no-store',
    headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new APIError(response.status, 'Email template request rejected.');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Missing email template response');
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    for (;;) {
      const result = await reader.read(); if (result.done) break;
      length += result.value.byteLength;
      if (length > 512 * 1024) { await reader.cancel(); throw new Error('Email template response exceeded its bound'); }
      chunks.push(result.value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result));
}
export async function listEmailTemplates(signal: AbortSignal): Promise<EmailTemplateCatalog> {
  const value = await jsonResponse('GET', '/api/v1/email-templates', signal);
  if (!object(value) || value.schema_version !== 1 || value.preview_synthetic !== true || !object(value.limits)
      || value.limits.subject_bytes !== 256 || value.limits.html_bytes !== 16384 || value.limits.text_bytes !== 8192
      || !Array.isArray(value.templates) || value.templates.length !== emailTemplateKinds.length
      || !value.templates.every(validTemplate) || new Set(value.templates.map(item => item.kind)).size !== value.templates.length) {
    throw new Error('Email template catalogue contract rejected');
  }
  return value as unknown as EmailTemplateCatalog;
}
export async function saveEmailTemplate(kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal): Promise<EmailTemplate> {
  if (!editableEmailTemplateKinds.includes(kind)) throw new Error('This email kind is not customizable');
  const value = await jsonResponse('PUT', `/api/v1/email-templates/${encodeURIComponent(kind)}`, signal, input);
  if (!validTemplate(value) || value.editable !== true || value.kind !== kind || value.revision <= input.expected_revision) throw new Error('Saved email template identity rejected');
  return value;
}
export async function previewEmailTemplate(kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal): Promise<EmailTemplatePreview> {
  if (!emailTemplateKinds.includes(kind) || (!editableEmailTemplateKinds.includes(kind)
      && !isBuiltInEmailTemplate({ ...input, revision: input.expected_revision }))) throw new Error('Only the built-in email can be previewed');
  const value = await jsonResponse('POST', `/api/v1/email-templates/${encodeURIComponent(kind)}/preview`, signal, input);
  if (!object(value) || value.schema_version !== 1 || value.synthetic !== true || value.mandatory_content_preserved !== true
      || value.revision !== input.expected_revision || typeof value.subject !== 'string' || bytes(value.subject) > 8192
      || typeof value.html !== 'string' || bytes(value.html) > 128 * 1024 || typeof value.text !== 'string' || bytes(value.text) > 128 * 1024) {
    throw new Error('Synthetic email preview contract rejected');
  }
  return value as unknown as EmailTemplatePreview;
}
