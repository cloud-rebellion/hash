import { APIError } from './client';
import { automationJSON } from './automationSettings';
import { emailDesignProblem, emailDesignLimits, readEmailDesign } from '../emailDesign';
import { emailTemplateKinds, editableEmailTemplateKinds, isBuiltInEmailTemplate, emailPreviewLocale, checkedWorkspaceEmailPreferences, isWorkspaceEmailLocale, type WorkspaceEmailPreferences, type WorkspaceEmailLocale, type EmailTemplate, type EmailTemplateCatalog, type EmailTemplateInput,
  type EmailDesignProposal, type EmailTemplateKind, type EmailTemplatePreview } from '../emailTemplateEditor';

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
    && (value.design_json === undefined || typeof value.design_json === 'string' && !emailDesignProblem(value.design_json))
    && value.mandatory_content === 'appended_by_hash' && Array.isArray(value.variables)
    && value.variables.length <= variables.length && new Set(value.variables).size === value.variables.length
    && value.variables.every(item => typeof item === 'string' && variables.includes(item));
}
const singleSourceBound = 6 * (256 + 16384 + 8192 + emailDesignLimits.source) + 4096;
const previewBound = 6 * (8192 + 2 * emailDesignLimits.rendered) + 4096;
async function jsonResponse(method: 'GET' | 'PUT' | 'POST', path: string, signal: AbortSignal, body?: EmailTemplateInput & { prompt?: string }, maxBytes = singleSourceBound): Promise<unknown> {
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
      if (length > maxBytes) { await reader.cancel(); throw new Error('Email template response exceeded its bound'); }
      chunks.push(result.value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result));
}
async function verifyDesignCommitment(source: string | undefined) {
  const design = readEmailDesign(source);
  if (!design?.logo) return;
  const decoded = Uint8Array.from(atob(design.logo.data_base64), ch => ch.charCodeAt(0));
  const digest = await crypto.subtle.digest('SHA-256', decoded);
  const actual = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
  if (actual !== design.logo.sha256) throw new Error('Email logo commitment rejected');
}
export async function listEmailTemplates(signal: AbortSignal): Promise<EmailTemplateCatalog> {
  const value = await jsonResponse('GET', '/api/v1/email-templates', signal, undefined, emailTemplateKinds.length * singleSourceBound + 4096);
  if (!object(value) || value.schema_version !== 1 || value.preview_synthetic !== true || !object(value.limits)
      || value.limits.subject_bytes !== 256 || value.limits.html_bytes !== 16384 || value.limits.text_bytes !== 8192 || value.limits.design_bytes !== emailDesignLimits.source
      || !Array.isArray(value.templates) || value.templates.length !== emailTemplateKinds.length
      || !value.templates.every(validTemplate) || new Set(value.templates.map(item => item.kind)).size !== value.templates.length) {
    throw new Error('Email template catalogue contract rejected');
  }
  await Promise.all((value.templates as EmailTemplate[]).map(item => verifyDesignCommitment(item.design_json)));
  return value as unknown as EmailTemplateCatalog;
}
function validInput(input: EmailTemplateInput): boolean {
  return object(input) && Object.keys(input).every(key => ['expected_revision', 'subject_template', 'html_template', 'text_template', 'design_json'].includes(key)) && revision(input.expected_revision) && input.expected_revision < Number.MAX_SAFE_INTEGER
    && typeof input.subject_template === 'string' && bytes(input.subject_template) <= 256 && !/[\r\n]/.test(input.subject_template)
    && typeof input.html_template === 'string' && bytes(input.html_template) <= 16384
    && typeof input.text_template === 'string' && bytes(input.text_template) <= 8192
    && (input.design_json === undefined || typeof input.design_json === 'string' && !emailDesignProblem(input.design_json));
}
export async function saveEmailTemplate(kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal): Promise<EmailTemplate> {
  if (!validInput(input)) throw new Error('Email source contract rejected');
  if (!editableEmailTemplateKinds.includes(kind)) throw new Error('This email kind is not customizable');
  const value = await jsonResponse('PUT', `/api/v1/email-templates/${encodeURIComponent(kind)}`, signal, input);
  if (!validTemplate(value) || value.editable !== true || value.kind !== kind || value.revision <= input.expected_revision || (input.design_json && !value.design_json)) throw new Error('Saved email template identity rejected');
  await verifyDesignCommitment(value.design_json);
  return value;
}
export async function previewEmailTemplate(kind: EmailTemplateKind, input: EmailTemplateInput, signal: AbortSignal): Promise<EmailTemplatePreview> {
  if (!validInput(input)) throw new Error('Email source contract rejected');
  if (!emailTemplateKinds.includes(kind) || (!editableEmailTemplateKinds.includes(kind)
      && !isBuiltInEmailTemplate({ ...input, revision: input.expected_revision }))) throw new Error('Only the built-in email can be previewed');
  const value = await jsonResponse('POST', `/api/v1/email-templates/${encodeURIComponent(kind)}/preview`, signal, input, previewBound);
  if (!object(value) || value.schema_version !== 1 || value.synthetic !== true || value.mandatory_content_preserved !== true || !emailPreviewLocale(kind, value.locale)
      || value.revision !== input.expected_revision || typeof value.subject !== 'string' || bytes(value.subject) > 8192
      || typeof value.html !== 'string' || bytes(value.html) > emailDesignLimits.rendered || typeof value.text !== 'string' || bytes(value.text) > emailDesignLimits.rendered) {
    throw new Error('Synthetic email preview contract rejected');
  }
  return value as unknown as EmailTemplatePreview;
}

export async function proposeEmailDesign(kind: EmailTemplateKind, input: EmailTemplateInput, prompt: string, signal: AbortSignal): Promise<EmailDesignProposal> {
  if (!editableEmailTemplateKinds.includes(kind) || !validInput(input) || typeof prompt !== 'string' || !prompt.trim() || bytes(prompt) > 4096) throw new Error('Email proposal source contract rejected');
  const value = await jsonResponse('POST', `/api/v1/email-templates/${encodeURIComponent(kind)}/propose`, signal, { ...input, prompt }, singleSourceBound + previewBound + 4096);
  if (!object(value) || value.schema_version !== 1 || value.saved !== false || value.kind !== kind || value.expected_revision !== input.expected_revision
      || !object(value.input) || !validInput(value.input as unknown as EmailTemplateInput) || value.input.expected_revision !== input.expected_revision
      || typeof value.input.design_json !== 'string' || !value.input.design_json
      || !object(value.preview) || value.preview.schema_version !== 1 || value.preview.synthetic !== true || value.preview.mandatory_content_preserved !== true || !emailPreviewLocale(kind, value.preview.locale)
      || value.preview.revision !== input.expected_revision || typeof value.preview.subject !== 'string' || bytes(value.preview.subject) > 8192
      || typeof value.preview.html !== 'string' || bytes(value.preview.html) > emailDesignLimits.rendered
      || typeof value.preview.text !== 'string' || bytes(value.preview.text) > emailDesignLimits.rendered) throw new Error('Email proposal response contract rejected');
  await verifyDesignCommitment(value.input.design_json as string);
  return value as unknown as EmailDesignProposal;
}


export async function getWorkspaceEmailPreferences(signal: AbortSignal): Promise<WorkspaceEmailPreferences> {
  return checkedWorkspaceEmailPreferences(await automationJSON('GET', '/api/v1/email-preferences', signal));
}
export async function saveWorkspaceEmailPreferences(saved: WorkspaceEmailPreferences, locale: WorkspaceEmailLocale, signal: AbortSignal): Promise<WorkspaceEmailPreferences> {
  const before = checkedWorkspaceEmailPreferences(saved);
  if (!isWorkspaceEmailLocale(locale) || before.revision >= Number.MAX_SAFE_INTEGER) throw new Error('Email preference input rejected');
  const value = checkedWorkspaceEmailPreferences(await automationJSON('PUT', '/api/v1/email-preferences', signal, { expected_revision: before.revision, locale }));
  if (value.org_id !== before.org_id || value.revision !== before.revision + 1 || value.locale !== locale) throw new Error('Saved email preference identity rejected');
  return value;
}
