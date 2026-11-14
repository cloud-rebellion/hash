import { APIError } from './client';
import { checkedSMTPTest } from './workspaceSMTP';
import { emailTemplateKinds, isWorkspaceEmailLocale, type WorkspaceEmailLocale, type EmailTemplateKind } from '../emailTemplateEditor';

export async function startSavedEmailTemplateTest(kind: EmailTemplateKind, templateRevision: number, smtpRevision: number, signal: AbortSignal, previewLocale?: WorkspaceEmailLocale) {
  if ((previewLocale !== undefined && !isWorkspaceEmailLocale(previewLocale)) || !emailTemplateKinds.includes(kind) || !Number.isSafeInteger(templateRevision) || templateRevision < 0 || !Number.isSafeInteger(smtpRevision) || smtpRevision < 1) throw new Error('Invalid saved email test observation');
  const response = await fetch(`/api/v1/email-templates/${encodeURIComponent(kind)}/test`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ expected_template_revision: templateRevision, expected_smtp_revision: smtpRevision, ...(previewLocale === undefined ? {} : { preview_locale: previewLocale }) }),
  });
  if (response.status !== 202) {
    await response.body?.cancel().catch(() => {});
    throw new APIError(response.status, 'Saved email test request rejected.');
  }
  if (!response.headers.get('Content-Type')?.toLowerCase().startsWith('application/json') || !response.body) {
    await response.body?.cancel().catch(() => {});
    throw new Error('Saved email test response was not confirmed');
  }
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 4096) throw new Error('Saved email test response exceeded its bound');
      chunks.push(part.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const receipt = checkedSMTPTest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  if (receipt.status !== 'pending' || receipt.smtp_accepted || receipt.inbox_delivery_confirmed) throw new Error('Saved email test enqueue was not confirmed');
  return receipt;
}
