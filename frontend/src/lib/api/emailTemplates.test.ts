import { afterEach, describe, expect, test } from 'bun:test';
import { emailTemplateKinds, editableEmailTemplateKinds, type EmailTemplateKind } from '../emailTemplateEditor';
import { listEmailTemplates, previewEmailTemplate, saveEmailTemplate } from './emailTemplates';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });
const item = (kind: EmailTemplateKind = emailTemplateKinds[0], revision = 0) => ({ kind, revision, editable: editableEmailTemplateKinds.includes(kind), subject_template: '', html_template: '', text_template: '', variables: ['document_name'], mandatory_content: 'appended_by_hash' });
const catalog = () => ({ schema_version: 1, templates: emailTemplateKinds.map(kind => item(kind)), limits: { subject_bytes: 256, html_bytes: 16384, text_bytes: 8192 }, preview_synthetic: true });
const input = { expected_revision: 2, subject_template: 'Hello {{recipient_name}}', html_template: '<p>Hello</p>', text_template: 'Hello' };
function respond(value: unknown, status = 200) {
  const calls: { path: string; options: RequestInit }[] = [];
  globalThis.fetch = (async (path: string | URL | Request, options: RequestInit) => { calls.push({ path: String(path), options }); return Response.json(value, { status }); }) as typeof fetch;
  return calls;
}
describe('email template HTTP contract', () => {
  test('missing/nonboolean/incompatible editable capability fails closed', async () => {
    for (const value of [undefined, 'true', 1]) {
      const data = catalog(); (data.templates[0] as unknown as Record<string, unknown>).editable = value;
      respond(data); await expect(listEmailTemplates(new AbortController().signal)).rejects.toThrow();
    }
    const data = catalog(); data.templates.find(value => value.kind === 'email.voided')!.editable = true;
    respond(data); await expect(listEmailTemplates(new AbortController().signal)).rejects.toThrow();
  });
  test('builtin-only metadata cannot hide a stored edition', async () => {
    const data = catalog(); const value = data.templates.find(value => value.kind === 'email.voided')!;
    value.revision = 2; value.text_template = 'Ignored edition'; respond(data);
    await expect(listEmailTemplates(new AbortController().signal)).rejects.toThrow();
  });
  test('builtin-only kinds reject save/custom preview before HTTP but permit native blank preview', async () => {
    const calls = respond({ schema_version: 1, synthetic: true, revision: 0, subject: 'Built in', html: '', text: '', mandatory_content_preserved: true });
    await expect(saveEmailTemplate('email.voided', input, new AbortController().signal)).rejects.toThrow();
    await expect(previewEmailTemplate('email.voided', input, new AbortController().signal)).rejects.toThrow(); expect(calls).toHaveLength(0);
    await previewEmailTemplate('email.voided', { expected_revision: 0, subject_template: '', html_template: '', text_template: '' }, new AbortController().signal);
    expect(calls).toHaveLength(1); expect(calls[0].path).toBe('/api/v1/email-templates/email.voided/preview');
  });
  test('loads the owner catalogue over same-origin authenticated no-store GET', async () => {
    const calls = respond(catalog()); const signal = new AbortController().signal; expect((await listEmailTemplates(signal)).templates).toHaveLength(9);
    expect(calls).toHaveLength(1); expect(calls[0].path).toBe('/api/v1/email-templates');
    expect(calls[0].options).toMatchObject({ method: 'GET', credentials: 'include', cache: 'no-store', signal }); expect(calls[0].options.body).toBeUndefined();
  });
  test('saves only content plus exact CAS; no transport, From or recipient input', async () => {
    const calls = respond({ ...item(undefined, 3), ...input, revision: 3 }); await saveEmailTemplate('email.invite', input, new AbortController().signal);
    expect(calls[0].path).toBe('/api/v1/email-templates/email.invite'); expect(calls[0].options.method).toBe('PUT');
    expect(JSON.parse(String(calls[0].options.body))).toEqual(input);
  });
  test('preview is synthetic, revision-bound and performs no save or send request', async () => {
    const calls = respond({ schema_version: 1, synthetic: true, revision: 2, subject: 'Sample', html: '<p>Sample</p>', text: 'Sample', mandatory_content_preserved: true });
    await previewEmailTemplate('email.invite', input, new AbortController().signal);
    expect(calls).toHaveLength(1); expect(calls[0].path).toBe('/api/v1/email-templates/email.invite/preview'); expect(calls[0].options.method).toBe('POST');
    expect(JSON.parse(String(calls[0].options.body))).toEqual(input);
  });
  test('catalogue refuses duplicate/unknown kinds, unsafe revision and lost immutable-content guarantee', async () => {
    for (const mutate of [
      (v: ReturnType<typeof catalog>) => { v.templates[1] = v.templates[0]; },
      (v: ReturnType<typeof catalog>) => { v.templates[0].revision = Number.MAX_SAFE_INTEGER + 1; },
      (v: ReturnType<typeof catalog>) => { v.templates[0].mandatory_content = 'editable'; },
      (v: ReturnType<typeof catalog>) => { v.templates[0].variables = ['url']; },
    ]) { const value = catalog(); mutate(value); respond(value); await expect(listEmailTemplates(new AbortController().signal)).rejects.toThrow(); }
  });
  test('refuses a foreign saved kind, nonadvancing revision and mismatched preview', async () => {
    respond(item('email.reminder', 3)); await expect(saveEmailTemplate('email.invite', input, new AbortController().signal)).rejects.toThrow();
    respond(item(undefined, 2)); await expect(saveEmailTemplate('email.invite', input, new AbortController().signal)).rejects.toThrow();
    for (const patch of [{ revision: 3 }, { synthetic: false }, { mandatory_content_preserved: false }]) {
      respond({ schema_version: 1, synthetic: true, revision: 2, subject: 'Sample', html: '', text: '', mandatory_content_preserved: true, ...patch });
      await expect(previewEmailTemplate('email.invite', input, new AbortController().signal)).rejects.toThrow();
    }
  });
  test('preserves actionable HTTP status without exposing arbitrary server errors', async () => {
    respond({ error: 'private database details' }, 409);
    try { await saveEmailTemplate('email.invite', input, new AbortController().signal); throw new Error('accepted'); }
    catch (error) { expect(error).toMatchObject({ status: 409 }); expect(String(error)).not.toContain('database'); }
  });
});
