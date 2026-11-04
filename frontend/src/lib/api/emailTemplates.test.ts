import { afterEach, describe, expect, test } from 'bun:test';
import { emailTemplateKinds, editableEmailTemplateKinds, type EmailTemplateKind } from '../emailTemplateEditor';
import { listEmailTemplates, previewEmailTemplate, saveEmailTemplate } from './emailTemplates';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });
const item = (kind: EmailTemplateKind = emailTemplateKinds[0], revision = 0) => ({ kind, revision, editable: editableEmailTemplateKinds.includes(kind), subject_template: '', html_template: '', text_template: '', variables: ['document_name'], mandatory_content: 'appended_by_hash' });
const catalog = () => ({ schema_version: 1, templates: emailTemplateKinds.map(kind => item(kind)), limits: { subject_bytes: 256, html_bytes: 16384, text_bytes: 8192, design_bytes: 131072 }, preview_synthetic: true });
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

import { defaultEmailDesign } from '../emailDesign';
import { proposeEmailDesign } from './emailTemplates';
const designSource = () => JSON.stringify(defaultEmailDesign());
const proposal = () => ({ schema_version: 1, saved: false, kind: 'email.invite', expected_revision: 2,
  input: { ...input, design_json: designSource() },
  preview: { schema_version: 1, synthetic: true, revision: 2, subject: 'Proposal', html: '<p>Native</p>', text: 'Native', mandatory_content_preserved: true } });
test('design omission is preserved and explicit empty design is forwarded for CAS clearing', async () => {
  for (const draft of [input, { ...input, design_json: '' }, { ...input, design_json: designSource() }]) {
    const calls = respond({ ...item(undefined, 3), ...draft, revision: 3 });
    await saveEmailTemplate('email.invite', draft, new AbortController().signal);
    expect(JSON.parse(String(calls[0].options.body))).toEqual(draft);
  }
});
test('source byte limits and returned malformed design reject rather than silently dropping design', async () => {
  const calls = respond(item(undefined, 3));
  for (const patch of [{ design_json: null }, { design_json: '{"schema_version":1}' }, { design_json: ' '.repeat(131073) }, { subject_template: 'å'.repeat(129) }]) {
    await expect(saveEmailTemplate('email.invite', { ...input, ...patch } as any, new AbortController().signal)).rejects.toThrow();
  }
  expect(calls).toHaveLength(0);
  const data = catalog(); (data.templates[0] as any).design_json = '{"schema_version":1}'; respond(data);
  await expect(listEmailTemplates(new AbortController().signal)).rejects.toThrow();
});
test('the complete nine-design catalogue can exceed the old512KiB bound while every row is validated', async () => {
  const bytes = new Uint8Array(32768); const digest = await crypto.subtle.digest('SHA-256', bytes);
  const sha256 = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
  const large = JSON.stringify({ ...defaultEmailDesign(), layout_html: '<div>' + 'a'.repeat(16200) + '{{logo}}{{native_content}}</div>', logo: { name: 'logo', media_type: 'image/png', data_base64: btoa(String.fromCharCode(...bytes)), sha256 } });
  const data = catalog(); for (const row of data.templates) { if (row.editable) Object.assign(row, { design_json: large, revision: 1 }); }
  // Escape legal JSON whitespace to exercise the actual wire bound beyond512KiB.
  const wire = JSON.stringify(data).replaceAll('a'.repeat(16200), '\\u0061'.repeat(16200)); expect(JSON.parse(wire)).toEqual(data); expect(wire.length).toBeGreaterThan(512 * 1024);
  globalThis.fetch = (async () => new Response(wire, { headers: { 'Content-Type': 'application/json' } })) as typeof fetch;
  expect((await listEmailTemplates(new AbortController().signal)).templates).toHaveLength(9);
  const invalid = catalog(); (invalid.templates[0] as any).design_json = large.replace(sha256, '0'.repeat(64)); respond(invalid);
  await expect(listEmailTemplates(new AbortController().signal)).rejects.toThrow('commitment');
});
test('configured-workspace AI proposal is one explicit POST and rejects saved, foreign or unbound candidates', async () => {
  const calls = respond(proposal()); const candidate = await proposeEmailDesign('email.invite', input, 'A calm, readable layout', new AbortController().signal);
  expect(candidate.saved).toBe(false); expect(calls).toHaveLength(1); expect(calls[0].path).toBe('/api/v1/email-templates/email.invite/propose');
  expect(JSON.parse(String(calls[0].options.body))).toEqual({ ...input, prompt: 'A calm, readable layout' });
  for (const patch of [{ saved: true }, { kind: 'email.reminder' }, { expected_revision: 3 }, { input: { ...input, design_json: null } }]) {
    respond({ ...proposal(), ...patch }); await expect(proposeEmailDesign('email.invite', input, 'Style', new AbortController().signal)).rejects.toThrow();
  }
});
test('preview supports bounded complete branded HTML and rejects an oversized stream', async () => {
  respond({ schema_version: 1, synthetic: true, revision: 2, subject: 'Sample', html: 'a'.repeat(200000), text: '', mandatory_content_preserved: true });
  expect((await previewEmailTemplate('email.invite', input, new AbortController().signal)).html.length).toBe(200000);
  respond({ schema_version: 1, synthetic: true, revision: 2, subject: 'Sample', html: 'a'.repeat(262145), text: '', mandatory_content_preserved: true });
  await expect(previewEmailTemplate('email.invite', input, new AbortController().signal)).rejects.toThrow();
  let cancelled = false;
  globalThis.fetch = (async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(4 * 1024 * 1024)); }, cancel() { cancelled = true; } }))) as typeof fetch;
  await expect(previewEmailTemplate('email.invite', input, new AbortController().signal)).rejects.toThrow('bound'); expect(cancelled).toBe(true);
});
