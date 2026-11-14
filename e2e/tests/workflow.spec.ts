import { test, expect, type APIRequestContext } from '@playwright/test';
import { randomUUID } from 'node:crypto';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

const MAILHOG = process.env.HASH_MAILHOG_URL || 'http://127.0.0.1:8025';

// Week 7: agent-driven workflow tools (send, void, remind, set_expiry,
// attach_metadata). These tests prove the moat: an agent can drive a
// document end-to-end via bearer-only MCP. The invitation case first uses
// an isolated owner-cookie REST prerequisite for its own SMTP configuration.

test.describe('MCP workflow write tools', () => {
  test('tools/list contains the new workflow tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'send_document',
      'void_document',
      'remind_recipient',
      'set_expiry',
      'attach_metadata'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('send_document rejects a signature-required draft with no signature field', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'No-signer test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'p', type: 'paragraph', text: 'hi' }] }
    });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'send_document',
      arguments: { document_id: doc.id, lawful_basis: 'contract' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('at least one signature field');
  });

  test('full agent workflow: create -> add_recipient -> send -> mailhog has invite', async ({ request, playwright, baseURL }) => {
    // This fixed disposable MCP workspace needs its own delivery transport.
    // Reuse the profiles' existing normal owner cookie only in this separate
    // REST prerequisite; the original MCP request context never receives it.
    const ownerCookie = process.env.HASH_E2E_SESSION_COOKIE;
    if (!ownerCookie) throw new Error('Missing HASH_E2E_SESSION_COOKIE');
    if (!baseURL) throw new Error('An explicit Hash browser origin is required for the owner fixture');
    const base = new URL(baseURL);
    if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash || base.pathname !== '/') {
      throw new Error('The owner fixture requires an explicit credential-free Hash origin');
    }
    const owner = await playwright.request.newContext({
      baseURL: base.origin,
      extraHTTPHeaders: { Cookie: ownerCookie, Origin: base.origin, Accept: 'application/json' }
    });
    try {
      const meResponse = await owner.get('/api/v1/me', { maxRedirects: 0 });
      expect(meResponse.status(), 'The existing fixture owner session is unavailable').toBe(200);
      const me = await meResponse.json();
      expect(me.role, 'The delivery prerequisite requires the fixed fixture owner').toBe('owner');
      expect(me.org_id, 'The owner session must belong to the fixed MCP workspace').toBe('11111111-1111-4111-8111-111111111111');

      const beforeResponse = await owner.get('/api/v1/workspace-smtp', { maxRedirects: 0 });
      expect(beforeResponse.status(), 'The owner could not read the current SMTP revision').toBe(200);
      const before = await beforeResponse.json();
      expect(before.schema_version).toBe(1);
      expect(Number.isSafeInteger(before.revision) && before.revision >= 0, 'The current SMTP revision must be explicit').toBe(true);
      const smtpHost = process.env.HASH_E2E_WORKSPACE_SMTP_HOST || 'smtp.hash.test';
      const expected = {
        schema_version: 1, revision: before.revision + 1, mode: 'configured', configured: true,
        host: smtpHost, port: 465, tls_mode: 'tls', sender_name: 'Hash CI Browser',
        sender_email: 'workflow-sender@example.test', username_set: false, password_set: false
      };
      const savedResponse = await owner.put('/api/v1/workspace-smtp', {
        maxRedirects: 0,
        data: { expected_revision: before.revision, host: smtpHost, port: 465, tls_mode: 'tls',
          sender_name: expected.sender_name, sender_email: expected.sender_email,
          credentials_action: 'replace', username: '', password: '' }
      });
      expect(savedResponse.status(), 'The owner SMTP prerequisite was not saved at the observed revision').toBe(200);
      const saved = await savedResponse.json();
      const maskedKeys = ['schema_version', 'revision', 'mode', 'configured', 'host', 'port', 'tls_mode',
        'sender_name', 'sender_email', 'username_set', 'password_set', 'updated_at'].sort();
      expect(Object.keys(saved).sort(), 'SMTP readback must expose only the masked settings contract').toEqual(maskedKeys);
      expect(saved).toMatchObject(expected);
      expect(typeof saved.updated_at).toBe('string');
      const readbackResponse = await owner.get('/api/v1/workspace-smtp', { maxRedirects: 0 });
      expect(readbackResponse.status(), 'The owner SMTP prerequisite could not be read back').toBe(200);
      const readback = await readbackResponse.json();
      expect(Object.keys(readback).sort(), 'SMTP readback must remain masked').toEqual(maskedKeys);
      expect(readback).toEqual(saved);
    } finally {
      await owner.dispose();
    }

    const nonce = randomUUID();
    const documentName = `Workflow E2E ${nonce}`;

    // Step 1: author
    const doc = await tool(request, 'create_document', {
      name: documentName,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'h', type: 'heading', attrs: { level: 1 }, text: 'NDA' },
          { id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }
        ]
      }
    });
    expect(doc.status).toBe('draft');

    // Step 2: recipient
    const recipientEmail = `wf-${nonce}@example.test`;
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'signer',
      email: recipientEmail,
      name: 'Workflow Test'
    });

    // Step 3: send
    const sendResult = await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
    expect(sendResult.status).toBe('sent');
    expect(Array.isArray(sendResult.links)).toBe(true);
    expect(sendResult.links.length).toBe(1);
    expect(sendResult.links[0].url).toMatch(/\/sign\//);

    // Step 4: require this invitation, preserving the original 30 x 100ms poll.
    // Another workspace's auth mail or a paginated global count proves nothing.
    let delivered = false;
    for (let i = 0; i < 30 && !delivered; i++) {
      await new Promise((r) => setTimeout(r, 100));
      delivered = await hasDeliveredInvite(request, recipientEmail, documentName);
    }
    expect(delivered, 'The unique workflow invitation was not delivered to MailHog').toBe(true);
  });

  test('void_document on a sent doc cancels it', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Void test',
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }]
      }
    });
    await tool(request, 'add_recipient', {
      document_id: doc.id, role: 'signer', email: 'void@example.com', name: 'V'
    });
    await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
    const voided = await tool(request, 'void_document', {
      document_id: doc.id, reason: 'agent recall'
    });
    expect(voided.status).toBe('voided');

    const fetched = await tool(request, 'get_document', { id: doc.id });
    expect(fetched.status).toBe('voided');
  });

  test('void_document on an already-voided doc fails (state-machine guard)', async ({ request }) => {
    // Reach the terminal state through the real lifecycle. Drafts are no
    // longer voidable: only a sent/in-progress ceremony can be recalled.
    const doc = await tool(request, 'create_document', {
      name: 'Void-terminal guard',
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }]
      }
    });
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'signer',
      email: `void-terminal-${Date.now()}@example.com`,
      name: 'Terminal Guard'
    });
    await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
    await tool(request, 'void_document', { document_id: doc.id, reason: 'first' });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'void_document',
      arguments: { document_id: doc.id, reason: 'second' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('only sent or in-progress documents can be voided');
  });

  test('attach_metadata round-trips through get_document', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Meta test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'attach_metadata', {
      document_id: doc.id,
      key: 'brightcrm_deal_id',
      value: 'deal_4f2c9e8a'
    });
    const fetched = await tool(request, 'get_document', { id: doc.id });
    const meta = fetched.metadata as Record<string, string>;
    expect(meta.brightcrm_deal_id).toBe('deal_4f2c9e8a');
  });

  test('set_expiry rejects past timestamps', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Expiry guard',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const past = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const res = await rpcRaw(request, 'tools/call', {
      name: 'set_expiry',
      arguments: { document_id: doc.id, expires_at: past }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('future');
  });

  test('set_expiry accepts a future timestamp', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Expiry happy path',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const future = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await tool(request, 'set_expiry', { document_id: doc.id, expires_at: future });
    const fetched = await tool(request, 'get_document', { id: doc.id });
    expect(fetched.expires_at).toBeTruthy();
  });
});

async function rpcRaw(request: APIRequestContext, method: string, params: unknown) {
  const res = await request.post('/mcp', {
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    data: { jsonrpc: '2.0', id: 1, method, params }
  });
  if (res.status() !== 200) {
    throw new Error(`MCP HTTP ${res.status()}: ${await res.text()}`);
  }
  return res.json();
}

async function tool(request: APIRequestContext, name: string, args: unknown) {
  const res = await rpcRaw(request, 'tools/call', { name, arguments: args });
  if (res.error) throw new Error(`rpc error: ${JSON.stringify(res.error)}`);
  if (res.result.isError) throw new Error(`tool error: ${res.result.content[0].text}`);
  return JSON.parse(res.result.content[0].text);
}

async function hasDeliveredInvite(request: APIRequestContext, recipient: string, documentName: string): Promise<boolean> {
  const response = await request.get(`${MAILHOG}/api/v2/search`, {
    params: { kind: 'to', query: recipient, start: 0, limit: 50 },
    maxRedirects: 0
  });
  expect(response.status(), 'The synthetic MailHog receiver is unavailable').toBe(200);
  const raw = await response.body();
  expect(raw.byteLength, 'The searched synthetic mailbox exceeded its fixture budget').toBeLessThanOrEqual(1 << 20);
  const body = JSON.parse(raw.toString('utf8'));
  expect(Array.isArray(body.items) && body.items.length <= 50, 'MailHog returned an invalid search page').toBe(true);
  const matches = body.items.filter((item: any) => {
    // SMTP envelope To is authoritative; a display/header address is not proof.
    const to = Array.isArray(item?.To) ? item.To : [];
    const exactRecipient = to.some((path: any) => typeof path?.Mailbox === 'string'
      && typeof path?.Domain === 'string' && `${path.Mailbox}@${path.Domain}` === recipient);
    const headers = item?.Content?.Headers;
    const subject = headers && typeof headers === 'object'
      ? Object.entries(headers).find(([name]) => name.toLowerCase() === 'subject')?.[1] : undefined;
    return exactRecipient && Array.isArray(subject)
      && subject.some((value: unknown) => typeof value === 'string' && value.includes(documentName));
  });
  expect(matches.length, 'The workflow produced duplicate matching invitations').toBeLessThanOrEqual(1);
  return matches.length === 1;
}
