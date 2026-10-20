import { describe, expect, test } from 'bun:test';
import {
  SignerPDFSession, confirmSignerPDFField, fetchSignerPDF, readBoundedSignerResponse,
  readSignerFieldResponse, renderSignerPDFPages, signerPDFScopeKey, validateSignerPDFFields,
  validateSignerPDFObservation, verifySignerPDFHeaders, type SignerPDFObservation, type SignerPDFScope
} from './signerPDF';

const documentID = '10000000-0000-4000-8000-000000000001';
const recipientID = '20000000-0000-4000-8000-000000000001';
const fieldID = '30000000-0000-4000-8000-000000000001';
const bytes = new TextEncoder().encode('%PDF-1.7\nlocal test bytes');
const sha = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), v => v.toString(16).padStart(2, '0')).join('');
const observation: SignerPDFObservation = { document_id: documentID, recipient_id: recipientID, pdf_sha256: sha };
const scope: SignerPDFScope = { token: 'original-token', noticeDigest: 'original-notice', observation };
function headers(observed = observation, contentType = 'application/pdf'): Headers {
  const h = new Headers({ 'Content-Type': contentType, 'X-Hash-Document-Id': observed.document_id,
    'X-Hash-Recipient-Id': observed.recipient_id, 'X-Hash-PDF-SHA256': observed.pdf_sha256 });
  if (observed.page_count !== undefined) h.set('X-Hash-PDF-Pages', `${observed.page_count}`);
  if (observed.html_source_commitment !== undefined) h.set('X-Hash-HTML-Source-Commitment', observed.html_source_commitment);
  if (observed.materialization_revision !== undefined) h.set('X-Hash-Materialization-Revision', `${observed.materialization_revision}`);
  return h;
}
const field = { id: fieldID, document_id: documentID, recipient_id: recipientID, type: 'text', page: 1,
  x_pct: 10, y_pct: 20, w_pct: 30, h_pct: 8, required: true, value: 'Saved' };

describe('recipient PDF observation', () => {
  test('requires the duplicate document and recipient witness; preserves legacy PDFs without a persisted page count', () => {
    expect(validateSignerPDFObservation(observation, documentID, recipientID)).toEqual(observation);
    const legacyHTML = { ...observation, html_source_commitment: 'a'.repeat(64) };
    expect(validateSignerPDFObservation(legacyHTML, documentID, recipientID)).toEqual(legacyHTML);
    for (const invalid of [undefined, { ...observation, document_id: recipientID }, { ...observation, recipient_id: documentID },
      { ...observation, pdf_sha256: 'unknown' }, { ...observation, page_count: 0 }, { ...observation, page_count: 501 }]) {
      expect(() => validateSignerPDFObservation(invalid, documentID, recipientID)).toThrow();
    }
  });
  test('registered HTML observations include the exact source, page count and revision together', () => {
    const html = { ...observation, html_source_commitment: 'a'.repeat(64), page_count: 2, materialization_revision: 3 };
    expect(validateSignerPDFObservation(html, documentID, recipientID)).toEqual(html);
    for (const invalid of [{ ...html, page_count: undefined }, { ...html, materialization_revision: undefined },
      { ...html, materialization_revision: 0 }, { ...observation, materialization_revision: 1 }]) {
      expect(() => validateSignerPDFObservation(invalid, documentID, recipientID)).toThrow();
    }
    for (const invalid of [{ ...observation, page_count: 1 }, { ...observation, page_count: 1, materialization_revision: 1 },
      { ...observation, html_source_commitment: 'a'.repeat(64), page_count: 1 },
      { ...observation, html_source_commitment: 'a'.repeat(64), materialization_revision: 1 }]) {
      expect(() => validateSignerPDFObservation(invalid, documentID, recipientID)).toThrow('incomplete');
    }
  });
  test('response headers match both values and presence rather than silently accepting another PDF', () => {
    verifySignerPDFHeaders(headers(), observation);
    for (const [name, value] of [['X-Hash-Document-Id', recipientID], ['X-Hash-Recipient-Id', documentID],
      ['X-Hash-PDF-SHA256', 'b'.repeat(64)], ['X-Hash-PDF-Pages', '1'], ['X-Hash-HTML-Source-Commitment', 'a'.repeat(64)],
      ['X-Hash-Materialization-Revision', '1']]) {
      const h = headers(); h.set(name, value);
      expect(() => verifySignerPDFHeaders(h, observation)).toThrow('changed');
    }
    const h = headers(); h.delete('X-Hash-PDF-SHA256');
    expect(() => verifySignerPDFHeaders(h, observation)).toThrow('changed');
  });
});

describe('bounded artifact and field reads', () => {
  test('checks response identity and browser SHA, and uses captured signal/no-store on the original token', async () => {
    const controller = new AbortController();
    const calls: any[] = [];
    const fetched = await fetchSignerPDF(scope, controller.signal, (async (...args: any[]) => {
      calls.push(args); return new Response(bytes, { headers: headers() });
    }) as typeof fetch);
    expect(fetched).toEqual(bytes);
    expect(calls[0]).toEqual(['/sign/original-token/pdf', { signal: controller.signal, cache: 'no-store', credentials: 'same-origin' }]);
    await expect(fetchSignerPDF(scope, controller.signal, (async () => new Response('other PDF bytes', { headers: headers() })) as typeof fetch)).rejects.toThrow('does not match');
    const wrong = headers(); wrong.set('X-Hash-Recipient-Id', documentID);
    await expect(fetchSignerPDF(scope, controller.signal, (async () => new Response(bytes, { headers: wrong })) as typeof fetch)).rejects.toThrow('changed');
    await expect(fetchSignerPDF(scope, controller.signal, (async () => new Response(bytes, { headers: headers(observation, 'text/html') })) as typeof fetch)).rejects.toThrow('not a PDF');
  });
  test('rejects declared and streamed oversize responses and cancels an interrupted body', async () => {
    const signal = new AbortController().signal;
    await expect(readBoundedSignerResponse(new Response('tiny', { headers: { 'Content-Length': '21' } }), 20, signal)).rejects.toThrow('limit');
    await expect(readBoundedSignerResponse(new Response(new Uint8Array(21)), 20, signal)).rejects.toThrow('limit');
    await expect(readBoundedSignerResponse(new Response(''), 20, signal)).rejects.toThrow('empty');
    let canceled = false;
    const controller = new AbortController();
    const response = new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); }, cancel() { canceled = true; } }));
    const pending = readBoundedSignerResponse(response, 20, controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow('closed');
    expect(canceled).toBe(true);
  });
  test('checks field headers before trusting JSON and refuses missing/malformed field payloads', async () => {
    const signal = new AbortController().signal;
    const data = await readSignerFieldResponse(new Response(JSON.stringify({ fields: [field] }), { headers: headers(observation, 'application/json') }), observation, signal);
    expect(validateSignerPDFFields(data.fields, observation, 1)).toEqual([field]);
    const wrong = headers(observation, 'application/json'); wrong.set('X-Hash-PDF-SHA256', 'b'.repeat(64));
    await expect(readSignerFieldResponse(new Response('{}', { headers: wrong }), observation, signal)).rejects.toThrow('changed');
    await expect(readSignerFieldResponse(new Response('[]', { headers: headers(observation, 'application/json') }), observation, signal)).rejects.toThrow('verified');
    expect(() => validateSignerPDFFields(undefined, observation, 1)).toThrow();
  });
  test('malformed JSON and invalid UTF8 expose a fixed field-verification error without parser excerpts', async () => {
    const signal = new AbortController().signal;
    for (const body of ['{"synthetic_private_excerpt":', new Uint8Array([0xff])]) {
      await expect(readSignerFieldResponse(new Response(body, { headers: headers(observation, 'application/json') }), observation, signal))
        .rejects.toThrow('The document fields could not be verified. Please reopen your signing link.');
    }
  });
  test('validates field ownership, actual page geometry, uniqueness and choice bounds; retains unassigned legacy fields', () => {
    expect(validateSignerPDFFields([{ ...field, recipient_id: undefined }], observation, 1)).toHaveLength(1);
    for (const invalid of [{ ...field, document_id: recipientID }, { ...field, recipient_id: documentID }, { ...field, page: 2 },
      { ...field, page: 1.5 }, { ...field, w_pct: 0 }, { ...field, y_pct: -1 }, { ...field, x_pct: 90 },
      { ...field, h_pct: Infinity }, { ...field, type: 'unknown' }, { ...field, value: 'x'.repeat(4097) },
      { ...field, type: 'dropdown', options: { choices: ['duplicate', 'duplicate'] } }]) {
      expect(() => validateSignerPDFFields([invalid], observation, 1)).toThrow();
    }
    expect(() => validateSignerPDFFields([field, field], observation, 1)).toThrow();
    expect(() => confirmSignerPDFField(field, { ...field, page: 2 })).toThrow('changed');
    expect(() => confirmSignerPDFField(field, { ...field, value: 'New confirmed value' })).not.toThrow();
  });
});

describe('PDF lifetime and complete page rendering', () => {
  test('invalidates immediately on every ceremony input and destroys a PDF that resolves after navigation', () => {
    for (const changed of [{ ...scope, token: 'new-token' }, { ...scope, noticeDigest: 'new-notice' },
      { ...scope, observation: { ...observation, document_id: recipientID } },
      { ...scope, observation: { ...observation, recipient_id: documentID } },
      { ...scope, observation: { ...observation, pdf_sha256: 'b'.repeat(64) } },
      { ...scope, observation: { ...observation, page_count: 2 } }]) {
      let live = signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation);
      const session = new SignerPDFSession(scope, () => live);
      let destroyed = 0;
      live = signerPDFScopeKey(changed.token, changed.noticeDigest, changed.observation);
      expect(session.current()).toBe(false);
      expect(() => session.attach({ destroy: async () => { destroyed++; } })).toThrow('closed');
      expect(destroyed).toBe(1);
      session.destroy();
      expect(session.controller.signal.aborted).toBe(true);
    }
  });
  test('destroy aborts requests and destroys an attached PDF once', () => {
    const session = new SignerPDFSession(scope, () => signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation));
    let destroyed = 0;
    session.attach({ destroy: async () => { destroyed++; } });
    session.destroy(); session.destroy();
    expect(session.current()).toBe(false);
    expect(destroyed).toBe(1);
  });
  test('immediately aborts its signal while real PDF retirement remains pending', async () => {
    const session = new SignerPDFSession(scope, () => signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation));
    let finish!: () => void, destroyed = 0, retired = false;
    const closing = new Promise<void>(resolve => { finish = resolve; });
    session.attach({ destroy() { destroyed++; return closing; } });
    const joined = session.destroy();
    expect(session.current()).toBe(false); expect(session.controller.signal.aborted).toBe(true);
    expect(session.destroy()).toBe(joined); expect(destroyed).toBe(1);
    void joined.then(() => { retired = true; });
    await Promise.resolve(); expect(retired).toBe(false);
    finish(); await joined; expect(retired).toBe(true);
  });
  test('retains failed PDF retirement across repeated disposal', async () => {
    const session = new SignerPDFSession(scope, () => signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation));
    const failure = new Error('synthetic retirement refusal');
    let destroyed = 0;
    session.attach({ destroy() { destroyed++; return Promise.reject(failure); } });
    const joined = session.destroy();
    await expect(joined).rejects.toBe(failure);
    expect(session.destroy()).toBe(joined); expect(destroyed).toBe(1); expect(session.current()).toBe(false);
  });
  test('a stale attachment after idle disposal has a distinct joined retirement', async () => {
    const session = new SignerPDFSession(scope, () => signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation));
    const idle = session.destroy(); await idle;
    let finish!: () => void, destroyed = 0, retired = false;
    const closing = new Promise<void>(resolve => { finish = resolve; });
    expect(() => session.attach({ destroy() { destroyed++; return closing; } })).toThrow('closed');
    const joined = session.destroy(); expect(joined).not.toBe(idle); expect(destroyed).toBe(1);
    void joined.then(() => { retired = true; }); await Promise.resolve(); expect(retired).toBe(false);
    finish(); await joined; expect(retired).toBe(true); expect(session.current()).toBe(false);
  });
  test('mounts all canvases before rendering, and only resolves after every page rendered with positive dimensions', async () => {
    const calls: string[] = [];
    let mounted = false;
    const pages = await renderSignerPDFPages({ numPages: 2 }, { ...observation, page_count: 2 }, {
      current() {}, width: async (_, n) => { calls.push(`width${n}`); return 600; },
      mount: async p => { expect(p).toHaveLength(2); calls.push('mount'); mounted = true; },
      canvas: n => { expect(mounted).toBe(true); calls.push(`canvas${n}`); return {} as HTMLCanvasElement; },
      render: async (_, n) => { calls.push(`render${n}`); return { width: 760, height: 1000 }; }
    });
    expect(calls).toEqual(['width1', 'width2', 'mount', 'canvas1', 'render1', 'canvas2', 'render2']);
    expect(pages).toEqual([{ num: 1, w: 760, h: 1000 }, { num: 2, w: 760, h: 1000 }]);
  });
  test('never skips absent canvases, mismatched page counts or failed renders', async () => {
    const base = { current() {}, width: async () => 600, mount: async () => {}, canvas: () => ({} as HTMLCanvasElement), render: async () => ({ width: 760, height: 1000 }) };
    await expect(renderSignerPDFPages({ numPages: 1 }, { ...observation, page_count: 2 }, base)).rejects.toThrow('page count');
    await expect(renderSignerPDFPages({ numPages: 501 }, observation, base)).rejects.toThrow('page count');
    await expect(renderSignerPDFPages({ numPages: 1 }, observation, { ...base, canvas: () => undefined })).rejects.toThrow('displayed');
    await expect(renderSignerPDFPages({ numPages: 1 }, observation, { ...base, render: async () => { throw new Error('render rejected'); } })).rejects.toThrow('render rejected');
    await expect(renderSignerPDFPages({ numPages: 1 }, observation, { ...base, render: async () => ({ width: 0, height: 0 }) })).rejects.toThrow('rendered');
  });
  test('a render that finishes after navigation cannot publish ready pages', async () => {
    let resolve!: (value: { width: number; height: number }) => void;
    let started!: () => void;
    const rendering = new Promise<void>(r => { started = r; });
    let active = true;
    const pending = renderSignerPDFPages({ numPages: 1 }, observation, {
      current() { if (!active) throw new Error('stale'); }, width: async () => 600, mount: async () => {},
      canvas: () => ({} as HTMLCanvasElement), render: () => new Promise(r => { resolve = r; started(); })
    });
    await rendering;
    active = false; resolve({ width: 760, height: 1000 });
    await expect(pending).rejects.toThrow('stale');
  });
});
