import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { SignerPDFSession, confirmSignerPDFField, readSignerFieldResponse, signerPDFScopeKey, validateSignerPDFFields, type SignerPDFScope } from '../signerPDF';

const component = await Bun.file(new URL('./PdfSignerView.svelte', import.meta.url)).text();
const transpiler = new Bun.Transpiler({ loader: 'ts' });
function callback(name: string, end: string, env: Record<string, unknown>) {
  const start = component.indexOf(`  ${name === 'saveField' ? 'async ' : ''}function ${name}(`);
  const finish = component.indexOf(end, start);
  if (start < 0 || finish < 0) throw new Error('Production callback not found');
  return new Function('env', `with (env) { ${transpiler.transformSync(component.slice(start, finish))}; return ${name}; }`)(env);
}
const scope: SignerPDFScope = { token: 'original-token', noticeDigest: 'acknowledged-notice', observation: {
  document_id: '10000000-0000-4000-8000-000000000001', recipient_id: '20000000-0000-4000-8000-000000000001', pdf_sha256: 'a'.repeat(64)
} };
const field = { id: '30000000-0000-4000-8000-000000000001', document_id: scope.observation.document_id,
  recipient_id: scope.observation.recipient_id, type: 'text', page: 1, x_pct: 10, y_pct: 20, w_pct: 30, h_pct: 8, required: true, value: 'Saved' };
function response(updated: unknown = [{ ...field, value: 'Edited' }], options?: { status?: number; headers?: Headers }) {
  const headers = options?.headers ?? new Headers({ 'Content-Type': 'application/json',
    'X-Hash-Document-Id': scope.observation.document_id, 'X-Hash-Recipient-Id': scope.observation.recipient_id,
    'X-Hash-PDF-SHA256': scope.observation.pdf_sha256 });
  return new Response(JSON.stringify(options?.status ? { error: 'Please retry' } : { updated }), { headers, status: options?.status ?? 200 });
}
function fixture() {
  const calls: any[] = [];
  let live = signerPDFScopeKey(scope.token, scope.noticeDigest, scope.observation);
  const env: any = {
    readOnly: false, signed: false, documentReady: true, loading: false, error: null, fieldsLoaded: true,
    fields: [{ ...field }], pages: [{ num: 1, w: 760, h: 1000 }],
    buf: { [field.id]: 'Edited' }, persisted: { [field.id]: 'Saved' }, saving: {}, saveErrors: {},
    session: new SignerPDFSession(scope, () => live),
    emptyValue: (f: any) => f.type === 'checkbox' ? 'false' : '',
    isFilled: (f: any, value: string) => f.type === 'checkbox' ? value === 'true' : !!value.trim(),
    errorMessage: (e: Error) => e.message,
    signerNoticeHeaders: (digest: string, acknowledged: boolean) => ({ digest, acknowledged }),
    readSignerFieldResponse, validateSignerPDFFields, confirmSignerPDFField,
    fetch: (url: string, options: unknown) => new Promise((resolve, reject) => calls.push({ url, options, resolve, reject }))
  };
  return { env, calls, navigate() { live = signerPDFScopeKey('next-token', scope.noticeDigest, scope.observation); },
    save: callback('saveField', '  function fieldsOnPage(', env), filled: callback('recomputeFilled', '  $effect(', env) };
}

let alertView: Promise<any> | undefined;
async function renderSaveErrors(selectedLocale: 'en' | 'sv', message: string, label: string) {
  const view = await (alertView ??= (async () => {
    const start = component.indexOf('  {#each Object.entries(saveErrors)');
    const end = component.indexOf('  {/each}', start);
    const fieldNameStart = component.indexOf('  function fieldName(');
    const fieldNameEnd = component.indexOf('\n</script>', fieldNameStart);
    if (start < 0 || end < start || fieldNameStart < 0 || fieldNameEnd < fieldNameStart) throw Error('Production field error view not found');
    const markup = component.slice(start, end + '  {/each}'.length);
    const source = `<script lang="ts">import {writable} from 'svelte/store'; import {signerRoomText,signerRoomError,signerRoomFieldType} from '../signerRoomUi'; let {selectedLocale,saveErrors,fields}=$props(); const locale=writable(selectedLocale); ${component.slice(fieldNameStart, fieldNameEnd)}</script>${markup}`;
    const directory = dirname(fileURLToPath(new URL('./PdfSignerView.svelte', import.meta.url)));
    const build = await Bun.build({ entrypoints: ['pdf-signer-errors'], target: 'bun', plugins: [{ name: 'production-pdf-signer-errors', setup(builder) {
      builder.onResolve({ filter: /^(svelte(?:\/|$)|\.\.\/signerRoomUi$)/ }, args => ({ path: Bun.resolveSync(args.path, directory) }));
      builder.onResolve({ filter: /^pdf-signer-errors$/ }, () => ({ path: 'entry', namespace: 'errors-entry' }));
      builder.onLoad({ filter: /.*/, namespace: 'errors-entry' }, () => ({ contents: "export {default as View} from 'pdf-signer-error-view'; export {render} from 'svelte/server';", loader: 'ts', resolveDir: directory }));
      builder.onResolve({ filter: /^pdf-signer-error-view$/ }, () => ({ path: 'view', namespace: 'errors-view' }));
      builder.onLoad({ filter: /.*/, namespace: 'errors-view' }, () => ({ contents: compile(source, { filename: join(directory, 'PdfSignerErrorFixture.svelte'), generate: 'server' }).js.code, loader: 'js', resolveDir: directory }));
    } }] });
    if (!build.success) throw Error(build.logs.map(String).join('\n'));
    const temporary = mkdtempSync(join(tmpdir(), 'hash-pdf-signer-errors-'));
    try {
      const output = join(temporary, 'view.mjs');
      writeFileSync(output, await build.outputs[0].text());
      return await import(pathToFileURL(output).href);
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  })());
  return view.render(view.View, { props: { selectedLocale, saveErrors: { [field.id]: message }, fields: [{ ...field, label }] } }).body;
}

describe('PDF signer readiness and durable edits', () => {
  test('requires the current verified PDF, all pages, field read and confirmed edits even when there are no required fields', () => {
    const state = fixture(); state.env.buf[field.id] = 'Saved';
    expect(state.filled()).toBe(true);
    for (const [name, value] of [['documentReady', false], ['loading', true], ['error', 'Rendering failed'], ['fieldsLoaded', false]]) {
      const f = fixture(); f.env.buf[field.id] = 'Saved'; f.env[name] = value;
      expect(f.filled()).toBe(false);
    }
    expect(fixture().filled()).toBe(false);
    state.env.saving[field.id] = true; expect(state.filled()).toBe(false);
    delete state.env.saving[field.id]; state.env.saveErrors[field.id] = 'failed'; expect(state.filled()).toBe(false);
    state.env.saveErrors = {}; state.navigate(); expect(state.filled()).toBe(false);
    const empty = fixture(); empty.env.fields = []; empty.env.documentReady = false;
    expect(empty.filled()).toBe(false);
  });
  test('uses the original token, acknowledged notice and abort signal, and only releases the gate after server confirmation', async () => {
    const state = fixture();
    const pending = state.save(field);
    expect(state.calls).toHaveLength(1);
    expect(state.calls[0].url).toBe('/sign/original-token/fields');
    expect(state.calls[0].options.headers).toEqual({ digest: 'acknowledged-notice', acknowledged: true });
    expect(state.calls[0].options.signal).toBe(state.env.session.controller.signal);
    expect(state.filled()).toBe(false);
    await state.save(field); expect(state.calls).toHaveLength(1);
    state.calls[0].resolve(response()); await pending;
    expect(state.env.persisted[field.id]).toBe('Edited');
    expect(state.env.buf[field.id]).toBe('Edited');
    expect(state.filled()).toBe(true);
  });
  test('failed, missing, drifted or geometrically changed confirmations revert controls and retain a visible blocking error', async () => {
    const badHeaders = new Headers({ 'Content-Type': 'application/json' });
    for (const res of [response(undefined, { status: 409 }), response([]), response([{ ...field, page: 2 }]),
      response([{ ...field, x_pct: 11 }]), response(undefined, { headers: badHeaders })]) {
      const state = fixture(); const pending = state.save(field);
      state.calls[0].resolve(res); await pending;
      expect(state.env.buf[field.id]).toBe('Saved');
      expect(state.env.persisted[field.id]).toBe('Saved');
      expect(state.env.saveErrors[field.id]).toBeTruthy();
      expect(state.env.saving[field.id]).toBe(false);
      expect(state.filled()).toBe(false);
    }
  });
  test('actual blocking alert localizes EN/SV while escaping the field label and withholding unknown error details', async () => {
    const label = 'Customer <img src=x onerror=privateMarker>';
    for (const selected of ['en', 'sv'] as const) {
      const html = await renderSaveErrors(selected, 'The server did not confirm the saved field.', label);
      expect(html).toContain('role="alert"');
      expect(html).toContain(selected === 'sv'
        ? 'Kunde inte spara Customer &lt;img src=x onerror=privateMarker>: Servern bekräftade inte det sparade fältet.'
        : 'Could not save Customer &lt;img src=x onerror=privateMarker>: The server did not confirm the saved field.');
      expect(html).not.toContain('<img');
      const unknown = await renderSaveErrors(selected, 'private-server-error <script>secret</script>', 'Customer');
      expect(unknown).toContain(selected === 'sv' ? 'Kunde inte spara Customer: Begäran misslyckades.' : 'Could not save Customer: The request failed.');
      expect(unknown).not.toContain('private-server-error');
      expect(unknown).not.toContain('secret');
    }
  });
  test('late successful and failed writes cannot mutate a different ceremony or release its pending state', async () => {
    for (const fail of [false, true]) {
      const state = fixture(); const pending = state.save(field);
      state.navigate();
      state.env.buf[field.id] = 'New ceremony draft';
      state.env.persisted[field.id] = 'New ceremony persisted';
      state.env.saveErrors[field.id] = 'New ceremony error';
      if (fail) state.calls[0].reject(new Error('old failure')); else state.calls[0].resolve(response());
      await pending;
      expect(state.env.buf[field.id]).toBe('New ceremony draft');
      expect(state.env.persisted[field.id]).toBe('New ceremony persisted');
      expect(state.env.saveErrors[field.id]).toBe('New ceremony error');
      expect(state.env.saving[field.id]).toBe(true);
    }
  });
  test('navigation during the response body read also refuses the late field value', async () => {
    const state = fixture(); const pending = state.save(field);
    let finish!: () => void;
    state.env.readSignerFieldResponse = async () => {
      await new Promise<void>(resolve => { finish = resolve; });
      return { updated: [{ ...field, value: 'Late edit' }] };
    };
    state.calls[0].resolve(response()); await Promise.resolve();
    state.navigate(); finish(); await pending;
    expect(state.env.persisted[field.id]).toBe('Saved');
    expect(state.env.buf[field.id]).toBe('Edited');
  });
  test('disabled, disposed, unrendered and signature controls never dispatch autosaves', async () => {
    for (const [name, value] of [['readOnly', true], ['signed', true], ['documentReady', false], ['loading', true], ['error', 'failed'], ['fieldsLoaded', false]]) {
      const state = fixture(); state.env[name] = value; await state.save(field); expect(state.calls).toHaveLength(0);
    }
    const stale = fixture(); stale.navigate(); await stale.save(field); expect(stale.calls).toHaveLength(0);
    const signature = fixture(); signature.env.fields[0].type = 'signature'; await signature.save(signature.env.fields[0]); expect(signature.calls).toHaveLength(0);
  });
});
