<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import { signerNoticeHeaders } from '$lib/api/signerNotice';
  import {
    SignerPDFSession, confirmSignerPDFField, fetchSignerPDF, readSignerFieldResponse,
    signerPDFScopeKey, validateSignerPDFFields, validateSignerPDFObservation,
    type SignerPDFField as Field, type SignerPDFObservation, type SignerPDFScope
  } from '$lib/signerPDF';
  import { t } from '$lib/i18n';
  import type { PdfDoc } from '$lib/pdf';
  import { ContinuousPDFPages } from '$lib/pdfPageResidency';
  import { captureFlarePDFViewError } from '$lib/flare-client';

  type Props = {
    token: string;
    noticeDigest: string;
    observation: SignerPDFObservation;
    signed?: boolean;
    readOnly?: boolean;
    onReadyChange?: (ready: boolean, scope: SignerPDFScope) => void;
    onFilledChange?: (filled: boolean, scope: SignerPDFScope) => void;
    onSignatureClick?: (scope: SignerPDFScope) => void;
  };
  let { token, noticeDigest, observation, signed = false, readOnly = false, onReadyChange, onFilledChange, onSignatureClick }: Props = $props();

  type PageInfo = { num: number; w: number; h: number };

  let pages = $state<PageInfo[]>([]);
  let fields = $state<Field[]>([]);
  let fieldsLoaded = $state(false);
  let documentReady = $state(false);
  let mounted = $state(false);
  let loading = $state(true);
  let error = $state<string | null>(null);
  const buf = $state<Record<string, string>>({});
  const persisted = $state<Record<string, string>>({});
  const saving = $state<Record<string, boolean>>({});
  const saveErrors = $state<Record<string, string>>({});
  const canvasEls: Record<number, HTMLCanvasElement> = {};
  let session: SignerPDFSession | undefined;
  let residentPages = $state<number[]>([]);
  const pageOwners = new WeakMap<SignerPDFSession, ContinuousPDFPages<PdfDoc>>();
  const observedPDFRetirements = new WeakSet<Promise<void>>();

  function emptyValue(f: Field): string {
    return f.type === 'checkbox' ? 'false' : '';
  }

  function isFilled(f: Field, v: string): boolean {
    if (f.type === 'checkbox') return v === 'true';
    return v.trim() !== '';
  }

  function recomputeFilled(): boolean {
    if (!session?.current() || loading || error || !documentReady) return false;
    if (!fieldsLoaded) return false;
    if (Object.keys(saveErrors).length > 0) return false;
    for (const f of fields) {
      if (f.type === 'signature') continue;
      const draftValue = buf[f.id] ?? emptyValue(f);
      const persistedValue = persisted[f.id] ?? emptyValue(f);
      // Do not let signing race an autosave or proceed with a value that the
      // server has not confirmed. This also protects optional edits from being
      // silently lost when the recipient signs immediately after changing one.
      if (saving[f.id] || draftValue !== persistedValue) return false;
      if (f.required && !isFilled(f, persistedValue)) return false;
    }
    return true;
  }

  $effect(() => {
    // Referencing each state object keeps the parent gate reactive to field
    // loading, every keystroke, and every autosave transition.
    void fieldsLoaded;
    void documentReady;
    void loading;
    void error;
    void token;
    void noticeDigest;
    void JSON.stringify(observation);
    void JSON.stringify(buf);
    void JSON.stringify(persisted);
    void JSON.stringify(saving);
    void JSON.stringify(saveErrors);
    void fields.length;
    if (session?.current()) onFilledChange?.(recomputeFilled(), session.scope);
  });

  onMount(() => { mounted = true; });

  $effect(() => {
    if (!mounted) return;
    const scope: SignerPDFScope = { token, noticeDigest, observation: { ...observation } };
    const active = new SignerPDFSession(scope, () => signerPDFScopeKey(token, noticeDigest, observation));
    const ownedCanvases = new Set<HTMLCanvasElement>();
    untrack(() => {
      session = active;
      pages = [];
      residentPages = [];
      fields = [];
      fieldsLoaded = false;
      documentReady = false;
      loading = true;
      error = null;
      for (const state of [buf, persisted, saving, saveErrors, canvasEls]) {
        const record = state as Record<string, unknown>;
        for (const name of Object.keys(record)) delete record[name];
      }
      onFilledChange?.(false, scope);
      onReadyChange?.(false, scope);
      void loadDocument(active, ownedCanvases);
    });
    return () => {
      retireDocument(active, ownedCanvases);
      // A disposed viewer must never publish a positive callback.
      onFilledChange?.(false, scope);
      onReadyChange?.(false, scope);
    };
  });

  async function loadDocument(active: SignerPDFSession, ownedCanvases = new Set<HTMLCanvasElement>()) {
    let pendingPDF: Uint8Array<ArrayBuffer> | undefined;
    try {
      const scope = active.scope;
      validateSignerPDFObservation(scope.observation, scope.observation.document_id, scope.observation.recipient_id);
      if (!scope.token || !scope.noticeDigest) throw new Error('The signing context is unavailable. Please reopen your signing link.');
      const signal = active.controller.signal;
      pendingPDF = await fetchSignerPDF(scope, signal);
      active.assertCurrent();
      const data = await fetch(`/sign/${scope.token}/fields`, { signal, cache: 'no-store', credentials: 'same-origin' })
        .then(response => readSignerFieldResponse(response, scope.observation, signal));
      active.assertCurrent();
      const pdf = await import('$lib/pdf');
      active.assertCurrent();
      const load = pdf.startPdfData(pendingPDF);
      pendingPDF = undefined; // PDF.js now owns the data and its original retirement.
      active.attach(load);
      const doc = await load.promise;
      active.assertCurrent();
      const loadedFields = validateSignerPDFFields(data.fields, scope.observation, doc.numPages);
      if (data.count !== undefined && data.count !== loadedFields.length) throw new Error('The document field list is incomplete.');
      const owner = new ContinuousPDFPages(doc, {
        current: () => active.assertCurrent(),
        geometry: pdf.pageGeometry,
        mount: async infos => { pages = infos; await tick(); },
        canvas: num => {
          const canvas = canvasEls[num];
          if (canvas) ownedCanvases.add(canvas);
          return canvas;
        },
        paint: pdf.renderPage,
        recycle: pdf.recyclePage,
        isResident: pdf.pageIsResident,
        resident: (num, ready) => {
          if (active.current()) residentPages = ready ? [...new Set([...residentPages, num])] : residentPages.filter(page => page !== num);
        },
        failed: reason => {
          // Initial failures go through the existing load catch. A later
          // viewport repaint failure revokes the same source's positive proof.
          if (active.current() && documentReady) {
            captureFlarePDFViewError();
            error = `Unable to load document: ${errorMessage(reason)}`;
            documentReady = false;
            onFilledChange?.(false, scope); onReadyChange?.(false, scope);
            retireDocument(active, ownedCanvases);
          }
        }
      }, scope.observation.page_count ?? doc.numPages);
      pageOwners.set(active, owner);
      const rendered = await owner.start();
      active.assertCurrent();
      if (!owner.allPagesRendered()) throw new Error('The PDF preview stopped before review completed. Reopen the document.');
      pages = rendered;
      fields = loadedFields;
      for (const f of loadedFields) {
        const value = f.value ?? emptyValue(f);
        buf[f.id] = value;
        persisted[f.id] = value;
      }
      fieldsLoaded = true;
      documentReady = true;
      loading = false;
      onReadyChange?.(true, scope);
    } catch (e) {
      if (active.current()) {
        captureFlarePDFViewError();
        error = `Unable to load document: ${errorMessage(e)}`;
        loading = false;
        documentReady = false;
        fieldsLoaded = false;
        pages = [];
        fields = [];
        onFilledChange?.(false, active.scope);
        onReadyChange?.(false, active.scope);
      }
      retireDocument(active, ownedCanvases);
    } finally {
      // Only the pre-transfer buffer belongs here; never touch PDF.js-owned data.
      if (pendingPDF?.byteLength) pendingPDF.fill(0);
    }
  }

  function retireDocument(active: SignerPDFSession, ownedCanvases: Set<HTMLCanvasElement>): Promise<void> {
    pageOwners.get(active)?.stop();
    const retirement = active.destroy();
    // Report a rejected original cleanup once, including after route disposal.
    // Observing it never replaces its promise, outcome or once-only owner.
    if (!observedPDFRetirements.has(retirement)) {
      observedPDFRetirements.add(retirement);
      void retirement.catch(() => { captureFlarePDFViewError(); });
    }
    pageOwners.delete(active);
    // The shared ledger releases only exact-generation stores after original
    // native retirement and render settlement. Never zero DOM by late callback.
    ownedCanvases.clear();
    return retirement;
  }

  function errorMessage(value: unknown): string {
    return value instanceof Error && value.message ? value.message : 'The request failed.';
  }

  async function saveField(f: Field) {
    if (readOnly) return;
    const active = session;
    if (signed || !active?.current() || !documentReady || loading || error || !fieldsLoaded) return;
    const originalField = fields.find(candidate => candidate.id === f.id);
    if (!originalField || originalField.type === 'signature') return;
    const nextValue = buf[f.id] ?? emptyValue(f);
    const previousValue = persisted[f.id] ?? emptyValue(f);
    if (saving[f.id] || nextValue === previousValue) return;

    saving[f.id] = true;
    delete saveErrors[f.id];
    try {
      const scope = active.scope;
      const res = await fetch(`/sign/${scope.token}/fields`, {
        method: 'POST',
        signal: active.controller.signal,
        cache: 'no-store',
        credentials: 'same-origin',
        headers: signerNoticeHeaders(scope.noticeDigest, true),
        body: JSON.stringify({ values: [{ field_id: f.id, value: nextValue }] }),
      });
      active.assertCurrent();
      const data = await readSignerFieldResponse(res, scope.observation, active.controller.signal);
      active.assertCurrent();
      const updates = validateSignerPDFFields(data.updated, scope.observation, pages.length);
      const updated = updates.find(candidate => candidate.id === f.id);
      if (!updated || updates.length !== 1) {
        throw new Error('The server did not confirm the saved field.');
      }
      confirmSignerPDFField(originalField, updated);

      const confirmedValue = updated.value ?? emptyValue(f);
      persisted[f.id] = confirmedValue;
      buf[f.id] = confirmedValue;
      const index = fields.findIndex((candidate) => candidate.id === f.id);
      if (index >= 0) {
        fields[index] = { ...fields[index], ...updated };
        fields = [...fields];
      }
    } catch (e) {
      if (!active.current()) return;
      // A failed request may not have reached the server. Revert the visible
      // control to the last confirmed value so the UI and signing gate agree
      // with the durable ceremony state.
      buf[f.id] = previousValue;
      saveErrors[f.id] = errorMessage(e);
    } finally {
      if (active.current()) saving[f.id] = false;
    }
  }

  function fieldsOnPage(page: number): Field[] {
    return fields.filter((f) => f.page === page);
  }

  function fieldName(fieldID: string): string {
    const field = fields.find((candidate) => candidate.id === fieldID);
    return field?.label || field?.type || 'field';
  }
</script>

<div class="pdf-signer" data-pdf-ready={documentReady && !loading && !error} data-pdf-page-count={pages.length}>
  {#if error}
    <div class="err" role="alert">{error}</div>
  {/if}
  {#each Object.entries(saveErrors) as [fieldID, message] (fieldID)}
    <div class="err" role="alert">Could not save {fieldName(fieldID)}: {message}</div>
  {/each}
  {#if loading}
    <p class="muted">{$t('pdf.loading')}</p>
  {/if}
  <!-- Canvases must exist while loading, before tick/render begins. -->
    {#each pages as p (p.num)}
      <div class="page" style="width:{p.w}px" aria-label="Document page {p.num}">
        <canvas width="0" height="0" bind:this={canvasEls[p.num]} style="aspect-ratio:{p.w}/{p.h}"></canvas>
        {#if !residentPages.includes(p.num)}<span class="page-loading" role="status">Rendering page {p.num}…</span>{/if}
        {#if documentReady && !error}
        <div class="overlay">
          {#each fieldsOnPage(p.num) as f (f.id)}
            {#if f.type === 'signature' && readOnly}
              <span class="fld sig" style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%">Signing paused</span>
            {:else if f.type === 'signature'}
              <button
                type="button"
                class="fld sig"
                data-field-id={f.id}
                data-recipient-id={f.recipient_id ?? ''}
                class:done={signed}
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                onclick={() => {
                  if (!readOnly && !signed && residentPages.includes(p.num) && recomputeFilled() && session?.current()) onSignatureClick?.(session.scope);
                }}
                disabled={readOnly || signed || !residentPages.includes(p.num) || !recomputeFilled()}
                title={!recomputeFilled() ? $t('sign.fillRequiredTitle') : ''}
              >
                {signed ? $t('pdf.signed') : $t('pdf.signHere')}
              </button>
            {:else if f.type === 'checkbox'}
              <label
                class="fld chk"
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
              >
                <input
                  type="checkbox"
                  data-field-id={f.id}
                  data-recipient-id={f.recipient_id ?? ''}
                  checked={buf[f.id] === 'true'}
                  class:save-failed={Boolean(saveErrors[f.id])}
                  aria-invalid={Boolean(saveErrors[f.id])}
                  aria-busy={Boolean(saving[f.id])}
                  disabled={readOnly || signed || !documentReady || !residentPages.includes(p.num) || Boolean(saving[f.id])}
                  onchange={(e) => {
                    buf[f.id] = (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false';
                    void saveField(f);
                  }}
                />
              </label>
            {:else if f.type === 'dropdown'}
              <select
                class="fld inp"
                data-field-id={f.id}
                data-recipient-id={f.recipient_id ?? ''}
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                bind:value={buf[f.id]}
                class:save-failed={Boolean(saveErrors[f.id])}
                aria-invalid={Boolean(saveErrors[f.id])}
                aria-busy={Boolean(saving[f.id])}
                disabled={readOnly || signed || !documentReady || !residentPages.includes(p.num) || Boolean(saving[f.id])}
                onchange={() => void saveField(f)}
              >
                <option value="">{f.label || 'Select…'}</option>
                {#each f.options?.choices ?? [] as c}
                  <option value={c}>{c}</option>
                {/each}
              </select>
            {:else}
              <input
                class="fld inp"
                data-field-id={f.id}
                data-recipient-id={f.recipient_id ?? ''}
                type={f.type === 'date' ? 'date' : 'text'}
                placeholder={f.label || f.type}
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                bind:value={buf[f.id]}
                class:save-failed={Boolean(saveErrors[f.id])}
                aria-invalid={Boolean(saveErrors[f.id])}
                aria-busy={Boolean(saving[f.id])}
                disabled={readOnly || signed || !documentReady || !residentPages.includes(p.num) || Boolean(saving[f.id])}
                onchange={() => void saveField(f)}
              />
            {/if}
          {/each}
        </div>
        {/if}
      </div>
    {/each}
</div>

<style>
  .pdf-signer {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    align-items: center;
  }
  .page {
    position: relative;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.12);
    border: 1px solid var(--color-border-light, #e5e5e5);
    max-width: 100%;
  }
  .page canvas {
    display: block;
    width: 100%;
    height: auto;
  }
  .page-loading {
    position: absolute; top: 0.5rem; left: 0.5rem;
    color: var(--color-text-muted, #777); font-size: 0.875rem;
  }
  .overlay {
    position: absolute;
    inset: 0;
  }
  .fld {
    position: absolute;
    box-sizing: border-box;
    font-size: 12px;
  }
  .inp {
    border: 1px solid var(--color-accent, #4f46e5);
    background: rgba(79, 70, 229, 0.06);
    border-radius: 3px;
    padding: 0 4px;
  }
  .save-failed {
    border-color: var(--color-danger, #dc2626);
    outline: 2px solid rgba(220, 38, 38, 0.18);
  }
  .chk {
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .sig {
    border: 2px dashed var(--color-accent, #171717);
    background: rgba(23, 23, 23, 0.06);
    color: var(--color-accent, #171717);
    border-radius: 4px;
    font-weight: 600;
    cursor: pointer;
  }
  .sig.done {
    border-style: solid;
    color: var(--color-success, #15803d);
    border-color: var(--color-success, #15803d);
    background: rgba(21, 128, 61, 0.08);
  }
  .err {
    color: var(--color-danger, #dc2626);
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }
  .muted {
    color: var(--color-text-muted, #777);
    font-size: 0.875rem;
  }
</style>
