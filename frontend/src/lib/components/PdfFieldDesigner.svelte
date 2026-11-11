<script lang="ts">
  import { ui, staffLocale } from '$lib/staffPreferences';
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import type { PdfDoc } from '$lib/pdf';
  import type { PdfLoad } from '$lib/pdfLoad';
  import { captureFlarePDFViewError } from '$lib/flare-client';
  import { ContinuousPDFPages } from '$lib/pdfPageResidency';
  import { PDFPaintLane, PDF_FIT_PAGE_HEIGHT, type ThumbnailPaint } from '$lib/pdfPageStrip';
  import PDFPageStrip from './PDFPageStrip.svelte';
  import {
    listFields,
    addField,
    deleteField,
    listRecipients,
    documentPdfURL,
    fetchVerifiedDocumentPDF,
    type DocumentField,
    type HTMLDocumentSource,
    type Recipient,
  } from '$lib/api/client';
  import { PenLine, Type, Calendar, CheckSquare, Trash2, Signature, FileText } from 'lucide-svelte';
  import { htmlPlacementPins, validateHTMLSource, verifiedHTMLGeneratedFields } from '$lib/htmlRevision';

  type Props = { documentID: string; recipientRevision?: number; hasHTMLSource?: boolean; pdfSHA256?: string; htmlSourceCommitment?: string;
    htmlSource?: HTMLDocumentSource | null; readonly?: boolean; fieldsEnabled?: boolean;
    onPlacementProof?: (proof: { documentID: string; pdfSHA256: string; htmlSourceCommitment: string; ready: boolean }) => void;
    onAddRecipient?: () => boolean | Promise<boolean>;
    onSignatureFieldsChange?: (fields: { role: string; label: string }[]) => void; onStateChange?: (state: {busy: boolean; dirty: boolean}) => void };
  let { documentID, recipientRevision = 0, hasHTMLSource = false, pdfSHA256, htmlSourceCommitment, htmlSource = null, readonly = false, fieldsEnabled = true, onPlacementProof, onAddRecipient, onSignatureFieldsChange, onStateChange }: Props = $props();
  const sourceHTML = untrack(() => hasHTMLSource), sourceSHA = untrack(() => pdfSHA256), sourceCommitment = untrack(() => htmlSourceCommitment);
  const retainedSource = untrack(() => htmlSource), generated = untrack(() => htmlSource?.source_schema_version === 3);

  type PageInfo = { num: number; w: number; h: number; scale: number };

  let pages = $state<PageInfo[]>([]);
  let activePage = $state(1);
  let fitPage = $state(true);
  let loadedPDF = $state.raw<PdfDoc | null>(null);
  let notice = $state<string | null>(null);
  let recipientOpening = $state(false);
  let fields = $state<DocumentField[]>([]);
  let recipients = $state<Recipient[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let saving = $state(false);
  let refreshingRecipients = $state(false);
  let recipientRefreshError = $state<string | null>(null);
  let appliedRecipientRevision = $state(untrack(() => recipientRevision));
  let rendered = $state(false);
  let residentPages = $state<number[]>([]);
  let pageResidency: ContinuousPDFPages<PdfDoc> | undefined;
  const placementUnavailable = $derived(!fieldsEnabled || readonly || generated || saving || loading || !rendered || refreshingRecipients || recipientRefreshError !== null || error !== null || pages.length === 0);
  let disposed = false;
  let pdfLoad: PdfLoad<PdfDoc> | null = null;
  const current = (target: string) => !disposed && documentID === target && hasHTMLSource === sourceHTML
    && (!sourceHTML || (pdfSHA256 === sourceSHA && htmlSourceCommitment === sourceCommitment
      && (!retainedSource || (htmlSource?.html_source_commitment === retainedSource.html_source_commitment
        && htmlSource.pdf_sha256 === retainedSource.pdf_sha256 && htmlSource.source_schema_version === retainedSource.source_schema_version))));
  const abort = new AbortController();
  const paintDocumentID = untrack(() => documentID);
  const paintLane = new PDFPaintLane(() => { if (!current(paintDocumentID)) throw new DOMException('The document view was closed.', 'AbortError'); });
  let pdfRenderer: typeof import('$lib/pdf') | null = null;
  const paintThumbnail: ThumbnailPaint<PdfDoc> = (doc, number, canvas, scale, options) => paintLane.paint('thumbnail', () => { if (!pdfRenderer) throw new Error('The PDF is not loaded.'); return pdfRenderer.renderPage(doc, number, canvas, scale, options); }, options.signal);

  function emitSignatureFields() {
    onSignatureFieldsChange?.((fieldsEnabled ? fields : []).filter((f) => f.type === 'signature' && f.required).map((f) => ({
      role: recipients.find((r) => r.id === f.recipient_id)?.role ?? 'unassigned',
      label: f.label ?? 'Signature',
    })));
  }
  function emitProof(ready: boolean) {
    onPlacementProof?.({ documentID, pdfSHA256: sourceSHA ?? '', htmlSourceCommitment: sourceCommitment ?? '', ready });
  }
  function verifyAssignments(recs: Recipient[], fs: DocumentField[]) {
    if (!Array.isArray(recs) || !Array.isArray(fs) || !recs.every((r) => r.document_id === documentID) || !fs.every((f) => f.document_id === documentID)) {
      throw new Error('The server returned field assignments for a different document.');
    }
    if (generated && retainedSource) verifiedHTMLGeneratedFields(retainedSource, fs, recs);
  }

  // Tool palette.
  const TOOLS = [
    { type: 'signature', label: 'Signature', icon: Signature, guidance: 'Choose a recipient, then click or drag on the page to place their signature.' },
    { type: 'text', label: 'Text', icon: Type, guidance: 'Click or drag on the page to add a text field for a recipient to fill.' },
    { type: 'date', label: 'Date', icon: Calendar, guidance: 'Click or drag on the page to add a date field for a recipient to fill.' },
    { type: 'checkbox', label: 'Checkbox', icon: CheckSquare, guidance: 'Click or drag on the page to add a checkbox for a recipient.' },
    { type: 'initial', label: 'Initial', icon: PenLine, guidance: 'Click or drag on the page to add a field for a recipient’s initials.' },
  ];
  let tool = $state('signature');
  let recipientID = $state('');
  let required = $state(true);

  // Drag-to-place state, in page-percentage coordinates.
  let draft = $state<{ page: number; x: number; y: number; w: number; h: number } | null>(null);
  let dragStart: { page: number; x: number; y: number; pointerID: number } | null = null;

  $effect(() => { const state={busy:saving,dirty:draft!==null}; untrack(()=>onStateChange?.(state)); });
  const canvasEls: Record<number, HTMLCanvasElement> = {};

  // Recipient deletion cascades assigned fields. Refresh both lists after a
  // confirmed recipient change, while retaining this designer through Preview
  // and waiting for any pending field write before replacing its local rows.
  $effect(() => {
    const revision = recipientRevision;
    if (!loading && !saving && !refreshingRecipients && revision !== appliedRecipientRevision) {
      void untrack(() => refreshPlacementContext(revision));
    }
  });

  async function refreshPlacementContext(revision: number) {
    if (!current(documentID) || loading || saving || refreshingRecipients) return;
    const target = documentID;
    refreshingRecipients = true;
    emitProof(false);
    recipientRefreshError = null;
    dragStart = null;
    draft = null;
    notice = null;
    try {
      const [recs, fs] = await Promise.all([listRecipients(target), listFields(target)]);
      if (!current(target) || revision !== recipientRevision) return;
      verifyAssignments(recs, fs);
      recipients = recs;
      fields = fs;
      emitSignatureFields();
      emitProof(rendered);
      if (!recs.some((r) => r.id === recipientID)) recipientID = recs[0]?.id ?? '';
      appliedRecipientRevision = revision;
    } catch (e) {
      if (current(target) && revision === recipientRevision) {
        recipientRefreshError = (e as Error).message;
        appliedRecipientRevision = revision;
      }
    } finally {
      if (current(target)) refreshingRecipients = false;
    }
  }

  // Observe each original retirement promise once, including after unmount.
  // Rejected native cleanup remains a real ownership failure; callers still
  // receive the same promise and rejection, without waiting for telemetry.
  const observedPDFRetirements = new WeakSet<Promise<void>>();
  function retirePDF(): Promise<void> {
    paintLane.close();
    const retirement = pdfLoad?.destroy() ?? Promise.resolve();
    if (pdfLoad && !observedPDFRetirements.has(retirement)) {
      observedPDFRetirements.add(retirement);
      void retirement.catch(() => { captureFlarePDFViewError(); });
    }
    return retirement;
  }
  onMount(async () => {
    const target = documentID;
    let initializationFailed = false;
    let pdfFailure: { error: unknown } | null = null;
    const isPDFRejection = (candidate: unknown): boolean => pdfFailure !== null && pdfFailure.error === candidate;
    try {
      emitProof(false);
      htmlPlacementPins(sourceHTML, sourceSHA, sourceCommitment);
      if (retainedSource) {
        validateHTMLSource(retainedSource, target, retainedSource.org_id);
        if (retainedSource.pdf_sha256 !== sourceSHA || retainedSource.html_source_commitment !== sourceCommitment) throw new Error('The saved signing locations belong to another PDF. Refresh this document.');
      } else if (sourceHTML && !readonly) throw new Error('Load and verify this document’s retained source before placing signature fields.');
      let pdf: typeof import('$lib/pdf');
      try { pdf = await import('$lib/pdf'); }
      catch (e) { pdfFailure = { error: e }; throw e; }
      if (!current(target)) return;
      pdfRenderer = pdf;
      const loadPDF = async () => {
        const bytes = sourceHTML ? await fetchVerifiedDocumentPDF(target, sourceSHA!, abort.signal) : null;
        if (!current(target) || initializationFailed) throw new DOMException('The document view was closed.', 'AbortError');
        try {
          pdfLoad = bytes ? pdf.startPdfData(bytes) : pdf.startPdf(documentPdfURL(target));
          const loaded = await pdfLoad.promise;
          if (!current(target) || initializationFailed) { await retirePDF(); throw new DOMException('The document view was closed.', 'AbortError'); }
          return loaded;
        } catch (e) { pdfFailure = { error: e }; throw e; }
      };
      const [recs, fs, doc] = await Promise.all([
        listRecipients(target),
        listFields(target),
        loadPDF(),
      ]);
      if (!current(target)) return;
      if (doc.numPages < 1 || doc.numPages > 500) throw new Error('This PDF exceeds the field-placement page limit.');
      if (retainedSource && doc.numPages !== retainedSource.page_count) throw new Error('The PDF page count differs from its saved source. Refresh this document.');
      verifyAssignments(recs, fs);
      loadedPDF = doc;
      recipients = recs;
      fields = fs;
      if (recs.length) recipientID = recs[0].id;

      try {
        pageResidency = new ContinuousPDFPages(doc, {
          current: () => { if (!current(target)) throw new DOMException('The document view was closed.', 'AbortError'); },
          geometry: pdf.pageGeometry,
          mount: async infos => { pages = infos; loading = false; await tick(); },
          canvas: num => canvasEls[num],
          paint: (...args) => paintLane.paint('page', () => pdf.renderPage(...args), args[4].signal),
          recycle: pdf.recyclePage,
          isResident: pdf.pageIsResident,
          resident: (num, ready) => {
            if (current(target)) residentPages = ready ? [...new Set([...residentPages, num])] : residentPages.filter(page => page !== num);
          },
          failed: reason => {
            if (current(target) && rendered) {
              if (!(reason instanceof Error && (reason.name === 'AbortError' || reason.name === 'RenderingCancelledException'))) captureFlarePDFViewError();
              error = (reason as Error).message; rendered = false; emitProof(false);
              void retirePDF();
            }
          }
        });
        pages = await pageResidency.start();
        if (!current(target)) return;
        if (!pageResidency.allPagesRendered()) throw new Error('The PDF preview stopped before review completed. Reopen the document.');
      } catch (e) { pdfFailure = { error: e }; throw e; }
      rendered = true;
      emitSignatureFields();
      emitProof(true);
    } catch (e) {
      const unexpectedPDF = isPDFRejection(e) && !(e instanceof Error && (e.name === 'AbortError' || e.name === 'RenderingCancelledException'));
      initializationFailed = true;
      abort.abort();
      pageResidency?.stop();
      let retirementFailed = false;
      try { await retirePDF(); } catch { retirementFailed = true; }
      if (current(target)) {
        if (unexpectedPDF) captureFlarePDFViewError();
        error = retirementFailed ? 'The PDF preview could not be closed. Refresh this page before trying again.' : (e as Error).message;
        rendered = false; emitProof(false);
      }
    } finally {
      if (current(target)) loading = false;
    }
  });

  onDestroy(() => {
    emitProof(false);
    onStateChange?.({ busy: false, dirty: false }); // an unmounted designer must not leave Send blocked
    disposed = true;
    paintLane.close();
    abort.abort();
    dragStart = null;
    draft = null;
    pageResidency?.stop();
    void retirePDF();
  });

  function setPageFit(fit: boolean) {
    if (typeof fit !== 'boolean' || !current(paintDocumentID) || saving || loading || refreshingRecipients || draft || error) return;
    fitPage = fit;
  }
  function selectPage(number: number) {
    if (!current(documentID) || saving || loading || refreshingRecipients || draft || error || !Number.isInteger(number) || number < 1 || number > pages.length) return;
    activePage = number; notice = null;
  }
  function chooseTool(type: string) { if (!placementUnavailable && TOOLS.some(item => item.type === type)) { tool = type; notice = null; } }
  async function addRecipient() {
    if (!current(documentID) || readonly || generated || saving || recipientOpening || !onAddRecipient) return;
    const target = documentID; recipientOpening = true;
    try { const opened = await onAddRecipient(); if (current(target) && !opened) notice = 'Finish the current action, then open Recipients below.'; }
    catch { if (current(target)) notice = 'The recipient form could not be opened. Use Recipients below.'; }
    finally { if (current(target)) recipientOpening = false; }
  }

  function recipientName(id?: string): string {
    if (!id) return 'Any recipient';
    const r = recipients.find((x) => x.id === id);
    return r ? r.name : 'recipient';
  }

  function pctFromEvent(e: PointerEvent, layer: HTMLElement) {
    const rect = layer.getBoundingClientRect();
    return {
      x: Math.min(100, Math.max(0, ((e.clientX - rect.left) / rect.width) * 100)),
      y: Math.min(100, Math.max(0, ((e.clientY - rect.top) / rect.height) * 100)),
    };
  }

  function onPointerDown(e: PointerEvent, page: number, layer: HTMLElement) {
    // A second pointer turns this into a navigation gesture, not placement.
    if (dragStart && e.pointerId !== dragStart.pointerID) {
      dragStart = null;
      draft = null;
      return;
    }
    if (page !== activePage || !e.isPrimary || e.button !== 0 || dragStart || readonly || generated || placementUnavailable || !pageResidency?.pageReady(page) || !current(documentID) || !pages.find((p) => p.num === page && p.w > 0 && p.h > 0)) return;
    if (tool === 'signature' && !recipientID) {
      notice = 'Pick a recipient before placing a signature field.';
      return;
    }
    notice = null;
    layer.setPointerCapture?.(e.pointerId);
    const p = pctFromEvent(e, layer);
    dragStart = { page, x: p.x, y: p.y, pointerID: e.pointerId };
    draft = { page, x: p.x, y: p.y, w: 0, h: 0 };
  }

  function onPointerMove(e: PointerEvent, layer: HTMLElement) {
    if (!dragStart || e.pointerId !== dragStart.pointerID) return;
    const p = pctFromEvent(e, layer);
    draft = {
      page: dragStart.page,
      x: Math.min(dragStart.x, p.x),
      y: Math.min(dragStart.y, p.y),
      w: Math.abs(p.x - dragStart.x),
      h: Math.abs(p.y - dragStart.y),
    };
  }

  function cancelPlacement(e: PointerEvent) {
    if (!dragStart || e.pointerId !== dragStart.pointerID) return;
    dragStart = null;
    draft = null;
  }

  async function onPointerUp(e: PointerEvent) {
    if (!dragStart || e.pointerId !== dragStart.pointerID) return;
    const d = draft;
    dragStart = null;
    draft = null;
    if (!d || d.page !== activePage || readonly || generated || placementUnavailable || !pageResidency?.pageReady(d.page) || !current(documentID)) return;
    // A click (no real drag) drops a sensibly sized default box.
    if (d.w < 1.5 || d.h < 1) {
      d.w = tool === 'signature' ? 26 : 18;
      d.h = tool === 'signature' ? 7 : 4;
      d.x = Math.min(d.x, 100 - d.w);
      d.y = Math.min(d.y, 100 - d.h);
    }
    const target = documentID;
    const input = {
      type: tool, page: d.page, x_pct: round(d.x), y_pct: round(d.y),
      w_pct: round(d.w), h_pct: round(d.h), required,
      recipient_id: recipientID || undefined,
      label: TOOLS.find((t) => t.type === tool)?.label,
      ...htmlPlacementPins(sourceHTML, sourceSHA, sourceCommitment),
    };
    saving = true;
    error = null;
    try {
      const created = await addField(target, input);
      if (current(target)) {
        if (created.document_id !== target) throw new Error('The server returned a field for a different document.');
        fields = [...fields, created]; emitSignatureFields();
      }
    } catch (e) {
      if (current(target)) error = (e as Error).message;
    } finally {
      if (current(target)) saving = false;
    }
  }

  function round(n: number): number {
    return Math.round(n * 1000) / 1000;
  }

  async function remove(f: DocumentField) {
    if (readonly || generated || placementUnavailable || !current(documentID) || f.document_id !== documentID) return;
    const target = documentID;
    saving = true;
    error = null;
    try {
      const pins = htmlPlacementPins(sourceHTML, sourceSHA, sourceCommitment);
      if (pins) await deleteField(f.id, pins); else await deleteField(f.id);
      if (current(target)) { fields = fields.filter((x) => x.id !== f.id); emitSignatureFields(); }
    } catch (e) {
      if (current(target)) error = (e as Error).message;
    } finally {
      if (current(target)) saving = false;
    }
  }

  function fieldsOnPage(page: number): DocumentField[] {
    return fieldsEnabled ? fields.filter((f) => f.page === page) : [];
  }

  function boxClass(type: string): string {
    return type === 'signature'
      ? 'border-accent bg-accent/10 text-accent'
      : 'border-info bg-info/10 text-info';
  }
</script>

<section class="card p-5 mb-6 min-w-0" aria-label={$ui(fieldsEnabled ? 'PDF signature locations' : 'Document pages')} data-generated-signatures={generated} data-placement-ready={rendered && !error && !recipientRefreshError && !refreshingRecipients}>
  <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      {#if fieldsEnabled}<Signature class="size-4" />{:else}<FileText class="size-4" />{/if} {$ui(!fieldsEnabled ? 'Document pages' : generated || readonly ? 'Signature locations' : 'Field designer')}
    </h2>
    <div class="flex gap-1" role="group" aria-label={$ui('Page size')}>
      <button type="button" class="btn text-xs {fitPage ? 'btn-primary' : 'btn-secondary'}" aria-pressed={fitPage} disabled={loading || saving || !!draft || !!error || refreshingRecipients} onclick={() => setPageFit(true)}>{$ui('Fit page')}</button>
      <button type="button" class="btn text-xs {!fitPage ? 'btn-primary' : 'btn-secondary'}" aria-pressed={!fitPage} disabled={loading || saving || !!draft || !!error || refreshingRecipients} onclick={() => setPageFit(false)}>{$ui('Larger page')}</button>
    </div>
  </div>
  {#if !fieldsEnabled}<p class="text-sm text-text-secondary mb-4">{$ui('Select a page below to view the saved PDF. Switch to Signing to add recipients and fillable fields.')}</p>
  {:else if generated}<p class="text-sm text-text-secondary mb-4 leading-relaxed">{$ui("Both signature locations are generated from the approved design and locked to this exact PDF and its printed parties. Change document values or wording above to create a new PDF; Hash regenerates its locations for fresh review.")}</p>
  {:else if readonly}<p class="text-sm text-text-secondary mb-4 leading-relaxed">{$ui("The saved field positions are shown for viewing.")}</p>
  {:else}<p class="text-sm text-text-secondary mb-4 leading-relaxed">
    {$ui("Pick a field type. On touch screens, tap to place a field and swipe to scroll. With a mouse, click or drag a box. Each signer fills their fields and signs where you drop a signature field; the values stamp onto the final PDF at exactly these positions.")}
  </p>{/if}

  <!-- Toolbar -->
  {#if fieldsEnabled && !generated && !readonly}<div class="flex flex-wrap items-end gap-3 mb-4 pb-4 border-b border-border-light">
    <div class="flex flex-wrap gap-1">
      {#each TOOLS as t}
        <button
          type="button" aria-pressed={tool === t.type}
          class="btn text-xs {tool === t.type ? 'btn-primary' : 'btn-secondary'}"
          disabled={placementUnavailable}
          onclick={() => chooseTool(t.type)}
        >
          <t.icon class="size-3" /> {$ui(t.label)}
        </button>
      {/each}
    </div>
    <label class="text-sm min-w-0 max-w-full">
      <span class="block text-xs uppercase tracking-widest text-text-muted font-mono mb-1">{$ui("Recipient")}</span>
      <select
        aria-label={$ui("Recipient")}
        bind:value={recipientID}
        onchange={() => notice = null}
        disabled={placementUnavailable}
        class="max-w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      >
        {#if tool === 'signature' && !recipientID}<option value="">{$ui('Choose a recipient')}</option>{/if}
        {#if tool !== 'signature'}
          <option value="">{$ui("Any recipient")}</option>
        {/if}
        {#each recipients as r (r.id)}
          <option value={r.id}>{r.name}</option>
        {/each}
      </select>
    </label>
    <label class="flex items-center gap-2 text-sm pb-2">
      <input type="checkbox" bind:checked={required} disabled={placementUnavailable} /> {$ui("Required")}
    </label>
  </div>{/if}

  {#if error}
    <div role="alert" class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3 space-y-2"><p>{$ui(error)}</p><p>{$ui('A previous request may have completed. Preserve other unsaved changes before reloading.')}</p><a class="btn btn-secondary" href={`/documents/${documentID}`} data-sveltekit-reload>{$ui('Reload document')}</a></div>
  {/if}
  {#if notice}<p role="status" class="text-sm text-warning mb-3">{$ui(notice)}</p>{/if}
  {#if fieldsEnabled && !generated && !readonly}<p class="text-sm font-medium text-text-primary mb-2" role="status">{$ui(TOOLS.find(item => item.type === tool)?.guidance ?? 'Choose a field type.')}</p><p class="text-xs text-text-secondary mb-3">{$ui('These tools add fillable fields; they do not edit existing PDF text. Change the source document to change its wording.')}</p>{/if}
  {#if !rendered && !loading && !error}<p class="text-xs text-text-muted mb-3" role="status">{$ui('Checking document pages before editing…')}</p>{/if}
  {#if saving}<p role="status" class="text-sm text-text-muted mb-3">{$ui("Saving field…")}</p>{/if}
  {#if refreshingRecipients}<p role="status" class="text-sm text-text-muted mb-3">{$ui("Refreshing field assignments…")}</p>{/if}
  {#if recipientRefreshError}
    <div role="alert" class="text-danger text-sm mb-3">
      <p>{$ui("Field assignments could not be refreshed:")} {recipientRefreshError}</p>
      <button type="button" class="btn btn-secondary" disabled={saving || refreshingRecipients} onclick={() => refreshPlacementContext(recipientRevision)}>{$ui("Retry field assignments")}</button>
    </div>
  {/if}

  {#if fieldsEnabled && recipients.length === 0 && !loading}
    <div class="p-3 rounded-md border border-warning bg-bg-elevated text-sm mb-3">
      <p>{$ui("Add recipients first so signature fields can be assigned to a signer.")}</p>
      {#if !generated && !readonly && onAddRecipient}<button type="button" class="btn btn-secondary mt-2" disabled={saving || recipientOpening} onclick={addRecipient}>{$ui('Add recipient')}</button>{/if}
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted text-sm">{$ui("Loading PDF...")}</p>
  {:else}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard focus lets users scroll the PDF placement pages.) -->
    <div class="max-w-full overflow-x-auto pt-3 space-y-6" role="region" aria-label={$ui(fieldsEnabled ? 'PDF field placement pages' : 'Document pages')} tabindex="0">
      {#each pages as p (p.num)}
        <div hidden={activePage !== p.num} class="relative mx-auto shadow-sm border border-border-light" style:width={fitPage ? `min(${p.w}px, calc(${PDF_FIT_PAGE_HEIGHT} * ${p.w / p.h}))` : `${p.w}px`} style:max-width="100%">
          <canvas width="0" height="0" bind:this={canvasEls[p.num]} aria-label={$ui("Document page {number}", { number: p.num })} class="block w-full h-auto" style="aspect-ratio:{p.w}/{p.h}"></canvas>
          {#if !residentPages.includes(p.num)}<span class="absolute left-2 top-2 text-sm text-text-muted" role="status">{$ui("Rendering page")} {p.num}…</span>{/if}
          <!-- The displayed page and overlay scale together; stored coordinates remain percentages. -->
          {#if fieldsEnabled}
          <div
            class="absolute inset-0 {generated || readonly ? '' : 'cursor-crosshair'}"
            role="application"
            tabindex="-1"
            aria-label={$ui('Field placement layer for page {number}', { number: p.num })}
            style="touch-action:pan-y pinch-zoom"
            onpointerdown={(e) => onPointerDown(e, p.num, e.currentTarget as HTMLElement)}
            onpointermove={(e) => onPointerMove(e, e.currentTarget as HTMLElement)}
            onpointerup={onPointerUp}
            onpointercancel={cancelPlacement}
            onlostpointercapture={cancelPlacement}
            onpointerleave={cancelPlacement}
          >
            {#each fieldsOnPage(p.num) as f (f.id)}
              <div
                data-field-id={f.id}
                data-recipient-id={f.recipient_id}
                class="absolute border-2 rounded flex items-center justify-between gap-1 px-1 text-[10px] font-mono {boxClass(f.type)}"
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
              >
                <span class="truncate">{f.type === 'signature' ? recipientName(f.recipient_id) : f.label || f.type}</span>
                {#if fieldsEnabled && !generated && !readonly}<button
                  type="button"
                  class="shrink-0 hover:text-danger"
                  aria-label={$ui("Remove field")}
                  disabled={placementUnavailable || !residentPages.includes(p.num)}
                  onpointerdown={(e) => e.stopPropagation()}
                  onclick={() => remove(f)}
                >
                  <Trash2 class="size-3" />
                </button>{/if}
              </div>
            {/each}
            {#if draft && draft.page === p.num}
              <div
                class="absolute border-2 border-dashed border-accent bg-accent/10 pointer-events-none rounded"
                style="left:{draft.x}%;top:{draft.y}%;width:{draft.w}%;height:{draft.h}%"
              ></div>
            {/if}
          </div>
          {/if}
          <span class="absolute -top-3 left-2 text-[10px] font-mono text-text-muted bg-bg-surface px-1">
            {$ui("Page")} {p.num}
          </span>
        </div>
      {/each}
    </div>
    {#if loadedPDF}<PDFPageStrip doc={loadedPDF} {activePage} paint={paintThumbnail} onSelect={selectPage} busy={!residentPages.includes(activePage)} disabled={saving || draft !== null || refreshingRecipients || !!error} translate={(text) => $ui(text)} />{/if}
  {/if}
</section>
