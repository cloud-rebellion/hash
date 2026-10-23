<script lang="ts">
 import { onMount, tick } from 'svelte';
 import { beforeNavigate } from '$app/navigation';
 import { exchangeNoticeAccess, getPublicNotice, fetchNoticePDF, noticeFileKey, noticeUnavailable, takeNoticeFragment, type PublicNotice, type NoticeFile } from '$lib/noticeAccess';
 import VerifiedPDFPages from './VerifiedPDFPages.svelte';
 let { noticeID }: { noticeID: string } = $props();
 let notice = $state.raw<PublicNotice | null>(null), bytes = $state.raw<Uint8Array<ArrayBuffer> | null>(null), selected = $state<NoticeFile | null>(null);
 let loading = $state(true), opening = $state(false), closing = $state(false), blocked = $state(false), error = $state<string | null>(null);
 let disposed = false, generation = 0, readGeneration = 0;
 let metaAbort: AbortController | null = null, pdfAbort: AbortController | null = null, pdfRead: Promise<void> | null = null;
 let previewOwner: { retire(): Promise<void> } | null = null;
 let retirement: Promise<void> | null = null;
 function consumeEntry() {
  // Remove the entire fragment before validation or any network operation.
  // A refresh uses only the short-lived purpose cookie, never browser storage.
  const fragment = window.location.hash;
  window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search);
  return takeNoticeFragment(fragment);
 }
 // Synchronous browser instantiation precedes layout onMount and all API work.
 // This private one-shot local is never reactive, persisted, logged or displayed.
 let entryCapability: string | null = null, entryInvalid = false;
 if (typeof window !== 'undefined') { try { entryCapability = consumeEntry(); } catch { entryInvalid = true; } }
 async function closePDF() {
  if (retirement) return retirement;
  readGeneration++; pdfAbort?.abort(); closing = true;
  const task = (async () => {
   await pdfRead?.catch(() => {}); await tick(); const owner = previewOwner;
   if (owner) await owner.retire(); if (previewOwner === owner) previewOwner = null;
   const previous = bytes; selected = null; bytes = null; previous?.fill(0); opening = false;
  })(); retirement = task;
  try { await task; } catch { blocked = true; if (!disposed) error = 'The PDF could not be closed safely. Refresh this page before opening another file.'; }
  finally { if (retirement === task) retirement = null; closing = false; }
 }
 async function load(exchange = false) {
  const operation = ++generation; metaAbort?.abort(); metaAbort = new AbortController(); const signal = metaAbort.signal;
  loading = true; error = null;
  try {
   let capability: string | null = null;
   try { if (exchange) { capability = entryCapability; entryCapability = null; if (entryInvalid) throw new Error(noticeUnavailable); } if (capability) await exchangeNoticeAccess(noticeID, capability, signal); }
   finally { capability = null; }
   const value = await getPublicNotice(noticeID, signal);
   if (!disposed && operation === generation) notice = value;
  } catch { if (!disposed && operation === generation) { notice = null; error = noticeUnavailable; } }
  finally { if (!disposed && operation === generation) loading = false; }
 }
 async function refresh() { if (loading || opening || closing || blocked) return; await closePDF(); if (!blocked) await load(); }
 async function open(file: NoticeFile, download = false) {
  if (!notice || disposed || loading || opening || closing || blocked || !notice.files.includes(file)) return;
  await closePDF(); if (blocked || disposed) return;
  const packet = notice, operation = ++readGeneration; pdfAbort = new AbortController(); const signal = pdfAbort.signal; opening = true; error = null;
  const task = (async () => {
   const value = await fetchNoticePDF(packet, file, signal);
   if (disposed || operation !== readGeneration || packet !== notice || signal.aborted) { value.fill(0); return; }
   if (download) {
    const url = URL.createObjectURL(new Blob([value], { type: 'application/pdf' }));
    try { const anchor = window.document.createElement('a'); anchor.href = url; anchor.download = 'notice-file-' + file.position + '.pdf'; anchor.rel = 'noopener'; anchor.click(); }
    finally { URL.revokeObjectURL(url); value.fill(0); }
   } else { selected = file; bytes = value; }
  })(); pdfRead = task;
  try { await task; } catch { if (!disposed && operation === readGeneration) error = noticeUnavailable; }
  finally { if (pdfRead === task) pdfRead = null; if (!disposed && operation === readGeneration) opening = false; }
 }
 beforeNavigate(() => { generation++; metaAbort?.abort(); void closePDF(); });
 onMount(() => { void load(true); return () => { disposed = true; entryCapability = null; generation++; metaAbort?.abort(); void closePDF(); }; });
</script>

<svelte:head><title>Email notice · Hash</title><meta name="robots" content="noindex,nofollow" /><meta name="referrer" content="no-referrer" /></svelte:head>
<main class="min-h-screen bg-bg px-4 py-8 sm:px-6">
 <div class="max-w-4xl mx-auto space-y-5">
  <p class="font-display text-xl">Hash</p>
  <header class="space-y-2"><p class="text-sm text-text-secondary">Shared email notice</p><h1 class="font-display text-2xl">{notice?.subject ?? 'Email notice'}</h1>
   <p class="text-sm text-text-secondary">Read the notice and its exact accompanying files. This page does not submit a signature or acknowledgement.</p></header>
  {#if loading}<p role="status">Opening the shared notice…</p>{/if}
  {#if error}<p role="alert" class="card border border-danger p-4 text-danger">{error}</p>{/if}
  {#if notice}<section class="card p-5 space-y-4" aria-label="Issued notice">
   <p class="text-xs text-text-secondary">Issued {new Date(notice.issued_at).toLocaleString()} · Email link expires {new Date(notice.expires_at).toLocaleString()}</p>
   <p class="whitespace-pre-wrap break-words">{notice.text}</p>
   <button type="button" class="btn btn-secondary" disabled={loading || opening || closing || blocked} onclick={refresh}>Refresh access</button>
  </section>
  <section class="card p-5 space-y-4" aria-label="Files accompanying this notice"><h2 class="font-display text-lg">Accompanying documents</h2>
   <ol class="space-y-3">{#each notice.files as file (file.position)}<li class="border border-border-light rounded-md p-4 space-y-2">
    <p class="font-medium">{file.title}</p><p class="text-sm text-text-secondary">{file.pdf_pages} {file.pdf_pages === 1 ? 'page' : 'pages'} · Saved version supplied with this notice</p>
    <div class="flex flex-wrap gap-2"><button type="button" class="btn btn-secondary" disabled={opening || closing || blocked} onclick={() => open(file)}>Read document</button>
     <button type="button" class="btn btn-secondary" disabled={opening || closing || blocked} onclick={() => open(file, true)}>Download PDF</button></div>
   </li>{/each}</ol>
  </section>{/if}
  {#if opening || closing}<p role="status">{closing ? 'Closing the document…' : 'Verifying the selected document…'}</p>{/if}
  {#if notice && selected && bytes}<section class="card p-5 space-y-4" aria-label="Read-only notice document">
   <div class="flex flex-wrap justify-between items-center gap-3"><h2 class="font-display text-lg">{selected.title}</h2><button type="button" class="btn btn-secondary" disabled={closing} onclick={closePDF}>Close document</button></div>
   {#key noticeFileKey(notice, selected)}<VerifiedPDFPages {bytes} expectedPages={selected.pdf_pages} proofKey={noticeFileKey(notice, selected)} ariaLabel={selected.title} onProof={() => {}} onOwner={owner => { previewOwner = owner; }} onRetirement={task => { void task.catch(() => { blocked = true; error = 'Refresh this page before opening another file.'; }); }} />{/key}
  </section>{/if}
 </div>
</main>
