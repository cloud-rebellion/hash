<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { ArrowLeft, ArrowRight, Check, CheckCheck, ChevronLeft, ChevronRight, Eye, FlaskConical, MessageCircle, PenLine, RotateCcw, Send, ShieldCheck } from 'lucide-svelte';
  import { getBranding, getMe } from '$lib/api/client';
  import { staffLocale } from '$lib/staffPreferences';
  import { createRoomPreview, createRoomPreviewAccess, roomPreviewCopy, type PreviewPoint } from '$lib/roomPreview';

  let { controller, accessController }: {
    controller?: ReturnType<typeof createRoomPreview>;
    accessController?: ReturnType<typeof createRoomPreviewAccess>;
  } = $props();
  const room = untrack(() => controller) ?? createRoomPreview();
  const access = untrack(() => accessController) ?? createRoomPreviewAccess({ identity: getMe, branding: getBranding });
  const copy = $derived(roomPreviewCopy($staffLocale));
  const brandName = $derived($access.brand.name || copy.workspace);
  const editable = $derived($room.outcome === 'review');
  const statusText = $derived(copy[({ review: 'reviewStatus', changes: 'changesStatus', declined: 'declinedStatus', signed: 'signedStatus', accepted: 'acceptedStatus' } as const)[$room.outcome]]);
  const notice = $derived($room.outcome === 'review' ? '' : copy[({ changes: 'changesNotice', declined: 'declinedNotice', signed: 'signedNotice', accepted: 'acceptedNotice' } as const)[$room.outcome]]);
  let chat = $state(''), change = $state(''), decline = $state('');
  let pointer = $state<number | null>(null), logoFailed = $state(false);

  onMount(() => { void access.load(); return () => { access.dispose(); }; });
  function reset() { room.reset(); chat = ''; change = ''; decline = ''; pointer = null; }
  function mode(value: 'signature' | 'acceptance') { room.setMode(value); chat = ''; change = ''; decline = ''; pointer = null; }
  function post(event: SubmitEvent) { event.preventDefault(); if (room.message(chat)) chat = ''; }
  function requestChange(event: SubmitEvent) { event.preventDefault(); if (room.requestChanges(change)) change = ''; }
  function declineExample(event: SubmitEvent) { event.preventDefault(); if (room.decline(decline)) decline = ''; }
  function location(event: PointerEvent): PreviewPoint {
    const bounds = event.currentTarget instanceof HTMLElement ? event.currentTarget.getBoundingClientRect() : { left: 0, top: 0, width: 1, height: 1 };
    return { x: (event.clientX - bounds.left) / Math.max(1, bounds.width), y: (event.clientY - bounds.top) / Math.max(1, bounds.height) };
  }
  function drawStart(event: PointerEvent) {
    if (!editable || event.button !== 0) return;
    event.preventDefault();
    const target = event.currentTarget as HTMLButtonElement;
    target.focus();
    try { target.setPointerCapture(event.pointerId); } catch { /* Pointer capture is optional. */ }
    pointer = event.pointerId; room.startStroke(location(event));
  }
  function drawMove(event: PointerEvent) { if (pointer === event.pointerId) room.extendStroke(location(event)); }
  function drawEnd() { pointer = null; }
  function strokePath(points: PreviewPoint[]) { return points.map((p, i) => `${i ? 'L' : 'M'}${(p.x * 1000).toFixed(2)} ${(p.y * 240).toFixed(2)}`).join(' '); }
</script>

<svelte:head><title>{copy.title} · Hash</title></svelte:head>

<div class="preview-page" lang={$staffLocale}>
  <header class="preview-heading">
    <div>
      <a href="/settings/email" class="preview-back"><ArrowLeft size={14} /> {copy.back}</a>
      <p class="page-eyebrow">{copy.eyebrow}</p>
      <h1 class="page-title">{copy.title}</h1>
      <p class="preview-intro">{copy.intro}</p>
    </div>
    {#if $access.status === 'ready'}<button type="button" class="btn btn-secondary" onclick={reset}><RotateCcw size={15} /> {copy.reset}</button>{/if}
  </header>

  <div class="preview-notice" role="note"><FlaskConical size={18} /><p><strong>{copy.demoBadge}.</strong> {copy.demoNotice}</p></div>

  {#if $access.status === 'loading'}
    <p class="preview-access" role="status">{copy.loading}</p>
  {:else if $access.status !== 'ready'}
    <section class="preview-access" aria-label={copy.title}>
      <p role="alert">{$access.status === 'signed-out' ? copy.signedOut : copy.failed}</p>
      {#if $access.status === 'signed-out'}<a class="btn btn-primary" href="/login">{copy.signIn} <ArrowRight size={14} /></a>
      {:else}<button class="btn btn-secondary" type="button" onclick={() => access.load()}>{copy.retry}</button>{/if}
    </section>
  {:else}
    {#if $access.fallback}<p class="preview-fallback" role="status">{copy.brandFallback}</p>{/if}
    <div class="preview-controls">
      <div><span>{copy.mode}</span><div class="preview-segment" aria-label={copy.mode}>
        <button type="button" aria-pressed={$room.mode === 'signature'} onclick={() => mode('signature')}><PenLine size={14} /> {copy.signatureMode}</button>
        <button type="button" aria-pressed={$room.mode === 'acceptance'} onclick={() => mode('acceptance')}><CheckCheck size={14} /> {copy.acceptanceMode}</button>
      </div></div>
      <p>{copy.modeHelp}</p>
    </div>

    <section class="room-shell" aria-label={copy.documentTitle} style={`--room-accent:${$access.brand.primary};--room-accent-foreground:${$access.brand.foreground}`}>
      <header class="room-header">
        <div class="room-brand">
          {#if $access.brand.logo && !logoFailed}<img src={$access.brand.logo} alt={brandName} onerror={() => { logoFailed = true; }} />
          {:else}<span class="room-monogram" aria-hidden="true">{brandName.slice(0, 1).toUpperCase()}</span>{/if}
          <div><strong>{brandName}</strong><span>{copy.documentType}</span></div>
        </div>
        <span class="room-state" data-outcome={$room.outcome}><span aria-hidden="true"></span>{statusText}</span>
      </header>

      <div class="room-grid">
        <section class="room-document" aria-label={copy.documentTitle}>
          <div class="room-document-heading"><div><h2>{copy.documentTitle}</h2><p>{copy.documentSubtitle}</p></div><Eye size={18} /></div>
          {#if notice}<div class="room-outcome" role="status"><Check size={17} /><p>{notice} <span>{copy.endingHelp}</span></p></div>{/if}

          <article class="sample-paper" aria-label={`${copy.page} ${$room.page} ${copy.of} 2`}>
            <div class="paper-brand"><span>{brandName}</span><span>{copy.demoBadge}</span></div>
            {#if $room.page === 1}
              <div class="paper-kicker">{copy.documentType}</div>
              <h3>{copy.overview}</h3>
              <p class="paper-lead">{copy.overviewBody}</p>
              <div class="paper-rule"></div>
              <h4>{copy.scope}</h4>
              <ul class="paper-scope"><li><Check size={14} />{copy.scopeOne}</li><li><Check size={14} />{copy.scopeTwo}</li><li><Check size={14} />{copy.scopeThree}</li></ul>
              <div class="paper-price"><span>{copy.amountLabel}</span><strong>{copy.amount}</strong><small>{copy.amountHelp}</small></div>
            {:else}
              <div class="paper-kicker">{copy.pageTwo}</div>
              <h3>{copy.working}</h3><p class="paper-lead">{copy.workingBody}</p>
              <div class="paper-rule"></div><h4>{copy.delivery}</h4><p>{copy.deliveryBody}</p>
              <div class="paper-signature" data-complete={$room.outcome === 'signed' || $room.outcome === 'accepted'}>
                <span>{$room.mode === 'signature' ? copy.signatureArea : copy.acceptedArea}</span>
                {#if $room.outcome === 'signed'}
                  {#if $room.signatureMode === 'type'}<strong class="typed-signature">{$room.signatureName.trim()}</strong>
                  {:else}<svg viewBox="0 0 1000 240" role="img" aria-label={copy.signatureArea}>{#each $room.strokes as stroke}<path d={strokePath(stroke)} />{/each}</svg>{/if}
                  <small>{copy.localOnly}</small>
                {:else if $room.outcome === 'accepted'}<div class="paper-accepted"><CheckCheck size={22} /><p>{copy.acceptedText}</p></div>
                {:else}<p>{$room.mode === 'signature' ? copy.signatureEmpty : copy.acceptanceEmpty}</p>{/if}
              </div>
            {/if}
            <footer class="paper-footer"><span>{copy.company} · {copy.demoBadge}</span><span>{$room.page} / 2</span></footer>
          </article>

          <nav class="page-carousel" aria-label={copy.pages}>
            <button type="button" class="page-arrow" aria-label={copy.previous} disabled={$room.page === 1} onclick={() => room.setPage($room.page - 1)}><ChevronLeft size={18} /></button>
            {#each [1, 2] as page}
              <button type="button" class="page-choice" aria-pressed={$room.page === page} aria-label={`${copy.page} ${page}: ${page === 1 ? copy.pageOne : copy.pageTwo}`} onclick={() => room.setPage(page)}>
                <span class="page-thumbnail" aria-hidden="true"><span class="thumbnail-brand"></span><span class="thumbnail-title"></span><span></span><span></span><span></span><span class:thumbnail-price={page === 1} class:thumbnail-signature={page === 2}></span></span>
                <span>{page === 1 ? copy.pageOne : copy.pageTwo}</span>
              </button>
            {/each}
            <button type="button" class="page-arrow" aria-label={copy.next} disabled={$room.page === 2} onclick={() => room.setPage($room.page + 1)}><ChevronRight size={18} /></button>
          </nav>
        </section>

        <aside class="room-sidebar">
          <section class="example-person"><span class="person-avatar" aria-hidden="true">AE</span><div><span>{copy.recipientLabel}</span><strong>{copy.recipient}</strong><p>{copy.company} · {copy.email}</p></div></section>
          <section class="room-conversation">
            <div class="conversation-switch" aria-label={copy.discussion}>
              <button type="button" aria-pressed={$room.panel === 'discussion'} onclick={() => room.setPanel('discussion')}><MessageCircle size={14} /> {copy.discussion}{#if $room.messages.length}<span>{$room.messages.length}</span>{/if}</button>
              <button type="button" aria-pressed={$room.panel === 'activity'} onclick={() => room.setPanel('activity')}>{copy.activity}</button>
            </div>
            {#if $room.panel === 'discussion'}
              <div class="conversation-messages" aria-live="polite" aria-label={copy.discussion}>
                {#if !$room.messages.length}<div class="conversation-empty"><MessageCircle size={24} /><h3>{copy.discussionEmpty}</h3><p>{copy.discussionHelp}</p></div>{/if}
                {#each $room.messages as message (message.id)}<article class="test-message"><div><strong>{copy.recipient}</strong><span>{message.kind === 'changes' ? copy.changeTitle : copy.localOnly}</span></div><p>{message.text}</p></article>{/each}
              </div>
              <form class="message-form" onsubmit={post}>
                <label for="room-preview-message">{copy.messageLabel}</label>
                <textarea id="room-preview-message" maxlength="1000" rows="2" bind:value={chat} placeholder={copy.messagePlaceholder}></textarea>
                <button type="submit" class="room-primary"><Send size={14} /> {copy.sendMessage}</button>
              </form>
            {:else}
              <div class="activity-panel"><p>{copy.activityHelp}</p><ol aria-live="polite">{#each $room.events as event}<li><span aria-hidden="true"></span>{copy[({ opened: 'openedEvent', message: 'messageEvent', changes: 'changesEvent', declined: 'declinedEvent', signed: 'signedEvent', accepted: 'acceptedEvent' } as const)[event]]}</li>{/each}</ol>{#if $room.declineReason}<blockquote>{$room.declineReason}</blockquote>{/if}</div>
            {/if}
          </section>

          {#if $room.problem}<p class="room-problem" role="alert">{copy[$room.problem]}</p>{/if}
          {#if editable}
            <section class="decision-panel" aria-label={copy.decision}>
              <h3>{copy.decision}</h3><p>{copy.decisionHelp}</p>
              {#if $room.mode === 'signature'}
                <div class="signature-switch" aria-label={copy.signatureMode}>
                  <button type="button" aria-pressed={$room.signatureMode === 'type'} onclick={() => room.setSignatureMode('type')}>{copy.type}</button>
                  <button type="button" aria-pressed={$room.signatureMode === 'draw'} onclick={() => room.setSignatureMode('draw')}>{copy.draw}</button>
                </div>
                {#if $room.signatureMode === 'type'}
                  <label for="room-preview-signature">{copy.signatureLabel}</label><input id="room-preview-signature" type="text" value={$room.signatureName} maxlength="100" placeholder={copy.signaturePlaceholder} autocomplete="off" oninput={(event) => room.setSignatureName(event.currentTarget.value)} />
                {:else}
                  <button type="button" class="draw-pad" aria-label={copy.drawLabel} onpointerdown={drawStart} onpointermove={drawMove} onpointerup={drawEnd} onpointercancel={drawEnd} onlostpointercapture={drawEnd}>
                    <svg viewBox="0 0 1000 240" aria-hidden="true">{#each $room.strokes as stroke}<path d={strokePath(stroke)} />{/each}</svg>
                    {#if !$room.strokes.length}<span>{copy.drawHelp}</span>{/if}
                  </button>
                {/if}
                <button class="clear-signature" type="button" onclick={() => room.clearSignature()}>{copy.clear}</button>
              {/if}
              <label class="preview-confirm"><input type="checkbox" checked={$room.confirmed} onchange={(event) => room.setConfirmed(event.currentTarget.checked)} /><span>{$room.mode === 'signature' ? copy.confirmSignature : copy.confirmAcceptance}</span></label>
              <button type="button" class="room-primary decision-action" onclick={() => room.finish()}><CheckCheck size={16} /> {$room.mode === 'signature' ? copy.sign : copy.accept}</button>
              <div class="decision-alternatives">
                <details><summary>{copy.changeTitle}</summary><form onsubmit={requestChange}><label for="room-preview-change">{copy.changeLabel}</label><textarea id="room-preview-change" rows="3" maxlength="1000" bind:value={change} placeholder={copy.changePlaceholder}></textarea><button type="submit" class="btn btn-secondary">{copy.changeAction}</button></form></details>
                <details><summary>{copy.declineTitle}</summary><form onsubmit={declineExample}><label for="room-preview-decline">{copy.declineLabel}</label><textarea id="room-preview-decline" rows="2" maxlength="1000" bind:value={decline} placeholder={copy.declinePlaceholder}></textarea><button type="submit" class="btn btn-secondary">{copy.declineAction}</button></form></details>
              </div>
            </section>
          {/if}
          <p class="room-footnote"><ShieldCheck size={14} />{copy.localOnly}</p>
        </aside>
      </div>
    </section>
  {/if}
</div>

<style>
  .preview-page {
    max-width:1240px;
    margin:0 auto;
    padding:32px 24px 56px;
  }
  .preview-heading {
    display:flex;
    align-items:flex-end;
    justify-content:space-between;
    gap:24px;
    margin-bottom:24px;
  }
  .preview-back {
    display:inline-flex;
    align-items:center;
    gap:6px;
    font-size:12px;
    color:var(--t-text-secondary);
    margin-bottom:24px;
  }
  .preview-heading .page-eyebrow {
    margin-bottom:10px;
  }
  .preview-intro {
    font-size:14px;
    color:var(--t-text-secondary);
    margin-top:12px;
  }
  .preview-notice {
    display:flex;
    align-items:flex-start;
    gap:12px;
    padding:14px 18px;
    border:1px solid var(--t-border);
    border-radius:12px;
    background:var(--t-bg-elevated);
    font-size:12px;
    line-height:1.7;
    color:var(--t-text-secondary);
  }
  .preview-notice :global(svg) {
    flex-shrink:0;
    margin-top:3px;
  }
  .preview-access {
    padding:40px 20px;
    text-align:center;
    color:var(--t-text-secondary);
    display:grid;
    justify-items:center;
    gap:18px;
  }
  .preview-fallback {
    font-size:12px;
    color:var(--t-text-secondary);
    margin-top:12px;
  }
  .preview-controls {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:20px;
    margin:24px 0 16px;
  }
  .preview-controls>div {
    display:flex;
    align-items:center;
    gap:12px;
  }
  .preview-controls>div>span,.preview-controls>p {
    font-size:11px;
    color:var(--t-text-secondary);
  }
  .preview-segment,.signature-switch {
    display:flex;
    gap:3px;
    padding:3px;
    background:var(--t-bg-elevated);
    border:1px solid var(--t-border);
    border-radius:9px;
  }
  .preview-segment button,.signature-switch button {
    display:flex;
    align-items:center;
    justify-content:center;
    gap:6px;
    border-radius:6px;
    padding:7px 12px;
    color:var(--t-text-secondary);
    font-size:12px;
  }
  .preview-segment button[aria-pressed=true],.signature-switch button[aria-pressed=true] {
    background:var(--t-bg-surface);
    color:var(--t-text-primary);
    box-shadow:0 1px 3px #00000012;
  }
  .room-shell {
    border:1px solid var(--t-border);
    border-radius:18px;
    background:var(--t-bg-surface);
    overflow:hidden;
    box-shadow:0 12px 40px #00000005;
  }
  .room-header {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:16px;
    padding:22px 28px;
    border-bottom:1px solid var(--t-border);
  }
  .room-brand {
    display:flex;
    align-items:center;
    gap:12px;
    min-width:0;
  }
  .room-brand img {
    max-width:150px;
    max-height:40px;
    object-fit:contain;
  }
  .room-monogram {
    display:grid;
    place-items:center;
    width:40px;
    height:40px;
    border-radius:11px;
    background:var(--room-accent);
    color:var(--room-accent-foreground);
    font-weight:600;
    font-size:19px;
  }
  .room-brand strong {
    display:block;
    font-size:14px;
    overflow-wrap:anywhere;
  }
  .room-brand div>span {
    display:block;
    margin-top:3px;
    font-size:10px;
    color:var(--t-text-secondary);
  }
  .room-state {
    display:inline-flex;
    align-items:center;
    gap:7px;
    flex-shrink:0;
    padding:7px 10px;
    border:1px solid var(--t-border);
    border-radius:999px;
    font-size:10px;
    color:var(--t-text-secondary);
  }
  .room-state>span {
    width:5px;
    height:5px;
    border-radius:50%;
    background:var(--t-text-secondary);
  }
  .room-state[data-outcome=signed],.room-state[data-outcome=accepted] {
    color:var(--t-success);
  }
  .room-state[data-outcome=changes] {
    color:var(--t-warning);
  }
  .room-state[data-outcome=declined] {
    color:var(--t-danger);
  }
  .room-grid {
    display:grid;
    grid-template-columns:minmax(0,1fr) 340px;
  }
  .room-document {
    padding:24px 30px;
    background:var(--t-bg-elevated);
    min-width:0;
  }
  .room-document-heading {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:16px;
    margin-bottom:22px;
  }
  .room-document-heading h2 {
    font-size:14px;
    font-weight:500;
  }
  .room-document-heading p {
    font-size:11px;
    color:var(--t-text-secondary);
    margin-top:5px;
  }
  .room-document-heading :global(svg) {
    color:var(--t-text-muted);
    flex-shrink:0;
  }
  .room-outcome {
    display:flex;
    gap:10px;
    background:var(--t-bg-surface);
    border:1px solid var(--t-border);
    border-radius:10px;
    padding:12px;
    margin-bottom:16px;
    font-size:12px;
    line-height:1.6;
  }
  .room-outcome :global(svg) {
    flex-shrink:0;
    margin-top:2px;
    color:var(--t-success);
  }
  .room-outcome span {
    display:block;
    color:var(--t-text-secondary);
    margin-top:3px;
  }
  .sample-paper {
    position:relative;
    display:flex;
    flex-direction:column;
    min-height:640px;
    max-width:600px;
    margin:auto;
    padding:36px 40px 28px;
    background:#fff;
    color:#20242c;
    border:1px solid #e5e7eb;
    border-radius:3px;
    box-shadow:0 8px 24px #00000008;
  }
  .paper-brand {
    display:flex;
    justify-content:space-between;
    gap:16px;
    align-items:center;
    padding-bottom:26px;
    border-bottom:2px solid var(--room-accent);
    font-size:10px;
    overflow-wrap:anywhere;
  }
  .paper-brand span:first-child {
    font-weight:700;
  }
  .paper-brand span:last-child {
    font-size:8px;
    letter-spacing:.1em;
    text-transform:uppercase;
    color:#626875;
    flex-shrink:0;
  }
  .paper-kicker {
    font-size:9px;
    letter-spacing:.14em;
    text-transform:uppercase;
    color:#626875;
    margin-top:38px;
  }
  .sample-paper h3 {
    font-family:var(--font-display);
    font-size:clamp(23px,2.4vw,32px);
    line-height:1.2;
    font-weight:500;
    letter-spacing:-.025em;
    max-width:350px;
    margin-top:12px;
  }
  .paper-lead {
    margin-top:18px!important;
    line-height:1.8!important;
  }
  .sample-paper p {
    font-size:11px;
    color:#505767;
    line-height:1.8;
    margin-top:12px;
  }
  .paper-rule {
    height:1px;
    background:#e5e7eb;
    margin:26px 0 24px;
  }
  .sample-paper h4 {
    font-size:12px;
    font-weight:600;
  }
  .paper-scope {
    display:grid;
    gap:14px;
    font-size:11px;
    margin-top:18px;
    color:#505767;
  }
  .paper-scope li {
    display:flex;
    gap:10px;
    align-items:center;
  }
  .paper-scope :global(svg) {
    color:var(--room-accent);
    flex-shrink:0;
  }
  .paper-price {
    border-left:3px solid var(--room-accent);
    padding:14px 0 14px 18px;
    margin-top:32px;
    display:grid;
    gap:5px;
  }
  .paper-price>span {
    font-size:10px;
    color:#626875;
  }
  .paper-price>strong {
    font-size:30px;
    letter-spacing:-.03em;
    font-weight:500;
  }
  .paper-price>small {
    font-size:9px;
    color:#626875;
  }
  .paper-footer {
    margin-top:auto;
    padding-top:40px;
    display:flex;
    justify-content:space-between;
    gap:12px;
    font-size:8px;
    color:#626875;
  }
  .paper-signature {
    border:1px dashed #b9bfcb;
    border-radius:8px;
    padding:18px;
    margin-top:30px;
    min-height:116px;
    display:flex;
    flex-direction:column;
    justify-content:center;
  }
  .paper-signature>span {
    font-size:9px;
    color:#626875;
    text-transform:uppercase;
    letter-spacing:.08em;
  }
  .paper-signature small {
    font-size:8px;
    color:#626875;
    margin-top:10px;
  }
  .paper-signature[data-complete=true] {
    border-style:solid;
    border-color:var(--room-accent);
  }
  .typed-signature {
    font-family:Georgia,serif;
    font-size:28px;
    font-style:italic;
    font-weight:400;
    overflow-wrap:anywhere;
    margin-top:8px;
  }
  .paper-signature svg {
    height:70px;
    width:100%;
    color:#20242c;
  }
  .paper-signature path,.draw-pad path {
    fill:none;
    stroke:currentColor;
    stroke-width:4;
    stroke-linecap:round;
    stroke-linejoin:round;
  }
  .paper-accepted {
    display:flex;
    align-items:center;
    gap:10px;
    margin-top:10px;
  }
  .paper-accepted p {
    margin:0;
  }
  .page-carousel {
    display:flex;
    gap:14px;
    align-items:center;
    justify-content:center;
    margin-top:22px;
  }
  .page-choice {
    display:grid;
    justify-items:center;
    gap:7px;
    font-size:10px;
    color:var(--t-text-secondary);
  }
  .page-thumbnail {
    display:flex;
    flex-direction:column;
    gap:5px;
    padding:10px 8px;
    width:58px;
    height:78px;
    border:1px solid var(--t-border);
    border-radius:4px;
    background:#fff;
    outline:2px solid transparent;
    outline-offset:3px;
  }
  .page-choice[aria-pressed=true] .page-thumbnail {
    outline-color:var(--room-accent);
  }
  .page-choice[aria-pressed=true] {
    color:var(--t-text-primary);
    font-weight:600;
  }
  .page-thumbnail>span {
    height:2px;
    width:100%;
    background:#e5e7eb;
  }
  .page-thumbnail>.thumbnail-brand {
    width:20px;
    background:var(--room-accent);
    height:3px;
    margin-bottom:6px;
  }
  .page-thumbnail>.thumbnail-title {
    width:85%;
    height:4px;
    background:#737985;
    margin-bottom:4px;
  }
  .page-thumbnail>.thumbnail-price {
    width:55%;
    height:8px;
    margin-top:4px;
    background:var(--room-accent);
    opacity:.65;
  }
  .page-thumbnail>.thumbnail-signature {
    height:14px;
    border:1px dashed #c2c7cf;
    background:transparent;
    margin-top:4px;
  }
  .page-arrow {
    padding:8px;
    border-radius:6px;
    color:var(--t-text-secondary);
  }
  .page-arrow:disabled {
    opacity:.3;
    cursor:not-allowed;
  }
  .room-sidebar {
    border-left:1px solid var(--t-border);
    min-width:0;
  }
  .example-person {
    display:flex;
    align-items:center;
    gap:10px;
    padding:20px;
    border-bottom:1px solid var(--t-border);
  }
  .person-avatar {
    display:grid;
    place-items:center;
    width:32px;
    height:32px;
    border:1px solid var(--t-border);
    border-radius:50%;
    color:var(--t-text-secondary);
    font-size:10px;
    flex-shrink:0;
  }
  .example-person div {
    min-width:0;
  }
  .example-person div>span {
    display:block;
    font-size:9px;
    color:var(--t-text-secondary);
  }
  .example-person strong {
    font-size:12px;
    font-weight:500;
  }
  .example-person p {
    font-size:10px;
    color:var(--t-text-secondary);
    overflow-wrap:anywhere;
    margin-top:2px;
  }
  .room-conversation {
    border-bottom:1px solid var(--t-border);
  }
  .conversation-switch {
    display:flex;
    gap:16px;
    padding:0 20px;
    border-bottom:1px solid var(--t-border);
  }
  .conversation-switch button {
    display:flex;
    align-items:center;
    gap:6px;
    border-bottom:2px solid transparent;
    padding:15px 0 12px;
    font-size:11px;
    color:var(--t-text-secondary);
  }
  .conversation-switch button[aria-pressed=true] {
    border-color:var(--room-accent);
    color:var(--t-text-primary);
  }
  .conversation-switch button>span {
    font-size:9px;
    padding:1px 5px;
    border-radius:999px;
    background:var(--t-bg-hover);
  }
  .conversation-messages {
    padding:18px;
    display:grid;
    gap:12px;
    max-height:300px;
    overflow:auto;
    min-height:160px;
  }
  .conversation-empty {
    display:grid;
    justify-items:center;
    align-content:center;
    text-align:center;
    padding:16px 0;
    gap:8px;
    color:var(--t-text-secondary);
  }
  .conversation-empty :global(svg) {
    color:var(--t-text-muted);
  }
  .conversation-empty h3 {
    font-size:12px;
    font-weight:500;
    color:var(--t-text-primary);
  }
  .conversation-empty p {
    font-size:11px;
    line-height:1.7;
    max-width:240px;
  }
  .test-message {
    padding:12px;
    background:var(--t-bg-elevated);
    border:1px solid var(--t-border);
    border-radius:10px;
    font-size:12px;
    overflow-wrap:anywhere;
  }
  .test-message>div {
    display:grid;
    gap:3px;
  }
  .test-message strong {
    font-size:10px;
    font-weight:500;
  }
  .test-message span {
    font-size:9px;
    color:var(--t-text-secondary);
  }
  .test-message p {
    margin-top:9px;
    white-space:pre-wrap;
    line-height:1.6;
  }
  .message-form {
    padding:0 18px 18px;
    display:grid;
    gap:8px;
  }
  .message-form label,.decision-panel label:not(.preview-confirm),.decision-alternatives label {
    display:block;
    font-size:10px;
    font-weight:500;
    color:var(--t-text-secondary);
  }
  textarea,input[type=text] {
    border:1px solid var(--t-border);
    border-radius:7px;
    background:var(--t-bg-elevated);
    color:var(--t-text-primary);
    padding:10px 11px;
    font-size:12px;
    width:100%;
    resize:vertical;
  }
  textarea::placeholder,input::placeholder {
    color:var(--t-text-muted);
  }
  .room-primary {
    display:flex;
    justify-content:center;
    align-items:center;
    gap:7px;
    width:100%;
    padding:10px 12px;
    background:var(--room-accent);
    color:var(--room-accent-foreground);
    border:1px solid transparent;
    border-radius:8px;
    font-size:11px;
    font-weight:500;
  }
  .room-primary:hover {
    filter:brightness(.94);
  }
  .activity-panel {
    padding:18px;
    font-size:11px;
  }
  .activity-panel>p {
    color:var(--t-text-secondary);
    line-height:1.6;
  }
  .activity-panel ol {
    display:grid;
    gap:18px;
    margin-top:22px;
    padding:0 0 5px 3px;
  }
  .activity-panel li {
    display:flex;
    align-items:center;
    gap:12px;
    font-size:11px;
  }
  .activity-panel li>span {
    width:6px;
    height:6px;
    border-radius:50%;
    background:var(--room-accent);
    flex-shrink:0;
  }
  .activity-panel blockquote {
    margin-top:18px;
    border-left:2px solid var(--t-border);
    padding-left:12px;
    white-space:pre-wrap;
    overflow-wrap:anywhere;
    color:var(--t-text-secondary);
  }
  .room-problem {
    font-size:11px;
    padding:12px 20px;
    color:var(--t-danger);
    line-height:1.6;
  }
  .decision-panel {
    padding:20px;
  }
  .decision-panel>h3 {
    font-size:13px;
    font-weight:500;
  }
  .decision-panel>p {
    font-size:11px;
    line-height:1.6;
    color:var(--t-text-secondary);
    margin-top:5px;
  }
  .signature-switch {
    margin:18px 0 12px;
  }
  .signature-switch button {
    flex:1;
    font-size:10px;
    padding:7px;
  }
  .decision-panel label:not(.preview-confirm) {
    margin-bottom:6px;
  }
  .clear-signature {
    display:block;
    font-size:10px;
    color:var(--t-text-secondary);
    text-decoration:underline;
    text-underline-offset:3px;
    margin:8px 0 16px;
  }
  .draw-pad {
    position:relative;
    display:block;
    width:100%;
    height:96px;
    touch-action:none;
    border:1px dashed var(--t-border);
    border-radius:8px;
    background:var(--t-bg-elevated);
  }
  .draw-pad>svg {
    width:100%;
    height:100%;
    color:var(--t-text-primary);
  }
  .draw-pad>span {
    position:absolute;
    inset:0;
    display:grid;
    place-items:center;
    padding:12px;
    color:var(--t-text-secondary);
    font-size:10px;
    pointer-events:none;
  }
  .preview-confirm {
    display:flex;
    align-items:flex-start;
    gap:9px;
    font-size:10px;
    line-height:1.6;
    color:var(--t-text-secondary);
    margin:18px 0 12px;
  }
  .preview-confirm>input {
    margin-top:3px;
    accent-color:var(--room-accent);
    flex-shrink:0;
  }
  .decision-action {
    font-size:12px;
  }
  .decision-alternatives {
    margin-top:14px;
    border-top:1px solid var(--t-border);
  }
  .decision-alternatives details {
    border-bottom:1px solid var(--t-border);
  }
  .decision-alternatives summary {
    cursor:pointer;
    padding:13px 0;
    font-size:11px;
    color:var(--t-text-secondary);
  }
  .decision-alternatives form {
    display:grid;
    gap:9px;
    padding:0 0 14px;
  }
  .decision-alternatives .btn {
    font-size:10px;
  }
  .room-footnote {
    display:flex;
    justify-content:center;
    align-items:center;
    gap:6px;
    padding:16px;
    font-size:9px;
    color:var(--t-text-secondary);
  }
  button:focus-visible,a:focus-visible,summary:focus-visible,input:focus-visible,textarea:focus-visible {
    outline:2px solid var(--t-info);
    outline-offset:3px;
  }
  button {
    cursor:pointer;
  }
  @media(max-width:1000px) {
    .room-grid {
      grid-template-columns:minmax(0,1fr) 310px;
    }
    .room-document {
      padding:22px;
    }
    .sample-paper {
      padding:28px;
      min-height:610px;
    }
    .preview-controls {
      align-items:flex-start;
    }
    .preview-controls>p {
      max-width:180px;
      text-align:right;
      line-height:1.6;
    }
  }
  @media(max-width:760px) {
    .preview-page {
      padding:24px 16px 40px;
    }
    .preview-heading {
      align-items:flex-start;
      flex-direction:column;
      gap:18px;
    }
    .preview-heading .page-title {
      font-size:30px;
    }
    .preview-controls {
      flex-wrap:wrap;
      gap:8px;
    }
    .preview-controls>p {
      max-width:none;
      text-align:left;
    }
    .room-header {
      padding:18px;
      flex-wrap:wrap;
    }
    .room-grid {
      grid-template-columns:1fr;
    }
    .room-sidebar {
      border-left:0;
      border-top:1px solid var(--t-border);
    }
    .room-document {
      padding:18px;
    }
    .sample-paper {
      min-height:600px;
      padding:28px;
    }
    .sample-paper h3 {
      font-size:30px;
    }
    .room-state {
      font-size:10px;
    }
    .conversation-messages {
      max-height:260px;
    }
    .decision-panel {
      padding:22px;
    }
    .room-footnote {
      padding-top:0;
    }
  }
  @media(prefers-reduced-motion:reduce) {
    * {
      scroll-behavior:auto;
    }
  }
</style>
