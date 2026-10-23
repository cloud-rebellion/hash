<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { closeSupersession, createSupersession, getSupersessionContext, inspectSupersession } from '$lib/api/supersession';
  import { readSupersessionMarker, saveSupersessionMarker, supersessionCommand, type SupersessionActor, type SupersessionContext, type SupersessionMarker, type SupersessionOutcome } from '$lib/supersession';
  let { documentID, actor, blocked, onStateChange }: { documentID: string; actor: SupersessionActor; blocked: boolean; onStateChange: (state: { busy: boolean; pending: boolean }) => void } = $props();
  let context = $state<SupersessionContext | null>(null), marker = $state<SupersessionMarker | null>(null);
  let invalid = $state(false), busy = $state(false), confirmed = $state(false), closeConfirmed = $state(false);
  let name = $state('Linked signing draft'), values = $state<Record<string, string>>({}), sections = $state<Record<string, string>>({});
  let message = $state(''), outcome = $state<SupersessionOutcome | null>(null);
  let mounted = false, active: AbortController | null = null;
  const report = () => onStateChange({ busy, pending: invalid || !!marker });
  onMount(() => { mounted = true; const saved = readSupersessionMarker(sessionStorage); marker = saved.marker; invalid = saved.invalid; report(); });
  onDestroy(() => { mounted = false; active?.abort(); });
  const owned = () => marker && marker.org_id === actor.org_id && marker.user_id === actor.user_id && marker.prior_document_id === documentID;
  function begin() { active?.abort(); const c = new AbortController(); active = c; busy = true; message = ''; report(); return c; }
  function finish(c: AbortController) { if (mounted && active === c) { busy = false; report(); } }
  async function navigate(document: string, c: AbortController) { if (!mounted || c.signal.aborted) return; await goto(`/documents/${document}`); saveSupersessionMarker(sessionStorage, null); }
  async function prepare() {
    if (blocked || busy || marker || invalid) return; const c = begin();
    try { const next = await getSupersessionContext(documentID, actor, c.signal); if (!mounted || c.signal.aborted) return; context = next; confirmed = false;
      if (next.state === 'ready') { values = { ...next.template.defaults }; sections = Object.fromEntries(next.template.sections.map(s => [s.name, s.default_text])); }
    } catch (error) { if (mounted && !c.signal.aborted) message = error instanceof Error ? error.message : 'The linked draft context is unavailable.'; } finally { finish(c); }
  }
  async function create() {
    if (blocked || busy || marker || invalid || !confirmed || context?.state !== 'ready') return;
    const ready = context, requestID = crypto.randomUUID();
    try { supersessionCommand(ready, name, values, sections, requestID); } catch (error) { message = error instanceof Error ? error.message : 'Complete the current template fields.'; return; }
    const pending: SupersessionMarker = { schema_version: 1, org_id: actor.org_id, user_id: actor.user_id, prior_document_id: documentID, prior_execution_id: ready.prior.execution_id, template_id: ready.template.id, request_id: requestID };
    try { saveSupersessionMarker(sessionStorage, pending); } catch { message = 'The original request could not be retained. No creation was sent.'; return; }
    marker = pending; const c = begin();
    try { const result = await createSupersession(ready, name, values, sections, pending, c.signal); if (!mounted || c.signal.aborted) return; outcome = result; await navigate(result.document_id, c); }
    catch { if (mounted && !c.signal.aborted) message = 'Keep this original request. Inspect its outcome before preparing another linked draft.'; } finally { finish(c); }
  }
  async function recover(close = false) {
    if (blocked || busy || !owned() || !marker || (close && !closeConfirmed)) return; const original = marker, c = begin();
    try { const result = close ? await closeSupersession(original, c.signal) : await inspectSupersession(original, c.signal); if (!mounted || c.signal.aborted) return; outcome = result;
      if (result.state === 'committed') await navigate(result.document_id, c);
      else message = result.state === 'closed' ? 'The original request was closed without a linked draft.' : 'The original outcome remains unconfirmed. This does not permit a new request.';
    } catch { if (mounted && !c.signal.aborted) message = 'The original outcome is unavailable. Retain this request and use the same original member session.'; } finally { finish(c); }
  }
  function acknowledgeClosed() { if (busy || outcome?.state !== 'closed') return; saveSupersessionMarker(sessionStorage, null); marker = null; outcome = null; context = null; confirmed = false; closeConfirmed = false; message = ''; report(); }
</script>

<section class="card p-4 my-4 space-y-3" aria-label="Create a linked signing draft">
  <h3 class="font-medium">Create a linked signing draft</h3>
  <p class="text-sm">Keep this agreement and its evidence intact. A new draft uses the current approved template and new party and signature fields. Review its PDF and choose signing separately. Ordinary amendment notices remain available in Later amendments.</p>
  {#if invalid}
    <p role="alert">The saved original request cannot be verified. Restore the original session and inspect it before creating another draft.</p>
  {:else if marker}
    <p class="text-sm">Original request: {marker.request_id}</p>
    {#if !owned()}<p role="alert">Return to the original member and <a href={`/documents/${marker.prior_document_id}`}>original agreement</a> to inspect this request.</p>
    {:else}
      <button class="btn btn-secondary" disabled={busy || blocked} onclick={() => recover()}>Inspect original request</button>
      {#if outcome?.state === 'closed'}<button class="btn btn-secondary" disabled={busy} onclick={acknowledgeClosed}>Acknowledge closure</button>
      {:else}<label class="flex gap-2 text-sm"><input type="checkbox" bind:checked={closeConfirmed} disabled={busy || blocked} />Close this exact request if it has not committed.</label><button class="btn btn-secondary" disabled={busy || blocked || !closeConfirmed} onclick={() => recover(true)}>Close original request</button>{/if}
    {/if}
  {:else if context?.state === 'linked'}
    <a class="btn btn-secondary" href={`/documents/${context.document_id}`}>Open existing linked draft</a>
  {:else if context?.state === 'ready'}
    {#if !context.creation_available}<p role="note">New supersession is disabled in this service. Existing evidence and request recovery remain available.</p>
    {:else}<fieldset class="space-y-3" disabled={busy || blocked}>
      <p class="text-sm">Current approved template revision {context.template.version}. These are its defaults, not copied values or signatures from the old agreement.</p>
      <label class="block text-sm">Draft name<input class="input w-full" bind:value={name} maxlength="200" /></label>
      {#each context.template.values as field (field.name)}<label class="block text-sm">{field.name.replaceAll('_', ' ')}{field.required ? ' *' : ''}<input class="input w-full" value={values[field.name] ?? ''} maxlength={field.max_chars || 8192} oninput={(event) => { values = { ...values, [field.name]: event.currentTarget.value }; confirmed = false; }} /></label>{/each}
      {#each context.template.sections as field (field.name)}<label class="block text-sm">{field.name.replaceAll('_', ' ')}<textarea class="input w-full" value={sections[field.name] ?? field.default_text} maxlength={field.max_chars || 32768} oninput={(event) => { sections = { ...sections, [field.name]: event.currentTarget.value }; confirmed = false; }}></textarea></label>{/each}
      <label class="flex gap-2 text-sm"><input type="checkbox" bind:checked={confirmed} />Create a separate draft for review. This does not sign or send it.</label>
      <button class="btn btn-primary" disabled={!confirmed} onclick={create}>{busy ? 'Creating…' : 'Create linked draft and review'}</button>
    </fieldset>{/if}
  {:else}<button class="btn btn-secondary" disabled={busy || blocked} onclick={prepare}>{busy ? 'Loading…' : 'Prepare linked draft'}</button>{/if}
  {#if message}<p role="status" class="text-sm">{message}</p>{/if}
</section>
