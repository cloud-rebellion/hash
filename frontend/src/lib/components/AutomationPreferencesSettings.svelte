<script lang="ts">
  import { onMount } from 'svelte';
  import { Bell, RotateCcw, Save } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { createAutomationPreferencesForm } from '$lib/automationSettings';
  import { getAutomationPreferences, putAutomationPreferences } from '$lib/api/automationSettings';
  const form = createAutomationPreferencesForm({ load: getAutomationPreferences, save: putAutomationPreferences });
  const locked = $derived(!!$form.busy || !$form.authorized || !$form.saved || $form.unconfirmed);
  onMount(() => { void form.load(); return form.dispose; });
</script>

<section class="card overflow-hidden" aria-labelledby="sender-notices-heading">
  <header class="border-b border-border bg-bg-elevated px-5 py-4">
    <p class="page-eyebrow">{$ui('My notifications')}</p>
    <h2 id="sender-notices-heading" class="mt-2 font-display text-lg flex items-center gap-2"><Bell class="size-4" />{$ui('Document activity')}</h2>
    <p class="mt-2 text-sm text-text-secondary">{$ui('Email me about documents I send. These preferences affect future activity only.')}</p>
  </header>
  <form class="p-5 space-y-5" onsubmit={(event) => { event.preventDefault(); void form.save(); }}>
    {#if $form.busy === 'loading'}<p role="status" class="text-sm text-text-secondary">{$ui('Loading automation settings…')}</p>{/if}
    {#if $form.error}<p role="alert" class="text-sm text-danger">{$ui($form.error)}</p>{/if}
    {#if $form.notice}<p role="status" class="text-sm text-text-secondary">{$ui($form.notice)}</p>{/if}
    <label class="flex gap-3 items-start">
      <input type="checkbox" class="mt-1" checked={$form.draft.notify_viewed} disabled={locked} onchange={(event) => form.edit({ ...$form.draft, notify_viewed: event.currentTarget.checked })} />
      <span><span class="block text-sm font-medium">{$ui('A recipient views my document')}</span><span class="mt-1 block text-xs leading-relaxed text-text-secondary">{$ui('One notice for each recipient’s first document view in that send. This does not track email opens.')}</span></span>
    </label>
    <label class="flex gap-3 items-start">
      <input type="checkbox" class="mt-1" checked={$form.draft.notify_signed} disabled={locked} onchange={(event) => form.edit({ ...$form.draft, notify_signed: event.currentTarget.checked })} />
      <span><span class="block text-sm font-medium">{$ui('A recipient signs my document')}</span><span class="mt-1 block text-xs leading-relaxed text-text-secondary">{$ui('A notice for each actual signature. Acknowledgements are separate and do not trigger this notice.')}</span></span>
    </label>
    <p class="rounded-lg border border-border bg-bg-elevated p-3 text-xs leading-relaxed text-text-secondary">{$ui('Existing messages about comments, requested changes, declines and final completion keep their current behavior. Turning these notices off does not retract emails already queued.')}</p>
    <div class="flex flex-wrap items-center gap-2 border-t border-border pt-4">
      <button type="submit" class="btn btn-primary" disabled={locked || !$form.dirty}><Save class="size-4" />{$ui($form.busy === 'saving' ? 'Saving…' : 'Save preferences')}</button>
      <button type="button" class="btn btn-secondary" disabled={!!$form.busy || !$form.saved || !$form.dirty || $form.unconfirmed} onclick={() => form.cancel()}>{$ui('Cancel')}</button>
      <button type="button" class="btn btn-secondary" disabled={!!$form.busy} onclick={() => { void form.load(); }}><RotateCcw class="size-4" />{$ui('Reload saved settings')}</button>
    </div>
  </form>
</section>
