<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { Clock3, RotateCcw, Save } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { createReminderPolicyForm, reminderSelection, validReminderSelection, type ReminderMode, type ReminderSnapshot } from '$lib/automationSettings';
  import { getReminderPolicy, putReminderPolicy } from '$lib/api/automationSettings';
  let { scope, id, documentUpdatedAt, readonly = false, externalBlocked = false, onStateChange, onSaved } : {
    scope: 'template' | 'document'; id: string; documentUpdatedAt?: string; readonly?: boolean; externalBlocked?: boolean;
    onStateChange: (state: { blocked: boolean; dirty: boolean; busy: boolean; unconfirmed: boolean }) => void;
    onSaved?: (saved: ReminderSnapshot) => Promise<void>;
  } = $props();
  const initial = untrack(() => ({ scope, id }));
  const form = createReminderPolicyForm(initial.scope, {
    load: signal => getReminderPolicy(initial.scope, initial.id, signal),
    save: async (saved, draft, signal) => { const result = await putReminderPolicy(saved, draft, signal); await onSaved?.(result); return result; },
  });
  const locked = $derived(readonly || externalBlocked || !!$form.busy || !$form.authorized || !$form.saved?.editable || $form.saved?.frozen === true || $form.unconfirmed);
  const invalid = $derived(!validReminderSelection($form.draft, initial.scope));
  let refreshedSource = $state('');
  $effect.pre(() => {
    const observed = documentUpdatedAt, saved = $form.saved;
    if (initial.scope !== 'document' || !observed || !saved || saved.updated_at === observed || $form.busy) return;
    if ($form.dirty || $form.unconfirmed || refreshedSource === observed) { untrack(() => { form.sourceChanged(); }); return; }
    refreshedSource = observed;
    untrack(() => { void form.load(); });
  });
  const controlID = `reminder-policy-${initial.scope}-${initial.id}`;
  $effect(() => { onStateChange({ blocked: !$form.saved || !$form.authorized || !!$form.busy || $form.dirty || $form.unconfirmed, dirty: $form.dirty, busy: !!$form.busy, unconfirmed: $form.unconfirmed }); });
  function mode(value: string) { if (['inherit','legacy','disabled','interval'].includes(value)) form.edit(reminderSelection(value as ReminderMode, $form.draft.interval_days || 1, $form.draft.max_fires || 1)); }
  onMount(() => { void form.load(); return form.dispose; });
</script>

<section class="card overflow-hidden" aria-labelledby={`${controlID}-heading`}>
  <header class="flex flex-wrap items-start justify-between gap-3 border-b border-border bg-bg-elevated px-5 py-4">
    <div><h2 id={`${controlID}-heading`} class="flex items-center gap-2 text-sm font-medium"><Clock3 class="size-4" />{$ui(initial.scope === 'template' ? 'Default recipient reminders' : 'Recipient reminders')}</h2><p class="mt-1 max-w-2xl text-xs leading-relaxed text-text-secondary">{$ui(initial.scope === 'template' ? 'A default for future sends that inherit this template. Existing sends are unchanged.' : 'Choose the reminders for this draft. Sending freezes the policy; later preference changes do not rewrite it.')}</p></div>
    {#if $form.saved?.frozen}<span class="rounded-full border border-border px-2 py-1 text-xs">{$ui('Frozen for this send')}</span>{/if}
  </header>
  <form class="p-5 space-y-4" onsubmit={(event) => { event.preventDefault(); void form.save(readonly || externalBlocked); }}>
    {#if $form.busy === 'loading'}<p role="status" class="text-sm text-text-secondary">{$ui('Loading reminder policy…')}</p>{/if}
    {#if $form.error}<p role="alert" class="text-sm text-danger">{$ui($form.error)}</p>{/if}
    {#if $form.notice}<p role="status" class="text-sm text-text-secondary">{$ui($form.notice)}</p>{/if}
    <div class="grid gap-4 sm:grid-cols-3">
      <div><label for={`${controlID}-mode`} class="block text-xs font-medium">{$ui('Reminder policy')}</label><select id={`${controlID}-mode`} class="input mt-2 w-full" value={$form.draft.mode} disabled={locked} onchange={(event) => mode(event.currentTarget.value)}>
        {#if initial.scope === 'document'}<option value="inherit">{$ui('Inherit template default')}</option>{/if}<option value="legacy">{$ui('Standard: days 3 and 7')}</option><option value="disabled">{$ui('No automatic reminders')}</option><option value="interval">{$ui('Custom interval')}</option>
      </select></div>
      {#if $form.draft.mode === 'interval'}
        <div><label for={`${controlID}-days`} class="block text-xs font-medium">{$ui('Days between reminders')}</label><input id={`${controlID}-days`} type="number" min="1" max="365" step="1" class="input mt-2 w-full" value={$form.draft.interval_days} disabled={locked} oninput={(event) => form.edit({ ...$form.draft, interval_days: event.currentTarget.valueAsNumber })} /></div>
        <div><label for={`${controlID}-count`} class="block text-xs font-medium">{$ui('Maximum reminders')}</label><input id={`${controlID}-count`} type="number" min="1" max="365" step="1" class="input mt-2 w-full" value={$form.draft.max_fires} disabled={locked} oninput={(event) => form.edit({ ...$form.draft, max_fires: event.currentTarget.valueAsNumber })} /></div>
      {/if}
    </div>
    {#if $form.draft.mode === 'interval'}<p class="text-xs text-text-secondary">{$ui('Whole 24-hour days from sending. Interval × maximum must fit within 365 days.')}</p>{/if}
    {#if invalid}<p role="alert" class="text-sm text-danger">{$ui('Choose a valid interval and repeat count within one year.')}</p>{/if}
    {#if $form.saved}<div class="rounded-lg border border-border bg-bg-elevated p-3 text-xs leading-relaxed text-text-secondary"><strong>{$ui('Saved schedule')}</strong><p class="mt-1">{#if $form.saved.effective_policy.offsets_days.length}{$ui('Days after sending')}: {$form.saved.effective_policy.offsets_days.join(', ')}{:else}{$ui('No automatic reminders')}{/if}</p><p class="mt-1">{$ui('Manual reminders do not replenish this automatic reminder allowance.')}</p></div>{/if}
    {#if externalBlocked}<p role="note" class="text-xs text-text-secondary">{$ui('Save or reconcile the other document changes before changing this policy.')}</p>{/if}
    {#if $form.saved && !$form.saved.editable && !$form.saved.frozen}<p role="note" class="text-xs text-text-secondary">{$ui('This policy is read-only for the current document or user.')}</p>{/if}
    <div class="flex flex-wrap gap-2 border-t border-border pt-4">
      <button type="submit" class="btn btn-primary" disabled={locked || !$form.dirty || invalid}><Save class="size-4" />{$ui($form.busy === 'saving' ? 'Saving…' : 'Save reminder policy')}</button>
      <button type="button" class="btn btn-secondary" disabled={!!$form.busy || !$form.dirty || $form.unconfirmed} onclick={() => form.cancel()}>{$ui('Cancel')}</button>
      <button type="button" class="btn btn-secondary" disabled={!!$form.busy} onclick={() => { void form.load(); }}><RotateCcw class="size-4" />{$ui('Reload saved settings')}</button>
    </div>
    {#if initial.scope === 'document' && ($form.dirty || $form.unconfirmed)}<p role="status" class="text-xs text-text-secondary">{$ui('Send stays blocked until this policy is saved or reconciled.')}</p>{/if}
  </form>
</section>
