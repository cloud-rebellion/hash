<script lang="ts">
  import { ArrowLeft, Bell } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import AutomationPreferencesSettings from '$lib/components/AutomationPreferencesSettings.svelte';
</script>

<div class="mx-auto max-w-4xl px-6 py-10 space-y-6">
  <a href="/settings" class="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary"><ArrowLeft class="size-4" />{$ui('Settings')}</a>
  <header class="space-y-2"><p class="page-eyebrow">{$ui('Connections & automation')}</p><h1 class="page-title flex items-center gap-3"><Bell class="size-6" />{$ui('Automations')}</h1><p class="max-w-2xl text-sm text-text-secondary">{$ui('Choose your own activity notices. Configure recipient reminders in each template or draft document.')}</p></header>
  <AutomationPreferencesSettings />
  <section class="card p-5 space-y-2"><h2 class="font-medium">{$ui('Recipient reminders')}</h2><p class="text-sm leading-relaxed text-text-secondary">{$ui('Without an explicit policy, automatic reminders remain on days 3 and 7, with two reminders in total. A draft can inherit its template default or use its own policy. Sending freezes the policy for that send.')}</p><a href="/templates" class="inline-flex text-sm underline underline-offset-4">{$ui('Manage template defaults')}</a></section>
</div>
