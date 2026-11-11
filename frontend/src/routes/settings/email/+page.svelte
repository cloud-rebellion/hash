<script lang="ts">
  import EmailTemplateSettings from '$lib/components/EmailTemplateSettings.svelte';
  import { ArrowRight, FlaskConical } from 'lucide-svelte';
  import { staffLocale } from '$lib/staffPreferences';
  import { roomPreviewCopy } from '$lib/roomPreview';
  const previewCopy = $derived(roomPreviewCopy($staffLocale));
</script>

<div class="mx-auto max-w-6xl px-5 pt-7 sm:px-6">
  <a class="flex items-center gap-4 rounded-xl border border-border bg-bg-surface px-5 py-4 transition-colors hover:bg-bg-hover focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-info" href="/settings/room-preview">
    <span class="flex size-10 shrink-0 items-center justify-center rounded-xl border border-border bg-bg-elevated text-text-secondary"><FlaskConical class="size-5" /></span>
    <span class="min-w-0 flex-1"><strong class="block text-sm font-medium">{previewCopy.entryTitle}</strong><span class="mt-1 block text-xs leading-relaxed text-text-secondary">{previewCopy.entryDescription}</span></span>
    <span class="flex shrink-0 items-center gap-2 text-xs text-text-secondary"><span class="hidden sm:inline">{previewCopy.entryAction}</span><ArrowRight class="size-4" /></span>
  </a>
</div>

<EmailTemplateSettings />
