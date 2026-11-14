<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { Mail, RotateCcw } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { startSavedEmailTemplateTest } from '$lib/api/emailTemplateSample';
  import { loadWorkspaceSMTP, readWorkspaceSMTPTest } from '$lib/api/workspaceSMTP';
  import { createEmailTemplateSample, type EmailTemplateKind, type WorkspaceEmailLocale } from '$lib/emailTemplateEditor';

  let { kind, revision, disabled = false, previewLocale }: { kind: EmailTemplateKind; revision: number; disabled?: boolean; previewLocale?: WorkspaceEmailLocale } = $props();
  const sample = createEmailTemplateSample({ load: loadWorkspaceSMTP, send: startSavedEmailTemplateTest, status: readWorkspaceSMTPTest });
  $effect.pre(() => { sample.setScope(kind, revision, previewLocale, disabled); });
  onMount(() => { sample.setScope(kind, revision, previewLocale, disabled); void sample.act('settings'); });
  onDestroy(() => sample.dispose());
</script>

<section class="space-y-3 rounded-xl border border-border bg-bg-elevated p-4" aria-label={$ui('Send a template test')}>
  <div><h3 class="text-sm font-medium text-text-primary">{$ui('Send a template test')}</h3><p class="mt-1 text-xs leading-relaxed text-text-secondary">{$ui('Send the saved design to your own account email using this workspace’s SMTP. Document details are synthetic and signing links are inactive.')}</p></div>
  {#if disabled}<p class="text-xs text-text-secondary">{$ui('Save or cancel your edits before sending a test.')}</p>{/if}
  {#if $sample.smtp && !$sample.smtp.configured}<a class="text-xs underline underline-offset-4" href="/settings/delivery">{$ui('Configure workspace email delivery first')}</a>{/if}
  {#if $sample.error}<p class="text-xs text-danger" role="alert">{$ui($sample.error)}</p>{/if}
  {#if $sample.receipt || $sample.uncertain || $sample.busy && $sample.attemptLocale}
    <p class="text-xs text-text-secondary">{$ui('Requested test language: {language}', { language: $ui($sample.attemptLocale === 'sv' ? 'Swedish' : $sample.attemptLocale === 'en' ? 'English' : 'Workspace default') })}</p>
  {/if}
  {#if $sample.receipt}
    <p class="text-xs leading-relaxed text-text-secondary" role="status">{$ui($sample.receipt.smtp_accepted ? 'SMTP accepted the test. Check your inbox; inbox delivery is not confirmed here.' : $sample.receipt.status === 'failed' ? 'Test delivery failed. Review workspace SMTP settings before trying again.' : 'The test is queued. SMTP acceptance and inbox delivery are still pending.')}</p>
  {/if}
  <div class="flex flex-wrap gap-2">
    <button type="button" class="btn btn-secondary" disabled={$sample.busy || disabled || $sample.uncertain || !$sample.smtp?.configured || !!$sample.receipt && !$sample.receipt.smtp_accepted && $sample.receipt.status !== 'failed'} aria-busy={$sample.busy} onclick={() => sample.act('send')}><Mail class="size-3.5" /> {$ui('Send saved template test')}</button>
    {#if $sample.receipt}<button type="button" class="btn btn-secondary" disabled={$sample.busy} onclick={() => sample.act('status')}><RotateCcw class="size-3.5" /> {$ui('Check test status')}</button>
    {:else if !$sample.smtp}<button type="button" class="text-xs underline underline-offset-4 disabled:opacity-50" disabled={$sample.busy} onclick={() => sample.act('settings')}>{$ui('Check delivery settings')}</button>{/if}
  </div>
</section>
