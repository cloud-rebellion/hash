<script lang="ts">
  import { onMount, onDestroy, untrack } from 'svelte';
  import { Mail, RotateCcw } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { APIError } from '$lib/api/client';
  import { startSavedEmailTemplateTest } from '$lib/api/emailTemplateSample';
  import { loadWorkspaceSMTP, readWorkspaceSMTPTest } from '$lib/api/workspaceSMTP';
  import type { EmailTemplateKind } from '$lib/emailTemplateEditor';
  import type { WorkspaceSMTP, SMTPTestReceipt } from '$lib/workspaceSMTP';

  let { kind, revision, disabled = false }: { kind: EmailTemplateKind; revision: number; disabled?: boolean } = $props();
  let smtp = $state<WorkspaceSMTP | null>(null), receipt = $state<SMTPTestReceipt | null>(null);
  let busy = $state(false), error = $state<string | null>(null), uncertain = $state(false);
  let disposed = false, generation = 0, request: AbortController | null = null, lastScope = '';
  const scope = () => JSON.stringify([kind, revision]);
  $effect.pre(() => {
    const next = scope();
    untrack(() => {
      if (lastScope && lastScope !== next) { generation++; request?.abort(); busy = false; receipt = null; error = null; uncertain = false; }
      lastScope = next;
    });
  });
  async function act(operation: 'settings' | 'send' | 'status') {
    if (disposed || busy || (operation === 'send' && (disabled || uncertain || !smtp?.configured || revision < 0)) || (operation === 'status' && !receipt)) return;
    const ticket = ++generation, selected = scope(), selectedKind = kind, selectedRevision = revision;
    const controller = new AbortController(); request = controller; busy = true; error = null;
    const timer = setTimeout(() => controller.abort(), 30_000);
    const current = () => !disposed && ticket === generation && selected === scope();
    try {
      if (operation === 'settings') {
        const result = await loadWorkspaceSMTP(controller.signal);
        if (controller.signal.aborted) throw new Error('Test request timed out');
        if (current()) smtp = result;
      } else if (operation === 'send') {
        const result = await startSavedEmailTemplateTest(selectedKind, selectedRevision, smtp!.revision, controller.signal);
        if (controller.signal.aborted) throw new Error('Test request timed out');
        if (current()) receipt = result;
      } else {
        const result = await readWorkspaceSMTPTest(receipt!.delivery_id, controller.signal);
        if (controller.signal.aborted) throw new Error('Test request timed out');
        if (current()) receipt = result;
      }
    } catch (cause) {
      if (!current()) return;
      const status = cause instanceof APIError ? cause.status : 0;
      if (operation === 'send' && (status === 0 || status >= 500)) {
        uncertain = true; error = 'Could not confirm whether the test was queued. Check your inbox and reload before another test.';
      } else if (status === 409) { smtp = null; error = 'The saved template or delivery settings changed. Reload and review before testing.'; }
      else if (status === 429) error = 'A test is pending or was requested recently. Check its status before sending another.';
      else if (status === 401 || status === 403) { smtp = null; error = 'Owner access is no longer available. Sign in again.'; }
      else error = 'Could not check the email test. Try again.';
    } finally {
      clearTimeout(timer);
      if (current()) { busy = false; request = null; }
    }
  }
  onMount(() => { void act('settings'); });
  onDestroy(() => { disposed = true; generation++; request?.abort(); });
</script>

<section class="space-y-3 rounded-xl border border-border bg-bg-elevated p-4" aria-label={$ui('Send a template test')}>
  <div><h3 class="text-sm font-medium text-text-primary">{$ui('Send a template test')}</h3><p class="mt-1 text-xs leading-relaxed text-text-secondary">{$ui('Send the saved design to your own account email using this workspace’s SMTP. Document details are synthetic and signing links are inactive.')}</p></div>
  {#if disabled}<p class="text-xs text-text-secondary">{$ui('Save or cancel your edits before sending a test.')}</p>{/if}
  {#if smtp && !smtp.configured}<a class="text-xs underline underline-offset-4" href="/settings/delivery">{$ui('Configure workspace email delivery first')}</a>{/if}
  {#if error}<p class="text-xs text-danger" role="alert">{$ui(error)}</p>{/if}
  {#if receipt}
    <p class="text-xs leading-relaxed text-text-secondary" role="status">{$ui(receipt.smtp_accepted ? 'SMTP accepted the test. Check your inbox; inbox delivery is not confirmed here.' : receipt.status === 'failed' ? 'Test delivery failed. Review workspace SMTP settings before trying again.' : 'The test is queued. SMTP acceptance and inbox delivery are still pending.')}</p>
  {/if}
  <div class="flex flex-wrap gap-2">
    <button type="button" class="btn btn-secondary" disabled={busy || disabled || uncertain || !smtp?.configured || !!receipt && !receipt.smtp_accepted && receipt.status !== 'failed'} aria-busy={busy} onclick={() => act('send')}><Mail class="size-3.5" /> {$ui('Send saved template test')}</button>
    {#if receipt}<button type="button" class="btn btn-secondary" disabled={busy} onclick={() => act('status')}><RotateCcw class="size-3.5" /> {$ui('Check test status')}</button>
    {:else if !smtp}<button type="button" class="text-xs underline underline-offset-4 disabled:opacity-50" disabled={busy} onclick={() => act('settings')}>{$ui('Check delivery settings')}</button>{/if}
  </div>
</section>
