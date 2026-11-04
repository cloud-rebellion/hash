<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import { ArrowLeft, Check, Mail, RotateCcw, Save, ShieldCheck } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { createWorkspaceSMTPController, type WorkspaceSMTPController, type SMTPField } from '$lib/workspaceSMTP';
  import { loadWorkspaceSMTP, saveWorkspaceSMTP, disableWorkspaceSMTP, startWorkspaceSMTPTest, readWorkspaceSMTPTest } from '$lib/api/workspaceSMTP';

  let { controller }: { controller?: WorkspaceSMTPController } = $props();
  const editor = untrack(() => controller) ?? createWorkspaceSMTPController({ load: loadWorkspaceSMTP, save: saveWorkspaceSMTP, disable: disableWorkspaceSMTP, test: startWorkspaceSMTPTest, status: readWorkspaceSMTPTest });
  const busy = $derived($editor.busy !== null);
  const locked = $derived(busy || !$editor.authorized);
  const fenced = $derived(locked || $editor.conflict || $editor.outcomeUnknown);
  const problems = $derived($editor.metadata ? editor.problems() : {});
  const invalid = $derived(Object.keys(problems).length > 0);
  const testPending = $derived($editor.testReceipt?.status === 'pending' || $editor.testReceipt?.status === 'retrying');
  const modeLabels = { unconfigured: 'Own SMTP required', installation_legacy: 'Legacy installation transport', configured: 'Saved configuration', disabled: 'Delivery disabled' };
  const testLabels = { pending: 'Queued', retrying: 'Retrying delivery', sent: 'SMTP accepted', failed: 'Delivery failed' };
  let form: HTMLFormElement | undefined = $state.raw();
  let disableButton: HTMLButtonElement | undefined = $state.raw();
  let disableCancel: HTMLButtonElement | undefined = $state.raw();
  onMount(() => { void editor.load(); return editor.dispose; });

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (fenced) return;
    const first = Object.keys(editor.problems())[0] as SMTPField | undefined;
    if (first) { form?.querySelector<HTMLElement>(`[data-smtp-field="${first}"]`)?.focus(); return; }
    await editor.save();
  }
  async function askDisable() { if (editor.requestDisable()) { await tick(); disableCancel?.focus(); } }
  async function closeDisable() { if (editor.cancelDisable()) { await tick(); disableButton?.focus(); } }
  function disableKey(event: KeyboardEvent) { if (event.key === 'Escape' && !busy) { event.preventDefault(); void closeDisable(); } }
</script>

<div class="mx-auto max-w-4xl space-y-6 px-5 py-8 sm:px-6 sm:py-10">
  <header class="space-y-3">
    <a class="inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text-primary" href="/settings"><ArrowLeft class="size-3" /> {$ui('Settings')}</a>
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div class="space-y-2"><p class="page-eyebrow">{$ui('Workspace · Delivery')}</p><h1 class="page-title">{$ui('Email delivery')}</h1><p class="max-w-xl text-sm text-text-secondary">{$ui('Connect this workspace’s own SMTP server. Email content is managed separately.')}</p></div>
      <span class="flex items-center gap-2 rounded-full border border-border px-3 py-1.5 text-xs text-text-secondary"><ShieldCheck class="size-3.5" /> {$ui('Owners only')}</span>
    </div>
  </header>
  {#if $editor.error}<div class="rounded-xl border border-danger/40 bg-danger/5 p-4 text-sm" role="alert"><p class="text-danger">{$ui($editor.error)}</p>{#if $editor.conflict || $editor.outcomeUnknown}<p class="mt-2 text-xs text-text-secondary">{$ui('Reloading discards the form and reads the current configuration. It does not undo a change or resend a test.')}</p>{/if}<button type="button" class="btn btn-secondary mt-3" disabled={busy} onclick={() => editor.load(true)}><RotateCcw class="size-3.5" /> {$ui($editor.metadata ? 'Discard form and reload' : 'Try again')}</button></div>{/if}
  {#if $editor.notice}<p class="flex items-center gap-2 text-sm text-success" role="status"><Check class="size-4" /> {$ui($editor.notice)}</p>{/if}
  {#if !$editor.metadata && $editor.busy === 'loading'}<p class="card p-6 text-sm text-text-secondary" role="status">{$ui('Loading delivery settings…')}</p>{/if}
  {#if $editor.metadata && $editor.authorized}
    <section class="flex items-start gap-3 rounded-xl border border-border bg-bg-elevated p-4" aria-label={$ui('Delivery status')}>
      <Mail class="mt-0.5 size-4 shrink-0 text-text-secondary" /><div class="space-y-1"><h2 class="text-sm font-medium text-text-primary">{$ui(modeLabels[$editor.metadata.mode])}</h2>
        <p class="text-xs leading-relaxed text-text-secondary">{$ui($editor.metadata.mode === 'configured' ? 'Configuration is saved. This does not prove that the server accepts mail or that a message reaches an inbox.' : $editor.metadata.mode === 'installation_legacy' ? 'This existing workspace still uses its legacy installation transport. Saving your own server replaces that route; disabling delivery does not fall back to it.' : 'Document email requires this workspace’s own SMTP configuration. No shared transport is selected automatically.')}</p>
        <p class="text-[10px] text-text-muted">{$ui('Revision {revision}', { revision: $editor.metadata.revision })}</p></div>
    </section>
    <form bind:this={form} onsubmit={save} novalidate class="overflow-hidden rounded-xl border border-border bg-bg-surface">
      <fieldset disabled={locked} class="space-y-6 p-5 sm:p-6">
        <legend class="sr-only">{$ui('Workspace SMTP configuration')}</legend>
        <section class="space-y-4" aria-labelledby="smtp-sender-heading">
          <div><h2 id="smtp-sender-heading" class="text-sm font-medium text-text-primary">{$ui('Sender identity')}</h2><p class="mt-1 text-xs text-text-secondary">{$ui('Use a sender address permitted by your mail provider.')}</p></div>
          <div class="grid gap-4 sm:grid-cols-2">
            <label class="field" for="smtp-sender-name"><span>{$ui('Sender name')}</span><input id="smtp-sender-name" data-smtp-field="sender_name" value={$editor.draft.sender_name} oninput={event => editor.edit('sender_name', event.currentTarget.value)} autocomplete="off" aria-invalid={!!problems.sender_name} aria-describedby="smtp-sender-name-help" /><small id="smtp-sender-name-help">{$ui(problems.sender_name ?? 'The name recipients see beside the sender address.')}</small></label>
            <label class="field" for="smtp-sender-email"><span>{$ui('Sender email')}</span><input id="smtp-sender-email" data-smtp-field="sender_email" type="email" value={$editor.draft.sender_email} oninput={event => editor.edit('sender_email', event.currentTarget.value)} autocomplete="off" spellcheck="false" aria-invalid={!!problems.sender_email} aria-describedby="smtp-sender-email-help" /><small id="smtp-sender-email-help">{$ui(problems.sender_email ?? 'Address only, without a display name.')}</small></label>
          </div>
        </section>
        <section class="space-y-4 border-t border-border pt-5" aria-labelledby="smtp-server-heading">
          <div><h2 id="smtp-server-heading" class="text-sm font-medium text-text-primary">{$ui('SMTP server')}</h2><p class="mt-1 text-xs text-text-secondary">{$ui('Encrypted connections only. Choose the mode specified by your provider.')}</p></div>
          <div class="grid gap-4 sm:grid-cols-2">
            <label class="field" for="smtp-host"><span>{$ui('Hostname or IP address')}</span><input id="smtp-host" data-smtp-field="host" value={$editor.draft.host} oninput={event => editor.edit('host', event.currentTarget.value)} autocomplete="off" spellcheck="false" autocapitalize="none" aria-invalid={!!problems.host} aria-describedby="smtp-host-help" /><small id="smtp-host-help">{$ui(problems.host ?? 'Enter the server address without a URL or port.')}</small></label>
            <label class="field" for="smtp-connection"><span>{$ui('Connection security')}</span><select id="smtp-connection" data-smtp-field="connection" value={$editor.draft.connection} onchange={event => editor.edit('connection', event.currentTarget.value)} aria-invalid={!!problems.connection} aria-describedby="smtp-connection-help"><option value="">{$ui('Choose a connection')}</option><option value="starttls">STARTTLS · 587</option><option value="tls">TLS · 465</option></select><small id="smtp-connection-help">{$ui(problems.connection ?? 'Port follows the selected security mode.')}</small></label>
          </div>
        </section>
        <section class="space-y-4 border-t border-border pt-5" aria-labelledby="smtp-auth-heading">
          <div><h2 id="smtp-auth-heading" class="text-sm font-medium text-text-primary">{$ui('Authentication')}</h2><p class="mt-1 text-xs text-text-secondary">{$ui('Stored credentials are never displayed. Changing the server requires a fresh authentication choice.')}</p></div>
          <label class="field" for="smtp-authentication"><span>{$ui('Authentication choice')}</span><select id="smtp-authentication" data-smtp-field="authentication" value={$editor.authentication} onchange={event => editor.authenticate(event.currentTarget.value as 'keep' | 'replace' | 'relay' | '')} aria-invalid={!!problems.authentication} aria-describedby="smtp-auth-help"><option value="">{$ui('Choose authentication')}</option>{#if $editor.metadata.configured}<option value="keep">{$ui($editor.metadata.username_set ? 'Keep saved credentials for this server' : 'Keep this server’s saved relay choice')}</option>{/if}<option value="replace">{$ui('Enter new username and password')}</option><option value="relay">{$ui('Use an unauthenticated TLS relay')}</option></select><small id="smtp-auth-help">{$ui(problems.authentication ?? 'Keeping credentials is allowed only for the unchanged server, port and security mode.')}</small></label>
          {#if $editor.authentication === 'replace'}
            {#key $editor.credentialEpoch}<div class="grid gap-4 sm:grid-cols-2">
              <label class="field" for="smtp-username"><span>{$ui('New SMTP username')}</span><input id="smtp-username" data-smtp-field="username" type="password" oninput={event => editor.credential('username', event.currentTarget.value)} autocomplete="off" spellcheck="false" autocapitalize="none" aria-invalid={!!problems.username} aria-describedby="smtp-username-help" /><small id="smtp-username-help">{$ui(problems.username ?? 'New entry only. The saved username is not retrieved.')}</small></label>
              <label class="field" for="smtp-password"><span>{$ui('New SMTP password')}</span><input id="smtp-password" data-smtp-field="password" type="password" oninput={event => editor.credential('password', event.currentTarget.value)} autocomplete="new-password" spellcheck="false" aria-invalid={!!problems.password} aria-describedby="smtp-password-help" /><small id="smtp-password-help">{$ui(problems.password ?? 'Cleared after submitting, cancelling or changing the server.')}</small></label>
            </div>{/key}
          {:else if $editor.authentication === 'relay'}<p class="rounded-lg border border-warning/40 bg-warning/5 p-3 text-xs text-text-secondary" role="note">{$ui('No username or password will be used. Select this only when your provider explicitly permits an unauthenticated encrypted relay.')}</p>{/if}
        </section>
      </fieldset>
      <footer class="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-bg-elevated px-5 py-4"><p class="max-w-sm text-xs text-text-secondary">{$ui('Saving changes configuration only. Use the separate owner test to check SMTP acceptance.')}</p><div class="flex gap-2"><button type="button" class="btn btn-secondary" disabled={busy || !$editor.dirty} onclick={() => editor.cancel()}>{$ui('Cancel')}</button><button type="submit" class="btn btn-primary" disabled={fenced || !$editor.dirty} aria-busy={$editor.busy === 'saving'}><Save class="size-3.5" /> {$ui($editor.busy === 'saving' ? 'Saving…' : 'Save delivery settings')}</button></div></footer>
    </form>
    <section class="card space-y-4 p-5 sm:p-6" aria-labelledby="smtp-test-heading">
      <div><h2 id="smtp-test-heading" class="text-sm font-medium text-text-primary">{$ui('Send an owner test')}</h2><p class="mt-1 text-xs leading-relaxed text-text-secondary">{$ui('A synthetic message goes only to your authenticated owner email address. The destination and content cannot be changed here.')}</p></div>
      <p class="text-xs text-text-secondary">{$ui('Test the saved configuration. SMTP acceptance means the mail server accepted the message, not that it reached the inbox.')}</p>
      {#if $editor.testUnknown}<p class="text-sm text-warning" role="alert">{$ui('The test request is unconfirmed and may still send. Sending another test is held on this page; reloading settings does not resolve that uncertainty.')}</p>{/if}
      {#if $editor.testReceipt}<div class="rounded-lg border border-border bg-bg-elevated p-3" role="status"><p class="text-sm font-medium text-text-primary">{$ui(testLabels[$editor.testReceipt.status])}</p><p class="mt-1 text-xs text-text-secondary">{$ui('Saved revision {revision} · Inbox delivery is not confirmed.', { revision: $editor.testReceipt.revision })}</p></div>{/if}
      {#if $editor.testError}<p class="text-xs text-warning" role="status">{$ui($editor.testError)}</p>{/if}
      <div class="flex flex-wrap items-center gap-3"><button type="button" class="btn btn-secondary" disabled={fenced || invalid || $editor.dirty || !$editor.metadata.configured || $editor.testUnknown || testPending} aria-busy={$editor.busy === 'testing'} onclick={() => editor.test()}><Mail class="size-3.5" /> {$ui($editor.busy === 'testing' ? 'Requesting test…' : 'Send synthetic test')}</button>{#if testPending && !$editor.polling}<button type="button" class="text-xs text-text-secondary underline" disabled={busy} onclick={() => editor.monitor()}>{$ui('Check test status')}</button>{/if}{#if $editor.polling}<span class="text-xs text-text-muted">{$ui('Monitoring delivery…')}</span>{/if}</div>
    </section>
    {#if $editor.metadata.mode === 'configured' || $editor.metadata.mode === 'installation_legacy'}
      <section class="rounded-xl border border-border p-5" aria-labelledby="smtp-disable-heading"><h2 id="smtp-disable-heading" class="text-sm font-medium text-text-primary">{$ui('Disable workspace delivery')}</h2><p class="mt-1 text-xs text-text-secondary">{$ui('Stops workspace document email. Staff sign-in and account recovery use their separate service.')}</p>
        {#if $editor.disablePrompt}<div class="mt-4 space-y-3 rounded-lg border border-danger/40 bg-danger/5 p-4" role="alertdialog" aria-labelledby="smtp-disable-question" aria-describedby="smtp-disable-detail"><p id="smtp-disable-question" class="text-sm font-medium text-text-primary">{$ui('Disable email delivery for this workspace?')}</p><p id="smtp-disable-detail" class="text-xs text-text-secondary">{$ui('No shared or legacy transport will be selected as a fallback. Unsaved form entries will be discarded.')}</p><div class="flex gap-2"><button bind:this={disableCancel} type="button" class="btn btn-secondary" disabled={busy} onkeydown={disableKey} onclick={closeDisable}>{$ui('Cancel')}</button><button type="button" class="btn btn-secondary text-danger" disabled={fenced} onkeydown={disableKey} onclick={() => editor.disable()}>{$ui($editor.busy === 'disabling' ? 'Disabling…' : 'Disable delivery')}</button></div></div>
        {:else}<button bind:this={disableButton} type="button" class="btn btn-secondary mt-4" disabled={fenced} onclick={askDisable}>{$ui('Disable delivery')}</button>{/if}
      </section>
    {/if}
    <p class="text-xs text-text-secondary"><a class="underline underline-offset-4" href="/settings/email">{$ui('Edit email content')}</a> · {$ui('Message templates and SMTP delivery are separate settings.')}</p>
  {/if}
</div>

<style>
  .field { display: block; font-size: 0.75rem; font-weight: 500; color: var(--color-text-primary); }
  .field input, .field select { display: block; margin-top: 0.5rem; width: 100%; border: 1px solid var(--color-border); border-radius: 0.5rem; background: var(--color-bg-elevated); padding: 0.6rem 0.75rem; color: var(--color-text-primary); font-size: 0.875rem; }
  .field input:focus-visible, .field select:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
  .field small { display: block; margin-top: 0.4rem; font-weight: 400; line-height: 1.5; color: var(--color-text-secondary); }
  .field input[aria-invalid='true'], .field select[aria-invalid='true'] { border-color: var(--color-warning); }
</style>
