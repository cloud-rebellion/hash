<script lang="ts">
  import { onMount } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { Link2, RefreshCw, ShieldCheck, TriangleAlert } from 'lucide-svelte';
  import { CRMConnectionController, crmConnectionCapacity, crmConnectionPin, crmToken, initialCRMConnectionState, type CRMConnectionState } from '$lib/crmConnection';
  import { crmConnectionTransport } from '$lib/api/crmConnection';

  let connectionState = $state.raw<CRMConnectionState>(initialCRMConnectionState());
  let token = $state('');
  let revokeConfirmed = $state(false);
  const controller = new CRMConnectionController(crmConnectionTransport, (next) => { connectionState = next; });
  const pin = $derived(crmConnectionPin(connectionState.response));
  const connection = $derived(connectionState.response?.connection ?? null);
  const capacity = $derived(crmConnectionCapacity(connectionState.response));
  const canChange = $derived(!!connectionState.owner && !!connectionState.response && connectionState.fresh && !connectionState.needsReadback && !connectionState.busy);
  const accountConfirmed = $derived(!!pin && connectionState.confirmation === pin);
  const statusLabel = $derived(connectionState.response?.requires_reconfiguration ? 'Reconfiguration required' : connection?.status === 'active' ? 'Enabled' : connection?.status === 'candidate' ? 'Awaiting account confirmation' : connection?.status === 'revoked' ? 'Revoked' : 'Not configured');

  async function refresh() {
    token = ''; revokeConfirmed = false;
    await controller.refresh();
  }
  async function configure(event: SubmitEvent) {
    event.preventDefault();
    const submitted = token; token = ''; revokeConfirmed = false;
    await controller.configure(submitted);
  }
  async function enable() { revokeConfirmed = false; await controller.enable(); }
  async function revoke() {
    if (!revokeConfirmed) return;
    const submittedPin = pin; token = ''; revokeConfirmed = false;
    await controller.revoke(submittedPin);
  }
  function interrupt() { token = ''; revokeConfirmed = false; controller.interrupt(); }
  beforeNavigate(({ from, to, willUnload }) => {
    if (willUnload || from?.url.href !== to?.url.href) interrupt();
  });
  onMount(() => {
    void refresh();
    const hidden = () => { if (document.visibilityState === 'hidden') interrupt(); };
    const focus = () => { if (!connectionState.busy) void refresh(); };
    document.addEventListener('visibilitychange', hidden);
    window.addEventListener('focus', focus);
    return () => {
      token = ''; revokeConfirmed = false; controller.dispose();
      document.removeEventListener('visibilitychange', hidden);
      window.removeEventListener('focus', focus);
    };
  });
</script>

<div class="px-6 py-10 max-w-3xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · Integrations</p>
    <h1 class="page-title">BrightCRM connection</h1>
  </div>
  <p class="text-sm text-text-secondary mb-6 leading-relaxed">
    An organisation owner can connect the CRM account used by this workspace.
    The address is set by your operator. Save a key, then review the returned team and integration user before enabling it.
  </p>

  {#if connectionState.error}
    <div role="alert" class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-4">{connectionState.error}</div>
  {/if}
  {#if connectionState.notice}
    <div role="status" class="p-3 rounded-md border border-success text-sm mb-4">{connectionState.notice}</div>
  {/if}
  <div class="flex items-center justify-between gap-3 mb-4">
    <p class="text-sm text-text-muted">Owner access required</p>
    <button type="button" class="btn btn-secondary btn-sm" onclick={refresh} disabled={!!connectionState.busy}>
      <RefreshCw class="size-4" /> {connectionState.busy === 'refresh' ? 'Refreshing…' : 'Refresh connection'}
    </button>
  </div>

  {#if connectionState.busy === 'refresh'}
    <div class="card p-5 text-sm text-text-muted" role="status">Checking your owner access and the saved connection…</div>
  {:else if connectionState.owner && connectionState.response}
    {#if connectionState.response.requires_reconfiguration}
      <div class="card p-5 border-l-4 border-warning mb-6">
        <h2 class="text-lg mb-2">Reconfiguration required</h2>
        <p class="text-sm text-text-secondary">
          Your operator changed the CRM address. The retained account check belongs to the previous address, and this connection cannot be used for new CRM reads.
          Save a replacement key and confirm its returned account for the displayed address, or revoke the stored key.
        </p>
      </div>
    {/if}
    {#if !capacity.configure}
      <div class="card p-5 border-l-4 border-warning mb-6">
        <h2 class="text-lg mb-2">Connection revision limit reached</h2>
        <p class="text-sm text-text-secondary">
          A replacement key cannot be saved safely for this connection.
          {#if capacity.enable}You can still confirm and enable the pending account.{/if}
          {#if capacity.revoke}You can still revoke its stored key below.{/if}
          Ask your operator for help before setting up another key.
        </p>
      </div>
    {/if}
    {#if !connectionState.response.available}
      <div class="card p-5 border-l-4 border-warning mb-6">
        <h2 class="text-lg flex items-center gap-2 mb-2"><TriangleAlert class="size-4" /> Connection setup unavailable</h2>
        <p class="text-sm text-text-secondary">Your operator needs to configure the CRM address and secure credential storage before a key can be saved or enabled.</p>
        {#if connection && connection.status !== 'revoked'}
          <p class="text-sm text-text-secondary mt-2">You can still revoke the existing connection below.</p>
        {/if}
      </div>
    {/if}
    <section class="card p-5 mb-6" aria-labelledby="crm-account-heading">
      <div class="flex items-center justify-between gap-3 mb-4">
        <h2 id="crm-account-heading" class="text-lg flex items-center gap-2"><Link2 class="size-4" /> CRM account</h2>
        <span class="text-xs font-mono px-2 py-1 rounded-full border border-border-light">{statusLabel}</span>
      </div>
      <dl class="grid grid-cols-1 sm:grid-cols-[9rem_1fr] gap-x-4 gap-y-2 text-sm">
        <dt class="text-text-muted">CRM address</dt><dd class="break-all">{connectionState.response.origin || 'Not configured'}</dd>
        {#if connection}
          <dt class="text-text-muted">CRM team ID</dt><dd class="font-mono break-all" data-crm-team-id>{connection.crm_team_id}</dd>
          <dt class="text-text-muted">Integration user ID</dt><dd class="font-mono break-all" data-crm-user-id>{connection.crm_user_id}</dd>
          <dt class="text-text-muted">Account checked</dt><dd>{connection.verified_at ? new Date(connection.verified_at).toLocaleString() : 'No retained check'}</dd>
          <dt class="text-text-muted">Last change</dt><dd>{new Date(connection.updated_at).toLocaleString()}</dd>
        {/if}
      </dl>
      {#if connection?.status === 'candidate'}
        <div class="mt-5 pt-4 border-t border-border-light space-y-3">
          <p class="text-sm text-text-secondary">This key is saved but disabled. Confirm these exact account IDs against the intended CRM team and integration user.</p>
          <label class="flex items-start gap-2 text-sm">
            <input type="checkbox" checked={accountConfirmed} disabled={!canChange || !connectionState.response.available || !capacity.enable}
              onchange={(event) => controller.confirmAccount(pin, event.currentTarget.checked)} />
            <span>I confirm that the displayed CRM team and integration user are the intended account for this organisation.</span>
          </label>
          <button type="button" class="btn btn-primary" onclick={enable} disabled={!canChange || !connectionState.response.available || !capacity.enable || !accountConfirmed}>
            <ShieldCheck class="size-4" /> {connectionState.busy === 'enable' ? 'Enabling…' : 'Enable connection'}
          </button>
        </div>
      {:else if connection?.status === 'revoked'}
        <p class="text-sm text-text-secondary mt-4">The stored key has been removed. The displayed account IDs are retained from the previous check.</p>
      {/if}
    </section>

    {#if connectionState.response.available}
      <form class="card p-5 mb-6 space-y-4" onsubmit={configure}>
        <h2 class="text-lg">{connection ? 'Replace the CRM key' : 'Set up a CRM key'}</h2>
        <p class="text-sm text-text-secondary">
          Use a read-only BrightCRM API key. Hash checks the account identity; this check does not expose or verify the key’s scopes or expiry.
          {#if connection?.status === 'active'}Saving a replacement disables the current connection until the returned account is confirmed again.{/if}
        </p>
        <label class="flex flex-col gap-2 text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">BrightCRM API key</span>
          <input type="password" bind:value={token} autocomplete="off" spellcheck="false" maxlength="64"
            aria-label="BrightCRM API key" placeholder="Paste the exact 64-character lowercase key"
            disabled={!canChange || !capacity.configure} class="px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm font-mono" />
          <span class="text-xs text-text-muted">Stored encrypted by Hash and never returned. The input clears when submitted or when you leave this page.</span>
        </label>
        <button type="submit" class="btn btn-primary" disabled={!canChange || !capacity.configure || !crmToken(token)}>
          {connectionState.busy === 'configure' ? 'Checking and saving…' : 'Check account and save key'}
        </button>
      </form>
    {/if}

    {#if connection && connection.status !== 'revoked'}
      <section class="card p-5 mb-6 space-y-3" aria-labelledby="crm-revoke-heading">
        <h2 id="crm-revoke-heading" class="text-lg">Revoke connection</h2>
        <p class="text-sm text-text-secondary">Stop new CRM reads through this connection and remove the stored key. Existing documents and signing evidence keep their recorded information.</p>
        <label class="flex items-start gap-2 text-sm">
          <input type="checkbox" bind:checked={revokeConfirmed} disabled={!canChange || !capacity.revoke} />
          <span>I want to revoke this organisation’s CRM connection.</span>
        </label>
        <button type="button" class="btn btn-secondary text-danger" onclick={revoke} disabled={!canChange || !capacity.revoke || !revokeConfirmed}>
          {connectionState.busy === 'revoke' ? 'Revoking…' : 'Revoke connection'}
        </button>
      </section>
    {/if}
    <p class="text-sm text-text-muted leading-relaxed">
      Enabling the connection approves account access. Changes to CRM information used in a contract still require a new PDF and human review before sending.
    </p>
  {:else if !connectionState.error}
    <div class="card p-5 text-sm text-text-muted">Refresh to verify your current owner access.</div>
  {/if}
</div>
