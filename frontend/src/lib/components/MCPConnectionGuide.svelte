<script lang="ts">
  import { onMount } from 'svelte';
  import { ui } from '$lib/staffPreferences';
  import { Check, Copy, KeyRound, Plug } from 'lucide-svelte';

  let canManageKeys = $state(false);
  let endpoint = $state('https://hash.example.com/mcp');
  let copied = $state(false);
  let copyFailed = $state(false);
  onMount(() => {
    endpoint = window.location.origin + '/mcp';
    const controller = new AbortController();
    let current = true;
    void fetch('/api/v1/me', { credentials: 'include', cache: 'no-store', signal: controller.signal })
      .then(async (response) => { const identity = response.ok ? await response.json() : null; if (current) canManageKeys = identity?.role === 'owner'; })
      .catch(() => { if (current) canManageKeys = false; });
    return () => { current = false; controller.abort(); };
  });

  async function copyEndpoint() {
    copied = false;
    copyFailed = false;
    try {
      await navigator.clipboard.writeText(endpoint);
      copied = true;
    } catch {
      copyFailed = true;
    }
  }
</script>

<section id="mcp" class="card p-5 sm:p-6 space-y-4" aria-labelledby="mcp-connection-heading">
  <div class="flex items-start gap-3">
    <span class="flex size-9 shrink-0 items-center justify-center rounded-lg bg-bg-hover"><Plug class="size-4" /></span>
    <div>
      <h2 id="mcp-connection-heading" class="font-display text-lg text-text-primary">{$ui('Connect via MCP over HTTP')}</h2>
      <p class="mt-1 text-sm text-text-secondary">{$ui('Connect an MCP-capable client to this workspace using an API key.')}</p>
    </div>
  </div>
  <div class="space-y-2">
    <label for="hash-mcp-endpoint" class="block text-xs font-medium text-text-secondary">{$ui('Server address')}</label>
    <div class="flex flex-wrap gap-2">
      <input id="hash-mcp-endpoint" class="min-w-0 flex-1 rounded-lg border border-border bg-bg-elevated px-3 py-2 font-mono text-xs text-text-primary" readonly value={endpoint} />
      <button type="button" class="btn btn-secondary" onclick={copyEndpoint}>{#if copied}<Check class="size-4" /> {$ui('Copied')}{:else}<Copy class="size-4" /> {$ui('Copy address')}{/if}</button>
    </div>
    {#if copyFailed}<p role="status" class="text-sm text-text-secondary">{$ui('Select and copy the server address above.')}</p>{/if}
  </div>
  <ol class="list-decimal space-y-2 pl-5 text-sm text-text-secondary">
    <li>{#if canManageKeys}{$ui('Create an API key with the access your client needs.')}{:else}{$ui('Ask a workspace owner for an API key with the access your client needs.')}{/if}</li>
    <li>{$ui("Add this server address in your client's HTTP MCP connection settings.")}</li>
    <li>{$ui('Use the key as a Bearer token in the Authorization header. Keep it private; do not add it to the address.')}</li>
  </ol>
  <div class="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
    <p class="max-w-xl text-xs text-text-secondary">{$ui('Available tools depend on your plan, workspace role and key scopes.')}</p>
    {#if canManageKeys}<a href="/settings/api-keys" class="btn btn-secondary"><KeyRound class="size-4" /> {$ui('Manage API keys')}</a>{/if}
  </div>
</section>
