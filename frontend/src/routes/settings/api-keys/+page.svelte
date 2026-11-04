<script lang="ts">
  import { ui, staffLocale } from '$lib/staffPreferences';
  import { onMount, tick } from 'svelte';
  import MCPConnectionGuide from '$lib/components/MCPConnectionGuide.svelte';
  import DocumentAIAccessSettings from '$lib/components/DocumentAIAccessSettings.svelte';
  import { createAPIKey, deleteAPIKey, listAPIKeys, type APIKeyResponse } from '$lib/api/client';
  import { Copy, Key, Plus, Trash2 } from 'lucide-svelte';

  let keys = $state<APIKeyResponse[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  let showCreate = $state(false);
  let newName = $state('');
  let scopes = $state<{ read: boolean; authoring: boolean; workflow: boolean }>({
    read: true, authoring: true, workflow: false
  });
  let creating = $state(false);
  let nameInput = $state.raw<HTMLInputElement>();
  let createTrigger = $state.raw<HTMLButtonElement>();
  const selectedPermission = $derived(scopes.read || scopes.authoring || scopes.workflow);
  const missingInput = $derived(!newName.trim() ? 'Enter a name for this key.' : !selectedPermission ? 'Choose at least one permission.' : '');

  async function openCreate() {
    if (creating) return;
    showCreate = true; error = null;
    await tick(); nameInput?.focus();
  }
  async function closeCreate() {
    if (creating) return;
    showCreate = false; error = null;
    await tick(); createTrigger?.focus();
  }
  let mintedPlaintext = $state<string | null>(null);
  let keyCopied = $state(false);
  let copyError = $state(false);
  let copyingKey = $state(false);
  let copyRevision = 0;

  async function refresh() {
    loading = true;
    try {
      const res = await listAPIKeys();
      keys = res.api_keys;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(refresh);

  async function create(event?: Event) {
    event?.preventDefault();
    if (creating) return;
    if (!newName.trim()) { error = 'Enter a name for this key.'; nameInput?.focus(); return; }
    if (!scopes.read && !scopes.authoring && !scopes.workflow) {
      error = 'Choose at least one permission.';
      return;
    }
    creating = true;
    error = null;
    try {
      const selected: string[] = [];
      if (scopes.read) selected.push('read');
      if (scopes.authoring) selected.push('write:authoring');
      if (scopes.workflow) selected.push('write:workflow');
      const res = await createAPIKey({ name: newName.trim(), scopes: selected });
      mintedPlaintext = res.plaintext ?? null;
      invalidateCopyFeedback();
      newName = '';
      scopes = { read: true, authoring: true, workflow: false };
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      creating = false;
    }
  }

  async function revoke(id: string) {
    if (!confirm($ui('Revoke this API key? This is permanent.'))) return;
    try {
      await deleteAPIKey(id);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  function invalidateCopyFeedback() {
    copyRevision++; keyCopied = false; copyError = false;
  }
  function dismissPlaintext() {
    mintedPlaintext = null; invalidateCopyFeedback();
  }
  async function copyPlaintext() {
    if (!mintedPlaintext || copyingKey) return;
    const value = mintedPlaintext;
    const revision = ++copyRevision;
    keyCopied = false; copyError = false; copyingKey = true;
    try {
      await navigator.clipboard.writeText(value);
      if (copyRevision === revision && mintedPlaintext === value) keyCopied = true;
    } catch {
      if (copyRevision === revision && mintedPlaintext === value) copyError = true;
    } finally { copyingKey = false; }
  }
</script>

<div class="px-6 py-10 max-w-4xl mx-auto">
  <div class="mb-8 flex items-baseline justify-between">
    <div class="space-y-2">
      <p class="page-eyebrow">{$ui("Settings · Developer")}</p>
      <h1 class="page-title">{$ui("API & AI access")}</h1>
    </div>
    {#if !showCreate}<button type="button" bind:this={createTrigger} class="btn btn-primary" onclick={openCreate} aria-controls="hash-api-key-create-form" aria-expanded="false">
      <Plus class="size-4" /> {$ui("Create API key")}
    </button>{/if}
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    {$ui("Connect any CRM, business application or automation through Hash’s HTTP API. Create and send a signature request from an approved blocks template with customer details and recipients, or send an already prepared document.")}
  </p>

  <section class="card p-5 mb-7 space-y-3" aria-labelledby="application-flow-heading">
    <h2 id="application-flow-heading" class="font-display text-lg text-text-primary">{$ui('Your application → Hash → your application')}</h2>
    <p class="text-sm leading-relaxed text-text-secondary">{$ui('Your application supplies the template, document data and recipients. Hash sends the invitation and handles document access, signing and evidence.')}</p>
    <p class="text-sm leading-relaxed text-text-secondary">{$ui('Hash sends the status events you select to a webhook URL in your application. Your integration decides how those events update its own records.')}</p>
    <a href="/settings/webhooks" class="btn btn-secondary">{$ui('Set up status webhooks')}</a>
    <p class="text-xs leading-relaxed text-text-secondary">{$ui('New keys start with read and authoring access. Enable workflow access only for integrations that need to send documents.')}</p>
  </section>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">{$ui('MCP is for AI document authoring and supported workspace settings. HTTP API integrations do not require MCP.')}</p>

  <div class="mb-7"><MCPConnectionGuide /></div>

  {#if error}
    <div role="alert" class="card p-4 mb-4 text-danger text-sm">{$ui(error)}</div>
  {/if}

  {#if mintedPlaintext}
    <div class="card p-5 mb-6 border border-success">
      <p class="font-mono uppercase tracking-widest text-xs text-text-muted mb-2">{$ui("New key, save now")}</p>
      <p class="text-sm mb-3">
        {$ui("Hash only shows the full key once. Copy it before navigating away.")}
      </p>
      <div class="flex items-center gap-2">
        <code class="flex-1 p-2 bg-bg-elevated rounded font-mono text-xs break-all">{mintedPlaintext}</code>
        <button class="btn btn-secondary" disabled={copyingKey} aria-busy={copyingKey} onclick={copyPlaintext}>
          <Copy class="size-4" /> {$ui(copyingKey ? "Copying…" : keyCopied ? "Copied" : "Copy")}
        </button>
      </div>
      {#if keyCopied}<p class="text-sm text-success mt-3" role="status">{$ui('Key copied.')}</p>{/if}
      {#if copyError}<p class="text-sm text-danger mt-3" role="alert">{$ui('Copy failed. Select the key and copy it manually.')}</p>{/if}
      <button class="btn btn-secondary mt-3" onclick={dismissPlaintext}>{$ui("I saved it")}</button>
    </div>
  {/if}

  {#if showCreate}
    <form id="hash-api-key-create-form" onsubmit={create} class="card p-5 mb-6" aria-label={$ui('Create API key')} aria-busy={creating}>
      <h2 class="font-medium text-lg mb-2">{$ui("Create API key")}</h2>
      <p class="text-sm text-text-secondary mb-5">{$ui("Give the key a name and select its permissions.")}</p>
      <label for="hash-api-key-name" class="block text-sm font-medium mb-2">{$ui('Name')}</label>
      <input
        id="hash-api-key-name" bind:this={nameInput} required maxlength="200" disabled={creating} aria-describedby="hash-api-key-input-help"
        type="text"
        bind:value={newName}
        placeholder={$ui('Name (e.g. Sales assistant)')}
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm mb-4"
      />
      <fieldset class="space-y-2 mb-4" disabled={creating}>
        <legend class="text-xs text-text-secondary font-medium mb-2">{$ui("Permissions")}</legend>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={scopes.read} />
          <span>read</span>
          <span class="text-text-muted text-xs">{$ui("(read documents, templates and status)")}</span>
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={scopes.authoring} />
          <span>write:authoring</span>
          <span class="text-text-muted text-xs">{$ui("(create and edit documents)")}</span>
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={scopes.workflow} />
          <span>write:workflow</span>
          <span class="text-text-muted text-xs">{$ui("(allow an integration to send documents)")}</span>
        </label>
        <p class="text-xs text-text-muted leading-relaxed">
          {$ui("AI authoring uses the default read and authoring permissions. Sending signature requests through the API also requires workflow access. MCP access depends on your plan.")}
        </p>
      </fieldset>
      <p id="hash-api-key-input-help" class="text-sm text-text-secondary mb-4 min-h-5" role="status">{missingInput ? $ui(missingInput) : $ui('Ready to create this key.')}</p>
      <div class="flex gap-2">
        <button type="submit" class="btn btn-primary" aria-describedby="hash-api-key-input-help" disabled={creating || !!missingInput}>
          {$ui(creating ? 'Creating…' : 'Create API key')}
        </button>
        <button type="button" class="btn btn-secondary" disabled={creating} onclick={closeCreate}>{$ui("Cancel")}</button>
      </div>
    </form>
  {/if}

  {#if loading}
    <p class="text-text-muted">{$ui("Loading…")}</p>
  {:else if keys.length === 0}
    <div class="card p-12 text-center">
      <Key class="size-8 mx-auto text-text-muted mb-3" />
      <p class="font-display text-xl font-extralight">{$ui("No API keys yet")}</p>
      <p class="text-text-secondary text-sm mt-2">{$ui("Mint your first key for automation or MCP access.")}</p>
    </div>
  {:else}
    <div class="card overflow-hidden">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">{$ui("Name")}</th>
            <th class="text-left px-4 py-3 font-medium">{$ui("Prefix")}</th>
            <th class="text-left px-4 py-3 font-medium">{$ui("Scopes")}</th>
            <th class="text-left px-4 py-3 font-medium">{$ui("Last used")}</th>
            <th class="text-right px-4 py-3 font-medium">{$ui("Actions")}</th>
          </tr>
        </thead>
        <tbody>
          {#each keys as k (k.id)}
            <tr class="border-b border-border-light last:border-0">
              <td class="px-4 py-3">{k.name}</td>
              <td class="px-4 py-3 font-mono text-xs">{k.key_prefix}…</td>
              <td class="px-4 py-3">
                <div class="flex gap-1 flex-wrap">
                  {#each k.scopes as sc (sc)}
                    <span class="px-1.5 py-0.5 rounded bg-bg-elevated text-xs font-mono">{sc}</span>
                  {/each}
                </div>
              </td>
              <td class="px-4 py-3 text-text-muted text-xs">
                {k.last_used_at ? new Date(k.last_used_at).toLocaleString($staffLocale === 'sv' ? 'sv-SE' : 'en-GB') : $ui('never')}
              </td>
              <td class="px-4 py-3 text-right">
                <button class="text-danger hover:underline text-xs inline-flex items-center gap-1" onclick={() => revoke(k.id)}>
                  <Trash2 class="size-3" /> {$ui("Revoke")}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <DocumentAIAccessSettings />
</div>
