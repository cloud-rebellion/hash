<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { listFields, listRecipients, savePDFSigningTemplate, type DocumentResponse } from '$lib/api/client';

  let { document, onSaved, onClose }: { document: DocumentResponse; onSaved: () => void; onClose: () => void } = $props();
  const sourceID = untrack(() => document.id);
  const sourceStamp = untrack(() => document.updated_at);
  let disposed = false;
  let loading = $state(true);
  let saving = $state(false);
  let error = $state<string | null>(null);
  let name = $state(untrack(() => `${document.name} (template)`));
  let fieldIDs: string[] = [];
  let parties = $state<{ recipient_id: string; role: string; label: string; source_name: string }[]>([]);
  const current = () => !disposed && document.id === sourceID && document.updated_at === sourceStamp && document.status === 'draft';

  onMount(async () => {
    try {
      const [fields, recipients] = await Promise.all([listFields(sourceID), listRecipients(sourceID)]);
      if (!current()) return;
      if (!fields.length || !fields.every((f) => f.document_id === sourceID && f.type === 'signature' && f.required && f.recipient_id)
        || !recipients.every((r) => r.document_id === sourceID)) {
        throw new Error('Place required signature fields for each party before saving this layout. Reusable layouts currently support signature fields only.');
      }
      fieldIDs = fields.map((f) => f.id);
      const owners = [...new Set(fields.map((f) => f.recipient_id!))];
      parties = owners.map((id, index) => {
        const owner = recipients.find((r) => r.id === id);
        if (!owner || ['cc', 'viewer'].includes(owner.role)) throw new Error('A signature field has no signing recipient. Refresh the draft and correct its assignments.');
        return { recipient_id: id, role: index === 0 ? 'provider' : index === 1 ? 'client' : `party_${index + 1}`,
          label: index === 0 ? 'Provider' : index === 1 ? 'Client' : `Party ${index + 1}`, source_name: owner.name };
      });
    } catch (e) { if (current()) error = (e as Error).message; }
    finally { if (!disposed) loading = false; }
  });
  onDestroy(() => { disposed = true; });

  async function save(event: Event) {
    event.preventDefault();
    if (!current() || loading || saving || !parties.length) return;
    const submitted = parties.map(({ recipient_id, role, label }) => ({ recipient_id, role: role.trim(), label: label.trim() }));
    if (new Set(submitted.map((p) => p.role)).size !== submitted.length
      || submitted.some((p) => !/^[a-z][a-z0-9_-]{0,63}$/.test(p.role) || ['cc', 'viewer'].includes(p.role) || !p.label)) {
      error = 'Give each party a distinct role and a label.';
      return;
    }
    saving = true;
    error = null;
    try {
      await savePDFSigningTemplate(sourceID, { name: name.trim(), expected_updated_at: sourceStamp, expected_field_ids: [...fieldIDs], parties: submitted });
      if (current()) onSaved();
    } catch (e) { if (current()) error = (e as Error).message; }
    finally { if (!disposed) saving = false; }
  }
</script>

<section class="card p-6 mb-6" aria-label="Save PDF signing layout">
  <h2 class="font-display text-lg mb-2">Save PDF signing layout</h2>
  <p class="text-sm text-text-secondary mb-4">The PDF text and signature positions are reused. Choose a name for each party slot; new contracts ask for fresh names and email addresses.</p>
  {#if document.updated_at !== sourceStamp || document.status !== 'draft'}
    <p role="alert" class="text-sm text-danger mb-4">The draft changed. Close this form and reopen it to review the current layout.</p>
  {/if}
  {#if loading}
    <p>Loading signature assignments…</p>
  {:else}
    <form onsubmit={save} class="space-y-4">
      <label class="block text-sm">Template name
        <input bind:value={name} required maxlength="200" disabled={saving} class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" />
      </label>
      {#each parties as party (party.recipient_id)}
        <fieldset class="border border-border-light rounded-md p-4 space-y-2" disabled={saving}>
          <legend class="text-sm px-1">Signature positions currently assigned to {party.source_name}</legend>
          <label class="block text-sm">Party label <input bind:value={party.label} required maxlength="100" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
          <label class="block text-sm">Party role <input bind:value={party.role} required pattern={'[a-z][a-z0-9_-]{0,63}'} maxlength="64" class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
        </fieldset>
      {/each}
      {#if error}<p role="alert" class="text-sm text-danger">{error}</p>{/if}
      <div class="flex gap-2">
        <button class="btn btn-primary" type="submit" disabled={saving || !parties.length || document.updated_at !== sourceStamp || document.status !== 'draft'}>{saving ? 'Saving…' : 'Save template'}</button>
        <button class="btn btn-secondary" type="button" disabled={saving} onclick={onClose}>Cancel</button>
      </div>
    </form>
  {/if}
</section>
