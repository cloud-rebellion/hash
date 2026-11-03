<script lang="ts">
  import { ui } from '$lib/staffPreferences';
  import { isDocumentPurpose, type DocumentPurpose } from '$lib/documentPurpose';
  let { value, onChange, disabled = false, signingOnly = false, signingReason = 'This reviewed contract design requires Signing. Choose another design for a document or presentation.' }: { value: DocumentPurpose | ''; onChange: (value: DocumentPurpose | '') => void; disabled?: boolean; signingOnly?: boolean; signingReason?: string } = $props();
  function changed(event: Event) { const next = (event.currentTarget as HTMLSelectElement).value; if (!disabled && (next === '' || (isDocumentPurpose(next) && (!signingOnly || next === 'signing')))) onChange(next); }
</script>
<label class="block text-sm font-medium space-y-2">
  <span>{$ui('Use this document for')}</span>
  <select {disabled} {value} onchange={changed} required class="block w-full px-3 py-2.5 rounded-lg border border-border bg-bg-elevated text-sm">
    <option value="">{$ui('Choose a purpose')}</option>
    <option value="document" disabled={signingOnly}>{$ui('Document — edit and download')}</option>
    <option value="presentation" disabled={signingOnly}>{$ui('Presentation — present and download')}</option>
    <option value="signing">{$ui('Signing — recipients, fields and signatures')}</option>
  </select>
  <span class="block text-xs font-normal text-text-secondary">{$ui('Signing controls are available only for Signing. Changing purpose does not change the document content.')}</span>
  {#if signingOnly}<span class="block text-xs font-normal text-text-secondary">{$ui(signingReason)}</span>{/if}
</label>
