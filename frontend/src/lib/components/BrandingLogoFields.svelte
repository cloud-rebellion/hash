<script lang="ts">
  import { ui } from '$lib/staffPreferences';

  let { supported, disabled = false, logoURL, logoAlt, onChange }: {
    supported: boolean;
    disabled?: boolean;
    logoURL: string;
    logoAlt: string;
    onChange: (patch: { logo_url?: string; logo_alt?: string }) => void;
  } = $props();

  function clearLogo() {
    if (disabled) return;
    onChange({ logo_url: '', logo_alt: '' });
  }
</script>

<section class="card p-5 mb-6" aria-labelledby="branding-logo-heading">
  <h2 id="branding-logo-heading" class="font-display font-extralight text-lg mb-4">{$ui('Document logo')}</h2>
  <fieldset disabled={disabled || !supported} class="space-y-3">
    <label class="block text-sm">
      <span class="text-xs uppercase tracking-widest text-text-muted font-mono">{$ui('Logo URL')}</span>
      <input type="url" value={logoURL} oninput={(event) => onChange({ logo_url: event.currentTarget.value })}
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm disabled:opacity-60" />
    </label>
    <label class="block text-sm">
      <span class="text-xs uppercase tracking-widest text-text-muted font-mono">{$ui('Logo alt text')}</span>
      <input type="text" value={logoAlt} oninput={(event) => onChange({ logo_alt: event.currentTarget.value })}
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm disabled:opacity-60" />
    </label>
  </fieldset>
  {#if !supported}
    <p class="text-sm text-text-secondary mt-3">{$ui('Logo URL editing is unavailable here. Add a local logo to your emails in Email design.')}</p>
    {#if logoURL.trim()}
      <p class="text-sm text-text-secondary mt-3">{$ui('Clear the saved logo URL, then save changes to keep editing document colors and fonts.')}</p>
      <button type="button" class="btn btn-secondary mt-2" {disabled} onclick={clearLogo}>{$ui('Clear logo URL')}</button>
    {/if}
  {/if}
  <a class="inline-block text-sm underline underline-offset-4 mt-3" href="/settings/email">{$ui('Open email design')}</a>
</section>
