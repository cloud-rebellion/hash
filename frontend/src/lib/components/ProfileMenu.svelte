<script lang="ts">
  import { tick } from 'svelte';
  import { BookOpen, ChevronDown, KeyRound, Settings, UserRound } from 'lucide-svelte';
  import LogoutButton from './LogoutButton.svelte';
  import { ui, staffLocale, setStaffLocale } from '$lib/staffPreferences';

  let { email = '', role = '', currentPath = '' }: { email?: string; role?: string; currentPath?: string } = $props();
  let open = $state(false);
  let container: HTMLDivElement;
  let trigger: HTMLButtonElement;
  let panel: HTMLDivElement;

  $effect(() => { currentPath; open = false; });

  function closeMenu(restoreFocus = false) {
    open = false;
    if (restoreFocus) trigger?.focus();
  }

  function outside(event: Event) {
    if (open && container && !container.contains(event.target as Node)) closeMenu();
  }

  async function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && open) {
      event.preventDefault();
      closeMenu(true);
      return;
    }
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    if (event.target === trigger) {
      event.preventDefault();
      open = true;
      await tick();
      if (!open) return;
      const items = panel?.querySelectorAll<HTMLAnchorElement | HTMLButtonElement>('a[href], button:not([disabled])');
      if (items?.length) items[event.key === 'ArrowDown' ? 0 : items.length - 1].focus();
      return;
    }
    if (!open || !panel?.contains(event.target as Node)) return;
    const items = Array.from(panel.querySelectorAll<HTMLAnchorElement | HTMLButtonElement>('a[href], button:not([disabled])'));
    const index = items.indexOf(event.target as HTMLAnchorElement | HTMLButtonElement);
    if (index < 0 || !items.length) return;
    event.preventDefault();
    items[(index + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length].focus();
  }
</script>

<svelte:window onfocusin={outside} onpointerdown={outside} onkeydown={handleKeydown} />

<div bind:this={container} class="relative shrink-0">
  <button bind:this={trigger} type="button" class="flex items-center gap-2 rounded-full border border-border bg-bg-elevated px-2 py-1.5 text-sm text-text-primary hover:bg-bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent" aria-label={$ui('Account menu') + (email ? ': ' + email : '')} aria-expanded={open} aria-controls="hash-account-panel" onclick={() => { open = !open; }}>
    <span class="flex size-7 items-center justify-center rounded-full bg-accent text-accent-foreground"><UserRound class="size-4" /></span>
    <span class="hidden max-w-44 truncate sm:inline" title={email || undefined}>{email || $ui('Account')}</span>
    <ChevronDown class="size-3.5" />
  </button>
  <div bind:this={panel} id="hash-account-panel" hidden={!open} class="absolute right-0 z-50 mt-3 w-72 max-w-[85vw] rounded-xl border border-border bg-bg-surface p-2 shadow-xl">
      <div class="border-b border-border px-3 py-3">
        <p class="break-words text-sm font-medium text-text-primary">{email || $ui('Your account')}</p>
        {#if role}<p class="mt-1 text-xs capitalize text-text-secondary">{$ui(role)}</p>{/if}
      </div>
      <nav aria-label={$ui('Account')} class="space-y-1 py-2">
        <a href="/settings" onclick={() => closeMenu()} class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-primary hover:bg-bg-hover"><Settings class="size-4" /> {$ui('Settings')}</a>
        {#if role === 'owner'}
          <a href="/settings/api-keys" onclick={() => closeMenu()} class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-primary hover:bg-bg-hover"><KeyRound class="size-4" /> {$ui('API access')}</a>
        {:else}
          <a href="/help#mcp" onclick={() => closeMenu()} class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-primary hover:bg-bg-hover"><KeyRound class="size-4" /> {$ui('API & MCP')}</a>
        {/if}
        <a href="/help" onclick={() => closeMenu()} class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-primary hover:bg-bg-hover"><BookOpen class="size-4" /> {$ui('Documentation')}</a>
      </nav>
      <div class="space-y-3 border-t border-border px-3 py-3">
        <label for="hash-staff-language" class="block text-xs font-medium text-text-secondary">
          {$ui('Language')}
          <select id="hash-staff-language" class="mt-1.5 block w-full rounded-lg border border-border bg-bg-elevated px-2 py-2 text-sm text-text-primary" value={$staffLocale} onchange={(event) => setStaffLocale(event.currentTarget.value === 'sv' ? 'sv' : 'en')}>
            <option value="en">English</option><option value="sv">Svenska</option>
          </select>
        </label>
      </div>
      <div class="border-t border-border px-1 pt-2 [&_form]:w-full [&_button]:w-full [&_button]:justify-start [&_button]:border-transparent [&_button]:bg-transparent">
        <LogoutButton compact />
      </div>
  </div>
</div>
