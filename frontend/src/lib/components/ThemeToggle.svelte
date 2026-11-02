<script lang="ts">
  import { Sun, Moon } from 'lucide-svelte';
  import { ui, staffResolvedTheme, setStaffTheme } from '$lib/staffPreferences';

  function chooseTheme(theme: 'light' | 'dark') {
    setStaffTheme(theme);
  }
</script>

<div role="group" aria-label={$ui('Appearance')} class="flex shrink-0 items-center gap-0.5 rounded-full border border-border bg-bg-elevated p-1">
  <button type="button" aria-label={$ui('Use light appearance')} title={$ui('Use light appearance')} aria-pressed={$staffResolvedTheme === 'light'} onclick={() => chooseTheme('light')} class="flex size-8 items-center justify-center rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent {$staffResolvedTheme === 'light' ? 'bg-accent text-accent-foreground' : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary'}">
    <Sun class="size-4" aria-hidden="true" />
  </button>
  <button type="button" aria-label={$ui('Use dark appearance')} title={$ui('Use dark appearance')} aria-pressed={$staffResolvedTheme === 'dark'} onclick={() => chooseTheme('dark')} class="flex size-8 items-center justify-center rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent {$staffResolvedTheme === 'dark' ? 'bg-accent text-accent-foreground' : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary'}">
    <Moon class="size-4" aria-hidden="true" />
  </button>
</div>
