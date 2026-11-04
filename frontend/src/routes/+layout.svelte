<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { FileSignature, LayoutDashboard, FileText, LayoutTemplate, ShieldCheck } from 'lucide-svelte';
  import { installRuntimeFlareBrowserCapture } from '$lib/flare-client';
  import ProfileMenu from '$lib/components/ProfileMenu.svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import { isStaffAuthPath } from '$lib/staffAuth';
  import { ui, staffLocale, initializeStaffPreferences } from '$lib/staffPreferences';

  let { children } = $props();

  let me = $state<{ email: string; role: string } | null>(null);

  // App chrome (the global nav) renders on the authenticated app surfaces only.
  // The public signer ceremony (/sign), completed files (/completed), legal pages, the auth screens, and the
  // marketing/login root render standalone with no nav.
  const path = $derived($page.url.pathname);
  const showChrome = $derived(
    !(path === '/' || isStaffAuthPath(path) || path.startsWith('/sign') || path.startsWith('/completed/') || path.startsWith('/notice/') || path.startsWith('/legal') || path.startsWith('/auth'))
  );

  const navItems = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/documents', label: 'Documents', icon: FileText },
    { href: '/templates', label: 'Templates', icon: LayoutTemplate },
    { href: '/verify', label: 'Verify', icon: ShieldCheck }
  ];

  function isActive(href: string): boolean {
    return path === href || path.startsWith(href + '/');
  }

  onMount(() => {
    const stopPreferences = initializeStaffPreferences();
    const stopFlareCapture = installRuntimeFlareBrowserCapture();
    return () => { stopFlareCapture(); stopPreferences(); };
  });

  $effect(() => {
    // The root layout survives client navigation between public and app pages.
    if (!showChrome) {
      me = null;
      return;
    }
    const controller = new AbortController();
    let current = true;
    void (async () => {
      try {
        const res = await fetch('/api/v1/me', {
          credentials: 'include', cache: 'no-store', signal: controller.signal
        });
        const identity = res.ok ? await res.json() : null;
        if (current) me = identity;
      } catch {
        if (current) me = null;
      }
    })();
    return () => {
      current = false;
      controller.abort();
    };
  });
</script>

<svelte:head>
  <title>{showChrome || path === '/' || isStaffAuthPath(path) || path.startsWith('/auth') ? 'Hash' : 'Document'}</title>
</svelte:head>

{#if showChrome}
  <div lang={$staffLocale} class="min-h-screen flex flex-col">
    <header class="border-b border-border-light bg-bg-surface">
      <div class="max-w-6xl mx-auto px-6 min-h-14 py-2 min-w-0 flex flex-wrap items-center justify-between gap-2 sm:gap-6">
        <a href="/dashboard" class="flex items-center gap-2 shrink-0">
          <FileSignature class="size-5 text-accent" />
          <span class="font-display text-lg font-extralight tracking-tight">Hash</span>
        </a>
        <nav class="order-last basis-full sm:order-none sm:basis-auto min-w-0 flex flex-wrap items-center justify-center sm:justify-start gap-1 sm:flex-1">
          {#each navItems as item}
            <a
              href={item.href}
              aria-label={$ui(item.label)}
              class="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors {isActive(item.href)
                ? 'bg-accent/10 text-accent font-medium'
                : 'text-text-muted hover:text-text hover:bg-border-light/40'}"
            >
              <item.icon class="size-4" />
              <span class="hidden sm:inline">{$ui(item.label)}</span>
            </a>
          {/each}
        </nav>
        <div class="flex shrink-0 items-center gap-2">
          <ThemeToggle />
          <ProfileMenu email={me?.email} role={me?.role} currentPath={path} />
        </div>
      </div>
    </header>
    <main class="flex-1">
      {@render children()}
    </main>
  </div>
{:else}
  {@render children()}
{/if}
