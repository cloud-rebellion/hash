<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { ui, staffLocale } from '$lib/staffPreferences';
  import { sessionExpiredLoginUrl, expiredLoginUrlFor } from '$lib/sessionExpiry';
  import { needsSession } from '$lib/routeSurface';

  let dialog = $state.raw<HTMLDialogElement>();
  let mounted = $state(false);
  let redirectedTo = $state<string | null>(null);
  onMount(() => { mounted = true; });

  // Shown only on a page that needs a session, and the link is computed from the page being shown.
  const visible = $derived($sessionExpiredLoginUrl !== null && needsSession($page.url.pathname));
  const signInHref = $derived(expiredLoginUrlFor($page.url.pathname, $page.url.search));

  // Replace the expired page in this tab. A delayed or cancelled navigation must
  // not leave the old workspace interactive. The modal remains a same-tab sign-in
  // fallback; ordinary beforeunload protection is not bypassed.
  $effect(() => {
    if (!mounted || !visible) { redirectedTo = null; return; }
    const target = signInHref;
    if (redirectedTo === target) return;
    redirectedTo = target;
    try { window.location.replace(target); } catch { /* retain the visible sign-in link */ }
  });

  $effect(() => {
    if (visible && dialog && !dialog.open) dialog.showModal();
    else if (!visible && dialog?.open) dialog.close();
  });

  function closed() {
    if (visible && dialog && !dialog.open) dialog.showModal();
  }

</script>

{#if visible}
  <dialog
    bind:this={dialog}
    lang={$staffLocale}
    aria-labelledby="session-expired-title"
    aria-describedby="session-expired-body"
    oncancel={(event) => event.preventDefault()}
    onclose={closed}
    class="card m-auto w-full max-w-md p-6 backdrop:bg-black/50"
  >
    <h2 id="session-expired-title" class="font-display text-lg">{$ui('Your session has expired')}</h2>
    <p id="session-expired-body" class="mt-2 text-sm text-text-muted">{$ui('Your session has expired. Please sign in again.')}</p>
    <div class="mt-4 flex flex-wrap gap-2">
      <a class="btn btn-primary" href={signInHref} data-sveltekit-reload>{$ui('Sign in again')}</a>
    </div>
  </dialog>
{/if}
