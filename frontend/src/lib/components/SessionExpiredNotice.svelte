<script lang="ts">
  import { page } from '$app/stores';
  import { ui, staffLocale } from '$lib/staffPreferences';
  import { sessionExpiredLoginUrl, loginUrlFor } from '$lib/sessionExpiry';
  import { needsSession } from '$lib/routeSurface';

  let dialog = $state.raw<HTMLDialogElement>();
  let checking = $state(false);
  let stillSignedOut = $state(false);

  // Shown only on a page that needs a session, and the link is computed from the page being shown.
  const visible = $derived($sessionExpiredLoginUrl !== null && needsSession($page.url.pathname));
  const signInHref = $derived(loginUrlFor($page.url.pathname, $page.url.search));

  // A native modal makes the page behind it inert and traps focus. The dialog cannot be dismissed
  // with Escape; only a successful /api/v1/me check (here, or from the focus probe) clears it.
  $effect(() => {
    if (visible) stillSignedOut = false;
  });

  $effect(() => {
    if (visible && dialog && !dialog.open) dialog.showModal();
    else if (!visible && dialog?.open) dialog.close();
  });

  function closed() {
    if (visible && dialog && !dialog.open) dialog.showModal();
  }

  async function checkAgain() {
    if (checking) return;
    checking = true; stillSignedOut = false;
    try {
      // The session guard wraps fetch: a 2xx from /me clears the notice, a 401 keeps it.
      await fetch('/api/v1/me', { credentials: 'include', cache: 'no-store' });
    } catch { /* offline: keep the notice */ }
    checking = false;
    stillSignedOut = $sessionExpiredLoginUrl !== null;
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
    <p id="session-expired-body" class="mt-2 text-sm text-text-muted">{$ui('Sign in again in a new tab, then check again. Unsaved changes stay on this page.')}</p>
    {#if stillSignedOut}
      <p class="mt-2 text-sm text-danger" role="status">{$ui('You are still signed out.')}</p>
    {/if}
    <div class="mt-4 flex flex-wrap gap-2">
      <a class="btn btn-primary" href={signInHref} target="_blank" rel="noopener noreferrer">{$ui('Sign in again')}</a>
      <button type="button" class="btn btn-secondary" onclick={checkAgain} disabled={checking} aria-busy={checking}>{$ui('Check again')}</button>
    </div>
  </dialog>
{/if}
