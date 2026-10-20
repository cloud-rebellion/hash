<script lang="ts">
  import { onDestroy } from 'svelte';

  let { compact = false }: { compact?: boolean } = $props();

  let busy = $state(false);
  let error = $state<string | null>(null);
  let disposed = false;
  let request: { controller: AbortController; timer: ReturnType<typeof setTimeout> } | null = null;

  function dispose() {
    disposed = true;
    if (request) {
      clearTimeout(request.timer);
      request.controller.abort();
    }
  }
  onDestroy(dispose);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || disposed) return;
    busy = true;
    error = null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    request = { controller, timer };
    try {
      // CORS mode preserves the real Origin on this POST under no-referrer.
      const response = await fetch('/auth/logout', {
        method: 'POST',
        mode: 'cors',
        credentials: 'same-origin',
        headers: { Accept: 'text/html' },
        redirect: 'follow',
        signal: controller.signal
      });
      if (!response.ok || controller.signal.aborted) throw new Error('Logout was not confirmed');
      if (!disposed) window.location.assign('/');
    } catch {
      if (!disposed) {
        error = 'Unable to confirm sign out. Please try again.';
        busy = false;
      }
    } finally {
      clearTimeout(timer);
      if (request?.controller === controller) request = null;
    }
  }
</script>

<form method="POST" action="/auth/logout" onsubmit={submit} class="inline shrink-0" aria-busy={busy}>
  <button class="btn btn-secondary {compact ? 'btn-sm' : ''}" type="submit" disabled={busy}>
    {busy ? 'Signing out…' : 'Sign out everywhere'}
  </button>
  {#if error}
    <p class="text-xs text-danger mt-1" role="alert">{error}</p>
  {/if}
</form>
