<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { FileSignature } from 'lucide-svelte';
  import { consumeStaffAuthToken, staffPasswordError, type StaffAuthMode } from '$lib/staffAuth';
  import { getStaffAuthStatus, loginWithPassword, registerWorkspace, verifyStaffEmail, forgotStaffPassword, resetStaffPassword, staffAuthErrorMessage } from '$lib/api/staffAuth';

  let { mode }: { mode: StaffAuthMode } = $props();
  let email = $state('');
  let name = $state('');
  let company = $state('');
  let password = $state('');
  let confirmation = $state('');
  let token = $state<string | null>(null);
  let busy = $state(false);
  let complete = $state(false);
  let error = $state<string | null>(null);
  let oidcEnabled = $state(false);
  let disposed = false;
  let request: { controller: AbortController; timer: ReturnType<typeof setTimeout> } | null = null;
  let statusRequest: { controller: AbortController; timer: ReturnType<typeof setTimeout> } | null = null;

  const copy = $derived({
    login: { title: 'Sign in to Hash', description: 'Use your email and password to open your workspace.', button: 'Sign in' },
    register: { title: 'Create your workspace', description: 'Start with your details. Verify your email before signing in.', button: 'Create workspace' },
    verify: { title: 'Verify your email', description: 'Enter the password you chose when creating your workspace, then verify your email.', button: 'Verify email' },
    forgot: { title: 'Reset your password', description: 'Enter your email to request a password reset link.', button: 'Send reset instructions' },
    reset: { title: 'Choose a new password', description: 'Your previous sessions will be signed out after the password is changed.', button: 'Save new password' }
  }[mode]);
  const newPassword = $derived(mode === 'register' || mode === 'reset');
  const tokenMode = $derived(mode === 'verify' || mode === 'reset');
  const inputClass = 'w-full rounded-md border border-border-light bg-bg-elevated px-3 py-2 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent disabled:opacity-60';
  const endpoint = $derived('/api/v1/auth/' + ({ login: 'login', register: 'register', verify: 'verify-email', forgot: 'forgot-password', reset: 'reset-password' }[mode]));

  function clearSecrets() { password = ''; confirmation = ''; token = null; }
  function dispose() {
    disposed = true;
    clearSecrets();
    for (const pending of [request, statusRequest]) {
      if (pending) { clearTimeout(pending.timer); pending.controller.abort(); }
    }
  }
  onDestroy(dispose);

  function initialise() {
    if (tokenMode) {
      try { token = consumeStaffAuthToken(window.location, window.history); }
      catch { token = null; }
      if (!token) error = 'Open the complete link from your latest email. This page needs a valid email link to continue.';
    }
    if (mode === 'login') {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10_000);
      statusRequest = { controller, timer };
      void getStaffAuthStatus(controller.signal).then(status => {
        if (!disposed && !controller.signal.aborted) oidcEnabled = status.oidc_enabled;
      }).catch(() => { /* Email sign-in remains usable; optional SSO stays hidden. */ }).finally(() => {
        clearTimeout(timer);
        if (statusRequest?.controller === controller) statusRequest = null;
      });
    }
  }
  onMount(initialise);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (disposed || busy || complete) return;
    error = null;
    if (tokenMode && !token) { error = 'Open a valid link from your latest email to continue.'; return; }
    if (mode !== 'verify' && !email.trim() && mode !== 'reset') { error = 'Enter your email address.'; return; }
    if (mode === 'login' || mode === 'verify' || newPassword) {
      const problem = staffPasswordError(password, newPassword ? confirmation : undefined);
      if (problem) { error = problem; return; }
    }
    if (mode === 'register' && (!name.trim() || !company.trim())) { error = 'Enter your name and company name.'; return; }
    busy = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    request = { controller, timer };
    try {
      if (mode === 'login') await loginWithPassword(email.trim(), password, controller.signal);
      else if (mode === 'register') await registerWorkspace(email.trim(), name.trim(), company.trim(), password, controller.signal);
      else if (mode === 'verify') await verifyStaffEmail(token!, password, controller.signal);
      else if (mode === 'forgot') await forgotStaffPassword(email.trim(), controller.signal);
      else await resetStaffPassword(token!, password, controller.signal);
      if (disposed || controller.signal.aborted) return;
      clearSecrets();
      complete = true;
      if (mode === 'login' || mode === 'verify') window.location.assign('/dashboard');
      else if (mode === 'reset') window.location.assign('/login');
    } catch (failure) {
      if (!disposed) { error = staffAuthErrorMessage(failure); complete = false; }
    } finally {
      clearTimeout(timer);
      if (request?.controller === controller) request = null;
      if (!disposed) busy = false;
    }
  }
</script>

<svelte:head>
  <title>{copy.title} · Hash</title>
  <meta name="referrer" content="no-referrer" />
  <meta name="robots" content="noindex, nofollow" />
</svelte:head>

<main class="min-h-screen flex items-center justify-center px-6 py-12">
  <div class="w-full max-w-md">
    <a href="/" class="mb-8 flex items-center justify-center gap-2" aria-label="Hash home">
      <FileSignature class="size-5 text-accent" aria-hidden="true" />
      <span class="font-display text-xl font-extralight tracking-tight">Hash</span>
    </a>
    <section class="card p-6 sm:p-8" aria-labelledby="staff-auth-title">
      <p class="page-eyebrow mb-3">Your workspace</p>
      <h1 id="staff-auth-title" class="font-display text-3xl font-extralight tracking-tight mb-3">{copy.title}</h1>
      <p class="text-sm text-text-secondary leading-relaxed mb-6">{copy.description}</p>

      {#if error}<p id="staff-auth-error" class="mb-4 text-sm text-danger" role="alert">{error}</p>{/if}
      {#if complete}
        <div class="text-sm text-text-secondary space-y-4" role="status" aria-live="polite">
          {#if mode === 'register'}
            <p>If registration can proceed, verification instructions have been queued. Check your inbox and open the email link to finish setting up your workspace.</p>
          {:else if mode === 'forgot'}
            <p>If this email has a Hash account, password reset instructions have been queued. Check your inbox for the link.</p>
          {:else if mode === 'reset'}
            <p>Your password has been changed. Sign in with your new password.</p>
          {:else}
            <p>Sign-in confirmed. Opening your workspace…</p>
          {/if}
          <a class="btn btn-secondary" href="/login">Back to sign in</a>
        </div>
      {:else}
        <form method="POST" action={endpoint} onsubmit={submit} aria-busy={busy} aria-describedby={error ? 'staff-auth-error' : undefined}>
          <fieldset disabled={busy} class="space-y-4">
            {#if mode === 'register'}
              <div><label for="staff-name" class="block text-sm font-medium mb-1.5">Your name</label><input id="staff-name" name="name" type="text" autocomplete="name" maxlength="200" required bind:value={name} class={inputClass} /></div>
              <div><label for="staff-company" class="block text-sm font-medium mb-1.5">Company name</label><input id="staff-company" name="company_name" type="text" autocomplete="organization" maxlength="200" required bind:value={company} class={inputClass} /></div>
            {/if}
            {#if mode === 'login' || mode === 'register' || mode === 'forgot'}
              <div><label for="staff-email" class="block text-sm font-medium mb-1.5">Email</label><input id="staff-email" name="email" type="email" autocomplete={mode === 'login' ? 'username' : 'email'} maxlength="254" spellcheck="false" autocapitalize="none" required bind:value={email} class={inputClass} /></div>
            {/if}
            {#if mode === 'login' || mode === 'verify' || newPassword}
              <div>
                <label for="staff-password" class="block text-sm font-medium mb-1.5">{newPassword ? 'New password' : 'Password'}</label>
                <input id="staff-password" name="password" type="password" autocomplete={newPassword ? 'new-password' : 'current-password'} minlength={newPassword ? 12 : undefined} maxlength="1024" required bind:value={password} class={inputClass} aria-describedby={newPassword ? 'staff-password-help' : undefined} />
                {#if newPassword}<p id="staff-password-help" class="text-xs text-text-secondary mt-2">Use at least 12 characters. A longer, unique passphrase works well.</p>{/if}
              </div>
            {/if}
            {#if newPassword}
              <div><label for="staff-confirmation" class="block text-sm font-medium mb-1.5">Confirm password</label><input id="staff-confirmation" name="password_confirmation" type="password" autocomplete="new-password" maxlength="1024" required bind:value={confirmation} class={inputClass} /></div>
            {/if}
            <button class="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed" type="submit" disabled={busy || (tokenMode && !token)}>{busy ? 'Please wait…' : copy.button}</button>
          </fieldset>
        </form>
      {/if}

      {#if mode === 'login'}
        <div class="mt-5 text-sm space-y-3">
          <a href="/forgot-password" class="block text-text-secondary underline underline-offset-4">Forgot your password?</a>
          <p class="text-text-secondary">New to Hash? <a href="/register" class="text-text-primary underline underline-offset-4">Create a workspace</a></p>
          {#if oidcEnabled}<a class="btn btn-secondary w-full" href="/auth/login" data-sveltekit-reload>Continue with single sign-on</a>{/if}
        </div>
      {:else if mode === 'reset'}
        <a href="/forgot-password" class="mt-5 block text-sm text-text-secondary underline underline-offset-4">Request a new reset link</a>
      {:else if mode === 'verify'}
        <a href="/register" class="mt-5 block text-sm text-text-secondary underline underline-offset-4">Back to create workspace</a>
      {:else}
        <p class="mt-5 text-sm text-text-secondary">Already have an account? <a href="/login" class="text-text-primary underline underline-offset-4">Sign in</a></p>
      {/if}
    </section>
  </div>
</main>
