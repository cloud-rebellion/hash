<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listMembers, updateMemberRole, getMe, inviteMember, APIError, type Member, type MemberRole } from '$lib/api/client';
  import { Users, ShieldCheck } from 'lucide-svelte';

  let members = $state<Member[]>([]);
  let myRole = $state('');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let savingId = $state<string | null>(null);
  let inviteEmail = $state('');
  let inviteName = $state('');
  let inviteRole = $state<MemberRole>('sender');
  let inviteBusy = $state(false);
  let inviteError = $state<string | null>(null);
  let inviteMessage = $state<string | null>(null);
  let disposed = false;
  let invitationRequest: { controller: AbortController; timer: ReturnType<typeof setTimeout> } | null = null;

  const ROLES: { value: MemberRole; label: string; desc: string }[] = [
    { value: 'owner', label: 'Owner', desc: 'Full access incl. org settings + members' },
    { value: 'sender', label: 'Sender', desc: 'Create, edit, and send documents' },
    { value: 'viewer', label: 'Viewer', desc: 'Read-only access' },
  ];
  const isOwner = $derived(myRole === 'owner');

  async function refresh() {
    loading = true;
    try {
      const [ms, me] = await Promise.all([listMembers(), getMe().catch(() => null)]);
      members = ms;
      myRole = me?.role ?? '';
      error = null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  function disposeInvitation() {
    disposed = true;
    if (invitationRequest) {
      clearTimeout(invitationRequest.timer);
      invitationRequest.controller.abort();
    }
  }
  onDestroy(disposeInvitation);

  async function sendInvitation(event: SubmitEvent) {
    event.preventDefault();
    if (!isOwner || inviteBusy || disposed) return;
    inviteError = null;
    inviteMessage = null;
    if (!inviteEmail.trim() || !inviteName.trim()) { inviteError = 'Enter the member’s name and email address.'; return; }
    inviteBusy = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    invitationRequest = { controller, timer };
    try {
      await inviteMember({ email: inviteEmail, name: inviteName, role: inviteRole }, controller.signal);
      if (disposed || controller.signal.aborted) return;
      inviteMessage = 'Invitation request accepted. Eligible accounts receive a password setup email.';
      inviteEmail = ''; inviteName = ''; inviteRole = 'sender';
      await refresh();
    } catch (failure) {
      if (!disposed) {
        inviteError = failure instanceof APIError ? failure.message : 'The invitation request could not be confirmed. Please try again.';
        if (failure instanceof APIError && failure.status === 403) await refresh();
      }
    } finally {
      clearTimeout(timer);
      if (invitationRequest?.controller === controller) invitationRequest = null;
      if (!disposed) inviteBusy = false;
    }
  }

  async function changeRole(m: Member, role: string) {
    if (role === m.role) return;
    savingId = m.id;
    error = null;
    try {
      const updated = await updateMemberRole(m.id, role);
      members = members.map((x) => (x.id === m.id ? updated : x));
    } catch (e) {
      error = (e as Error).message;
      await refresh(); // re-sync the select back to the server's value
    } finally {
      savingId = null;
    }
  }

  function roleLabel(role: string): string {
    return ROLES.find((r) => r.value === role)?.label ?? role;
  }
</script>

<div class="px-6 py-10 max-w-4xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · Team</p>
    <h1 class="page-title">Members &amp; roles</h1>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Roles control what each person can do. <strong>Owners</strong> manage org
    settings, billing, integrations, and members. <strong>Senders</strong> create
    and send documents. <strong>Viewers</strong> have read-only access. Only an
    owner can change roles.
    Members use their own verified email and password to sign in. Owners can invite
    colleagues, who choose their own password through an email link.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  {#if isOwner}
    <section class="card p-5 mb-6" aria-labelledby="invite-member-title">
      <h2 id="invite-member-title" class="font-display font-extralight text-lg mb-2">Invite a member</h2>
      <p class="text-sm text-text-secondary mb-4">Choose their workspace role. They set their own password.</p>
      {#if inviteError}<p class="text-sm text-danger mb-4" role="alert">{inviteError}</p>{/if}
      {#if inviteMessage}<p class="text-sm text-text-secondary mb-4" role="status" aria-live="polite">{inviteMessage}</p>{/if}
      <form method="POST" action="/api/v1/members" onsubmit={sendInvitation} aria-busy={inviteBusy}>
        <fieldset disabled={inviteBusy} class="space-y-4">
          <div class="grid sm:grid-cols-2 gap-4">
            <div>
              <label for="invite-member-name" class="block text-sm font-medium mb-1.5">Name</label>
              <input id="invite-member-name" name="name" type="text" autocomplete="off" maxlength="200" required bind:value={inviteName} class="w-full rounded-md border border-border-light bg-bg-elevated px-3 py-2 text-sm focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent" />
            </div>
            <div>
              <label for="invite-member-email" class="block text-sm font-medium mb-1.5">Email</label>
              <input id="invite-member-email" name="email" type="email" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="254" required bind:value={inviteEmail} class="w-full rounded-md border border-border-light bg-bg-elevated px-3 py-2 text-sm focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent" />
            </div>
          </div>
          <div>
            <label for="invite-member-role" class="block text-sm font-medium mb-1.5">Role</label>
            <select id="invite-member-role" name="role" bind:value={inviteRole} class="w-full sm:w-56 rounded-md border border-border-light bg-bg-elevated px-3 py-2 text-sm focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent">
              {#each ROLES as role}<option value={role.value}>{role.label}</option>{/each}
            </select>
          </div>
          <button type="submit" class="btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed" disabled={inviteBusy}>{inviteBusy ? 'Requesting invitation…' : 'Send invitation'}</button>
        </fieldset>
      </form>
    </section>
  {/if}

  <section class="card p-5">
    <h2 class="font-display font-extralight text-lg mb-4 flex items-center gap-2">
      <Users class="size-4" /> Org members
    </h2>
    {#if loading}
      <p class="text-text-muted text-sm">Loading...</p>
    {:else if members.length === 0}
      <p class="text-text-muted text-sm">No members yet.</p>
    {:else}
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
            <th class="py-2">Member</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border-light">
          {#each members as m (m.id)}
            <tr>
              <td class="py-3">
                <div class="font-medium">
                  {m.name || m.email}
                  {#if m.is_self}<span class="text-xs text-text-muted">(you)</span>{/if}
                </div>
                <div class="text-xs text-text-muted">{m.email}</div>
              </td>
              <td>
                {#if isOwner}
                  <select
                    class="px-3 py-1.5 rounded-md border border-border-light bg-bg-elevated text-sm"
                    value={m.role}
                    disabled={savingId === m.id}
                    onchange={(e) => changeRole(m, (e.currentTarget as HTMLSelectElement).value)}
                  >
                    {#each ROLES as r}
                      <option value={r.value}>{r.label}</option>
                    {/each}
                  </select>
                {:else}
                  <span class="inline-flex items-center gap-1 text-sm capitalize">
                    {#if m.role === 'owner'}<ShieldCheck class="size-3 text-accent" />{/if}
                    {roleLabel(m.role)}
                  </span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if !isOwner}
        <p class="text-xs text-text-muted mt-4">Only owners can change roles.</p>
      {/if}
    {/if}
  </section>
</div>
