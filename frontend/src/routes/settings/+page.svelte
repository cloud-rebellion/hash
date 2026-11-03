<script lang="ts">
  import { KeyRound, Webhook, Receipt, Palette, ShieldCheck, Scale, UserSearch, Bot, Users, Link2, ArrowUpRight, Mail } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import MCPConnectionGuide from '$lib/components/MCPConnectionGuide.svelte';

  const groups = [
    { title: 'Workspace', description: 'People, presentation and your plan.', items: [
      { href: '/settings/members', label: 'Members & roles', desc: 'Manage who can view, prepare and send documents.', icon: Users },
      { href: '/settings/branding', label: 'Branding', desc: 'Choose your workspace logo, colors and fonts.', icon: Palette },
      { href: '/settings/email', label: 'Email content', desc: 'Edit document email content and preview it with sample data.', icon: Mail },
      { href: '/settings/billing', label: 'Plans & invoices', desc: 'Review subscriptions, quotas and invoices.', icon: Receipt },
    ] },
    { title: 'Documents & signing', description: 'Signing rules and your authority to sign.', items: [
      { href: '/settings/signing-policies', label: 'Signing workflows and policies', desc: 'Review owner-approved rules; execution is unavailable.', icon: ShieldCheck },
      { href: '/settings/signing-authority', label: 'My signing authority', desc: 'Review your named authority, limits and revocation.', icon: KeyRound },
      { href: '/settings/eidas-rules', label: 'Signature levels', desc: 'Simple signatures are active; AES and QES are unavailable.', icon: Scale },
    ] },
    { title: 'Connections & automation', description: 'Connect Hash with your applications and AI tools.', items: [
      { href: '/settings/api-keys', label: 'API & AI access', desc: 'Workspace owners manage scoped API and MCP access.', icon: KeyRound },
      { href: '/settings/webhooks', label: 'Webhooks', desc: 'Deliver signed status updates to another application.', icon: Webhook },
      { href: '/settings/ai', label: 'AI provider', desc: 'Configure the model provider used by AI features.', icon: Bot },
      { href: '/settings/integrations/brightcrm', label: 'BrightCRM connection', desc: 'Manage an optional CRM account connection.', icon: Link2 },
    ] },
    { title: 'Privacy & evidence', description: 'Privacy requests, compliance records and audit checks.', items: [
      { href: '/settings/compliance', label: 'Compliance kit', desc: 'Review compliance records and configured advisory flags.', icon: ShieldCheck },
      { href: '/settings/dsr', label: 'Data subject rights', desc: 'Manage requests for access, correction and erasure.', icon: UserSearch },
      { href: '/settings/audit-chain', label: 'Audit chain verification', desc: 'Check the integrity of the retained event chain.', icon: ShieldCheck },
    ] },
  ];
</script>

<div class="mx-auto max-w-6xl px-6 py-10 space-y-8">
  <div class="space-y-2">
    <p class="page-eyebrow">{$ui('Workspace')}</p>
    <h1 class="page-title">{$ui('Settings')}</h1>
    <p class="max-w-2xl text-sm text-text-secondary">{$ui('Find the controls for your workspace in one place. Some changes require an owner.')}</p>
  </div>

  <div class="grid gap-5 lg:grid-cols-2">
    {#each groups as group (group.title)}
      <section class="card overflow-hidden">
        <div class="border-b border-border bg-bg-elevated px-5 py-4">
          <h2 class="font-display text-lg text-text-primary">{$ui(group.title)}</h2>
          <p class="mt-1 text-xs text-text-secondary">{$ui(group.description)}</p>
        </div>
        <div class="divide-y divide-border">
          {#each group.items as item (item.href)}
            <a href={item.href} class="group flex items-start gap-3 px-5 py-4 transition-colors hover:bg-bg-hover focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-accent">
              <span class="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated"><item.icon class="size-4" /></span>
              <div class="min-w-0 flex-1">
                <span class="text-sm font-medium text-text-primary">{$ui(item.label)}</span>
                <p class="mt-1 text-xs leading-relaxed text-text-secondary">{$ui(item.desc)}</p>
              </div>
              <ArrowUpRight class="mt-1 size-4 shrink-0 text-text-secondary" />
            </a>
          {/each}
        </div>
      </section>
    {/each}
  </div>

  <MCPConnectionGuide />
</div>
