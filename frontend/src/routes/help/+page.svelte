<script lang="ts">
  import { ArrowRight, FileSignature } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import MCPConnectionGuide from '$lib/components/MCPConnectionGuide.svelte';

  const steps = [
    { title: 'Create your design', body: 'Save a reusable template, start with a blank document or upload an existing PDF.', href: '/templates', action: 'Open templates' },
    { title: 'Prepare the agreement', body: 'Fill in the customer details, review the actual PDF and add the right signing parties and fields.', href: '/documents', action: 'Open documents' },
    { title: 'Send and follow progress', body: 'Send the prepared document for signature. Follow its status, comments and requested changes in the document.', href: '/documents', action: 'View documents' },
    { title: 'Keep the completed evidence', body: 'After completion, download the final PDF and audit certificate. Verification checks the retained signing evidence.', href: '/verify', action: 'Open verification' },
  ];
</script>

<div class="mx-auto max-w-6xl px-6 py-10 space-y-8">
  <div class="flex items-start gap-4">
    <span class="mt-1 flex size-12 shrink-0 items-center justify-center rounded-xl border border-border bg-bg-surface"><FileSignature class="size-6" /></span>
    <div class="space-y-2">
      <p class="page-eyebrow">{$ui('Documentation')}</p>
      <h1 class="page-title">{$ui('A clear path from draft to signature')}</h1>
      <p class="max-w-2xl text-sm leading-relaxed text-text-secondary">{$ui('Hash keeps document design, review, signing and evidence in one workspace. Start with your own wording and keep each customer agreement separate.')}</p>
    </div>
  </div>

  <section aria-label={$ui('How Hash works')} class="grid gap-4 sm:grid-cols-2">
    {#each steps as step, index}
      <div class="card flex flex-col p-6">
        <span class="mb-5 flex size-8 items-center justify-center rounded-full bg-bg-hover font-mono text-xs text-text-secondary">0{index + 1}</span>
        <h2 class="font-display text-lg text-text-primary">{$ui(step.title)}</h2>
        <p class="mt-2 mb-5 flex-1 text-sm leading-relaxed text-text-secondary">{$ui(step.body)}</p>
        <a href={step.href} class="inline-flex items-center gap-2 text-sm font-medium text-text-primary hover:underline">{$ui(step.action)} <ArrowRight class="size-4" /></a>
      </div>
    {/each}
  </section>

  <MCPConnectionGuide />

  <section class="card p-6" aria-labelledby="workspace-help-heading">
    <h2 id="workspace-help-heading" class="font-display text-lg text-text-primary">{$ui('Make the workspace yours')}</h2>
    <p class="mt-2 max-w-3xl text-sm leading-relaxed text-text-secondary">{$ui('Use Settings to manage your team, branding, integrations and evidence controls. Language is in the account menu; appearance controls are next to it.')}</p>
    <a href="/settings" class="btn btn-secondary mt-5">{$ui('Open settings')} <ArrowRight class="size-4" /></a>
  </section>
</div>
