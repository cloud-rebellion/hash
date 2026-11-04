<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { ArrowLeft, Check, ChevronRight, Code2, Eye, FileText, Mail, RotateCcw, Save, ShieldCheck, Sparkles, Palette, Upload, X } from 'lucide-svelte';
  import { ui } from '$lib/staffPreferences';
  import { createEmailTemplateEditor, canEditEmailTemplate, emailDraftProblems, emailFieldBytes, emailPreviewDocument, type EmailTemplateKind, type EmailField } from '$lib/emailTemplateEditor';
  import { listEmailTemplates, previewEmailTemplate, saveEmailTemplate, proposeEmailDesign } from '$lib/api/emailTemplates';

  import { emailDesignDraft, localEmailLogo, type EmailDesign } from '$lib/emailDesign';
  import EmailTemplateSampleSend from './EmailTemplateSampleSend.svelte';

  let { controller }: { controller?: ReturnType<typeof createEmailTemplateEditor> } = $props();
  const editor = untrack(() => controller) ?? createEmailTemplateEditor({ load: listEmailTemplates, preview: previewEmailTemplate, save: saveEmailTemplate, propose: proposeEmailDesign });
  let format = $state<'html' | 'text'>('html');
  const info: Record<EmailTemplateKind, { name: string; description: string }> = {
    'email.invite': { name: 'Signature invitation', description: 'When a recipient is invited to review and sign.' },
    'email.reminder': { name: 'Signing reminder', description: 'A reminder for a recipient who has not finished.' },
    'email.completed_signer': { name: 'Completed · recipient', description: 'Confirmation for a recipient after completion.' },
    'email.completed_sender': { name: 'Completed · sender', description: 'Confirmation for the sender after completion.' },
    'email.declined': { name: 'Signature declined', description: 'When a recipient declines the document.' },
    'email.changes_requested': { name: 'Changes requested', description: 'When a recipient asks the sender for changes.' },
    'email.new_comment': { name: 'New comment', description: 'A notification about a document comment.' },
    'email.voided': { name: 'Document voided', description: 'When a sent document is voided.' },
    'email.quota_warning_80': { name: 'Usage warning', description: 'When the workspace approaches its plan limit.' },
  };
  const selectedInfo = $derived($editor.selected ? info[$editor.selected.kind] : null);
  const problems: Partial<Record<EmailField, string>> = $derived($editor.catalog ? emailDraftProblems($editor.draft, $editor.catalog.limits) : {});
  const invalid = $derived(Object.keys(problems).length > 0);
  let prompt = $state('');
  let logoBusy = $state(false);
  let logoError = $state<string | null>(null);
  let alive = true;
  const design = $derived(emailDesignDraft($editor.draft.design_json));
  const activePreview = $derived($editor.proposal?.preview ?? $editor.preview);
  const busy = $derived($editor.busy !== null || logoBusy);
  const locked = $derived(busy || !$editor.authorized);
  const editable = $derived(canEditEmailTemplate($editor.selected));
  const editorLocked = $derived(locked || !editable);
  const previewHTML = $derived(activePreview ? emailPreviewDocument(activePreview.html) : '');
  onMount(() => { void editor.load(); return () => { alive = false; editor.dispose(); }; });

  function resetToBuiltIn() {
    if (editorLocked) return;
    editor.edit('subject_template', ''); editor.edit('html_template', ''); editor.edit('text_template', '');
  }

  function updateDesign(field: keyof EmailDesign, value: EmailDesign[keyof EmailDesign]) {
    if (editorLocked) return;
    editor.edit('design_json', JSON.stringify({ ...design, [field]: value }));
  }
  async function selectLogo(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0]; input.value = '';
    if (!file || editorLocked) return;
    const source = $editor.draft.design_json, kind = $editor.selected?.kind, revision = $editor.selected?.revision;
    logoBusy = true; logoError = null;
    try {
      const logo = await localEmailLogo(file);
      if (!alive || $editor.selected?.kind !== kind || $editor.selected?.revision !== revision || $editor.draft.design_json !== source) return;
      editor.edit('design_json', JSON.stringify({ ...design, logo, layout_html: design.layout_html.includes('{{logo}}') ? design.layout_html : '<div>{{logo}}</div>' + design.layout_html }));
    } catch { if (alive) logoError = 'Use a local PNG or JPEG logo up to 32 KiB and 512 pixels.'; }
    finally { if (alive) logoBusy = false; }
  }
</script>

<div class="mx-auto max-w-6xl space-y-6 px-5 py-8 sm:px-6 sm:py-10">
  <header class="space-y-3">
    <a class="inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text-primary" href="/settings"><ArrowLeft class="size-3" /> {$ui('Settings')}</a>
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div class="space-y-2">
        <p class="page-eyebrow">{$ui('Workspace · Email')}</p>
        <h1 class="page-title">{$ui('Email design')}</h1>
        <p class="max-w-2xl text-sm text-text-secondary">{$ui('Design your workspace emails. Hash keeps the required signing and security section.')}</p>
      </div>
      <div class="flex items-center gap-2 rounded-full border border-border px-3 py-1.5 text-xs text-text-secondary"><ShieldCheck class="size-3.5" /> {$ui('Owners only')}</div>
    </div>
  </header>

  <div class="flex items-start gap-3 rounded-xl border border-border bg-bg-elevated px-4 py-3 text-xs leading-relaxed text-text-secondary">
    <Mail class="mt-0.5 size-4 shrink-0" />
    <p>{$ui('Design, preview and test your emails. Configure this workspace’s own sender and SMTP server in Delivery settings.')} <a href="/settings/delivery" class="underline underline-offset-4">{$ui('Email delivery')}</a></p>
  </div>

  {#if $editor.error}
    <div class="rounded-xl border border-danger/40 bg-danger/5 p-4 text-sm" role="alert">
      <p class="text-danger">{$ui($editor.error)}</p>
      {#if $editor.conflict}<p class="mt-2 text-xs text-text-secondary">{$ui('Your draft is kept here. Reloading replaces it with the latest saved revision.')}</p>{/if}
      {#if $editor.conflict || !$editor.catalog || !$editor.authorized}<button type="button" class="btn btn-secondary mt-3" disabled={busy} onclick={() => editor.load()}><RotateCcw class="size-3.5" /> {$ui($editor.conflict ? 'Discard draft and reload' : 'Try again')}</button>{/if}
    </div>
  {/if}
  {#if $editor.notice}<p class="flex items-center gap-2 text-sm text-success" role="status"><Check class="size-4" /> {$ui($editor.notice)}</p>{/if}

  {#if $editor.busy === 'loading' && !$editor.catalog}
    <div class="card flex items-center gap-3 p-6 text-sm text-text-secondary" role="status"><Mail class="size-4" /> {$ui('Loading email templates…')}</div>
  {:else if $editor.catalog && $editor.selected && selectedInfo}
    <div class="grid items-start gap-5 lg:grid-cols-[220px_minmax(0,1fr)]">
      <nav aria-label={$ui('Email content')} class="overflow-hidden rounded-xl border border-border bg-bg-surface">
        <div class="border-b border-border px-4 py-3 text-[10px] font-medium uppercase tracking-widest text-text-muted">{$ui('Document notifications')}</div>
        <div class="grid sm:grid-cols-2 lg:grid-cols-1">
          {#each $editor.catalog.templates as item (item.kind)}
            <button type="button" class="email-kind flex min-h-16 items-center gap-2 border-b border-border px-4 py-3 text-left text-xs transition-colors last:border-b-0 hover:bg-bg-hover"
              class:email-kind-selected={$editor.selected.kind === item.kind} aria-current={$editor.selected.kind === item.kind ? 'true' : undefined}
              disabled={locked || ($editor.dirty && $editor.selected.kind !== item.kind)} onclick={() => editor.select(item.kind)}>
              <span class="min-w-0 flex-1"><span class="block font-medium text-text-primary">{$ui(info[item.kind].name)}</span><span class="mt-1 block text-[10px] text-text-muted">{$ui(!canEditEmailTemplate(item) ? 'Built-in · read only' : item.revision === 0 ? 'Built-in content' : 'Saved revision {revision}', { revision: item.revision })}</span></span>
              {#if $editor.selected.kind === item.kind}<ChevronRight class="size-3.5 shrink-0" />{/if}
            </button>
          {/each}
        </div>
      </nav>

      <section class="min-w-0 overflow-hidden rounded-xl border border-border bg-bg-surface" aria-labelledby="email-editor-heading">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
          <div><h2 id="email-editor-heading" class="text-base font-medium text-text-primary">{$ui(selectedInfo.name)}</h2><p class="mt-1 text-xs text-text-secondary">{$ui(selectedInfo.description)}</p></div>
          <span class="rounded-full border border-border px-2.5 py-1 text-[10px] text-text-secondary">{$ui($editor.dirty ? 'Unsaved changes' : 'Up to date')}</span>
        </div>
        {#if !editable}<p class="border-b border-border bg-bg-elevated px-5 py-3 text-xs leading-relaxed text-text-secondary" role="note">{$ui('This message uses built-in content. Customization is unavailable. You can preview its standard content.')}</p>{/if}
        <div class="grid xl:grid-cols-[minmax(0,1fr)_minmax(280px,0.9fr)]">
          <div class="min-w-0 space-y-5 p-5">
            <label class="block" for="email-template-subject">
              <span class="flex items-baseline justify-between gap-3 text-xs font-medium text-text-primary">{$ui('Subject override')}<span class="text-[10px] font-normal text-text-muted">{emailFieldBytes($editor.draft.subject_template)} / {$editor.catalog.limits.subject_bytes} {$ui('bytes')}</span></span>
              <input id="email-template-subject" class="mt-2 w-full rounded-lg border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary" value={$editor.draft.subject_template} placeholder={$ui('Leave blank to use the built-in subject')} disabled={editorLocked} aria-invalid={!!problems.subject_template} aria-describedby="email-subject-help" oninput={(event) => editor.edit('subject_template', event.currentTarget.value)} />
              <span id="email-subject-help" class="mt-1.5 block text-xs text-text-secondary">{problems.subject_template ? $ui(problems.subject_template) : $ui('Optional. Keep the subject on one line.')}</span>
            </label>

            {#if editable}
              <section class="space-y-4 rounded-xl border border-border p-4" aria-label={$ui('Brand and layout')}>
                <div class="flex items-center gap-2"><Palette class="size-4 text-text-secondary" /><h3 class="text-xs font-medium text-text-primary">{$ui('Brand and layout')}</h3></div>
                <p class="text-xs leading-relaxed text-text-secondary">{$ui('Choose colours, upload your logo and edit the layout around the required message. Changes belong to this email template.')}</p>
                <div class="grid grid-cols-2 gap-3">
                  {#each [{ key: 'background', label: 'Background' }, { key: 'surface', label: 'Message surface' }, { key: 'primary', label: 'Action colour' }, { key: 'text', label: 'Text colour' }] as colour}
                    <label class="block text-xs text-text-secondary" for={'email-colour-' + colour.key}>{$ui(colour.label)}
                      <span class="mt-1.5 flex items-center gap-2 rounded-lg border border-border bg-bg-elevated px-2 py-1.5"><input id={'email-colour-' + colour.key} type="color" class="h-7 w-8 shrink-0 cursor-pointer border-0 bg-transparent p-0" disabled={editorLocked} value={design[colour.key as 'background' | 'surface' | 'primary' | 'text']} oninput={(event) => updateDesign(colour.key as keyof EmailDesign, event.currentTarget.value)} /><span class="font-mono text-[10px] text-text-primary">{design[colour.key as 'background' | 'surface' | 'primary' | 'text']}</span></span>
                    </label>
                  {/each}
                </div>
                <div class="space-y-2">
                  <label for="email-logo" class="flex items-center gap-2 text-xs font-medium text-text-primary"><Upload class="size-3.5" /> {$ui('Local logo')}</label>
                  <input id="email-logo" type="file" accept="image/png,image/jpeg" disabled={editorLocked} class="block w-full text-xs text-text-secondary file:mr-3 file:rounded-lg file:border file:border-border file:bg-bg-elevated file:px-3 file:py-2 file:text-text-primary" onchange={selectLogo} />
                  <p class="text-[10px] leading-relaxed text-text-muted">{$ui('PNG or JPEG · maximum 32 KiB · 512 × 512 pixels. Embedded in the email; no external image requests or tracking pixels.')}</p>
                  {#if logoBusy}<p class="text-xs text-text-secondary" role="status">{$ui('Checking logo…')}</p>{/if}
                  {#if logoError}<p class="text-xs text-danger" role="alert">{$ui(logoError)}</p>{/if}
                  {#if design.logo}<div class="flex items-center gap-3"><span class="text-xs text-text-secondary">{$ui('Local logo attached')}</span><button type="button" class="inline-flex items-center gap-1 text-xs text-text-secondary underline underline-offset-4" disabled={editorLocked} onclick={() => updateDesign('logo', null)}><X class="size-3" /> {$ui('Remove logo')}</button></div>{/if}
                  <label for="email-logo-alt" class="block text-xs text-text-secondary">{$ui('Logo description')}</label>
                  <input id="email-logo-alt" class="w-full rounded-lg border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary" value={design.logo_alt} disabled={editorLocked} oninput={(event) => updateDesign('logo_alt', event.currentTarget.value)} />
                </div>
                <details>
                  <summary class="cursor-pointer text-xs font-medium text-text-primary">{$ui('Layout HTML')}</summary>
                  <label for="email-layout-html" class="sr-only">{$ui('Layout HTML')}</label>
                  <textarea id="email-layout-html" rows="8" class="mt-3 w-full resize-y rounded-lg border border-border bg-bg-elevated p-3 font-mono text-xs leading-relaxed text-text-primary" value={design.layout_html} disabled={editorLocked} spellcheck="false" aria-invalid={!!problems.design_json} oninput={(event) => updateDesign('layout_html', event.currentTarget.value)}></textarea>
                  <p class="mt-2 text-[10px] leading-relaxed text-text-secondary">{$ui('Keep exactly one {{native_content}} slot and use {{logo}} for the attached logo. Safe tables, text and inline styles only. Links, remote images and hidden content are rejected.')}</p>
                </details>
                {#if problems.design_json}<p class="text-xs text-danger" role="alert">{$ui(problems.design_json)}</p>{/if}
                <button type="button" class="text-xs text-text-secondary underline underline-offset-4" disabled={editorLocked || !$editor.draft.design_json} onclick={() => editor.edit('design_json', '')}>{$ui('Use built-in design')}</button>
              </section>
              <section class="space-y-3 rounded-xl border border-border bg-bg-elevated p-4" aria-label={$ui('Design with AI')}>
                <h3 class="flex items-center gap-2 text-xs font-medium text-text-primary"><Sparkles class="size-4" /> {$ui('Design with AI')}</h3>
                <p class="text-xs leading-relaxed text-text-secondary">{$ui('Uses your enabled workspace AI provider. Describe the style and content; review the proposal before adding it to your draft. Nothing is saved or sent automatically.')}</p>
                <label for="email-design-prompt" class="sr-only">{$ui('Describe your email design')}</label>
                <textarea id="email-design-prompt" rows="3" class="w-full rounded-lg border border-border bg-bg-surface p-3 text-xs leading-relaxed text-text-primary" placeholder={$ui('Describe your email design')} value={prompt} disabled={editorLocked} oninput={(event) => prompt = event.currentTarget.value}></textarea>
                <div class="flex flex-wrap items-center justify-between gap-2"><a href="/settings/ai" class="text-xs text-text-secondary underline underline-offset-4">{$ui('Workspace AI settings')}</a><button type="button" class="btn btn-secondary" disabled={editorLocked || invalid || $editor.conflict || !prompt.trim() || emailFieldBytes(prompt) > 4096} aria-busy={$editor.busy === 'proposing'} onclick={() => editor.propose(prompt)}><Sparkles class="size-3.5" /> {$ui($editor.busy === 'proposing' ? 'Creating proposal…' : 'Create design proposal')}</button></div>
                {#if $editor.proposal}
                  <div class="space-y-3 border-t border-border pt-3" role="status"><p class="text-xs font-medium text-text-primary">{$ui('Review AI proposal')}</p><p class="text-xs leading-relaxed text-text-secondary">{$ui('The preview shows the proposed email. Accepting replaces this unsaved subject, introduction and design. Save changes separately after review.')}</p><dl class="space-y-2 text-xs"><dt class="text-text-muted">{$ui('Subject')}</dt><dd class="break-words text-text-primary">{$editor.proposal.input.subject_template || $ui('Built-in subject')}</dd><dt class="text-text-muted">{$ui('HTML introduction')}</dt><dd><pre class="max-h-28 overflow-auto whitespace-pre-wrap break-words text-text-secondary">{$editor.proposal.input.html_template}</pre></dd><dt class="text-text-muted">{$ui('Plain text introduction')}</dt><dd><pre class="max-h-28 overflow-auto whitespace-pre-wrap break-words text-text-secondary">{$editor.proposal.input.text_template}</pre></dd></dl><div class="flex flex-wrap gap-2"><button type="button" class="btn btn-primary" disabled={editorLocked || $editor.conflict} onclick={() => editor.acceptProposal()}>{$ui('Use proposal in draft')}</button><button type="button" class="btn btn-secondary" disabled={busy} onclick={() => editor.discardProposal()}>{$ui('Discard proposal')}</button></div></div>
                {/if}
              </section>
            {/if}

            <div>
              <div class="flex flex-wrap items-center justify-between gap-3">
                <h3 class="text-xs font-medium text-text-primary">{$ui('Introductory content')}</h3>
                <div class="flex rounded-lg border border-border p-0.5" role="group" aria-label={$ui('Content format')}>
                  <button type="button" class="format-button" class:format-active={format === 'html'} aria-pressed={format === 'html'} onclick={() => format = 'html'}><Code2 class="size-3" /> HTML</button>
                  <button type="button" class="format-button" class:format-active={format === 'text'} aria-pressed={format === 'text'} onclick={() => format = 'text'}><FileText class="size-3" /> {$ui('Plain text')}</button>
                </div>
              </div>
              <p class="mt-2 text-xs leading-relaxed text-text-secondary">{$ui('Your introduction appears before the required message. Hash always adds the action link, expiry and essential notices.')}</p>
              {#if format === 'html'}
                <label for="email-template-html" class="sr-only">{$ui('HTML introduction')}</label>
                <textarea id="email-template-html" rows="13" class="mt-3 w-full resize-y rounded-lg border border-border bg-bg-elevated p-3 font-mono text-xs leading-relaxed text-text-primary" value={$editor.draft.html_template} placeholder={$ui('Leave blank to use built-in content')} disabled={editorLocked} spellcheck="false" aria-invalid={!!problems.html_template} aria-describedby="email-body-help" oninput={(event) => editor.edit('html_template', event.currentTarget.value)}></textarea>
                <p class="mt-1 flex justify-between gap-3 text-[10px] text-text-muted"><span>{problems.html_template ? $ui(problems.html_template) : $ui('Simple formatting only. No links, images, attributes or CSS.')}</span><span class="shrink-0">{emailFieldBytes($editor.draft.html_template)} / {$editor.catalog.limits.html_bytes}</span></p>
              {:else}
                <label for="email-template-text" class="sr-only">{$ui('Plain text introduction')}</label>
                <textarea id="email-template-text" rows="13" class="mt-3 w-full resize-y rounded-lg border border-border bg-bg-elevated p-3 font-mono text-xs leading-relaxed text-text-primary" value={$editor.draft.text_template} placeholder={$ui('Leave blank to use built-in content')} disabled={editorLocked} aria-invalid={!!problems.text_template} aria-describedby="email-body-help" oninput={(event) => editor.edit('text_template', event.currentTarget.value)}></textarea>
                <p class="mt-1 flex justify-between gap-3 text-[10px] text-text-muted"><span>{problems.text_template ? $ui(problems.text_template) : $ui('Plain text is used by email clients that do not display HTML.')}</span><span class="shrink-0">{emailFieldBytes($editor.draft.text_template)} / {$editor.catalog.limits.text_bytes}</span></p>
              {/if}
              <p id="email-body-help" class="mt-3 text-xs text-text-secondary">{$ui('Use a variable exactly as shown. Unknown variables are rejected.')}</p>
              <div class="mt-2 flex flex-wrap gap-1.5" aria-label={$ui('Available variables')}>{#each $editor.selected.variables as variable}<code class="rounded border border-border bg-bg-elevated px-2 py-1 text-[10px] text-text-secondary">{'{{' + variable + '}}'}</code>{/each}</div>
            </div>
            <div class="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4">
              <button type="button" class="text-xs text-text-secondary underline decoration-border underline-offset-4 hover:text-text-primary disabled:no-underline" disabled={editorLocked || (!$editor.draft.subject_template && !$editor.draft.html_template && !$editor.draft.text_template)} onclick={resetToBuiltIn}>{$ui('Use built-in content')}</button>
              <button type="button" class="btn btn-secondary" disabled={locked || invalid || $editor.conflict || !!$editor.proposal} onclick={() => editor.preview()} aria-busy={$editor.busy === 'previewing'}><Eye class="size-3.5" /> {$ui($editor.busy === 'previewing' ? 'Generating preview…' : 'Generate preview')}</button>
            </div>
          </div>

          <aside class="min-w-0 border-t border-border bg-bg-elevated p-5 xl:border-l xl:border-t-0" aria-label={$ui('Email preview')}>
            <div class="mb-4 flex items-center justify-between gap-3"><h3 class="text-xs font-medium text-text-primary">{$ui('Preview')}</h3><span class="rounded-full border border-border px-2 py-1 text-[9px] uppercase tracking-wider text-text-muted">{$ui($editor.proposal ? 'AI proposal · not saved' : 'Sample data')}</span></div>
            <p class="mb-4 text-xs leading-relaxed text-text-secondary">{$ui('No email is sent. Action links in this preview cannot be used.')}</p>
            {#if activePreview}
              {#if !$editor.proposal && $editor.previewOutdated}<p class="mb-3 text-xs text-warning" role="status">{$ui('This preview is out of date. Generate it again after editing.')}</p>{/if}
              <div class="overflow-hidden rounded-lg border border-border bg-white text-neutral-900" class:preview-outdated={!$editor.proposal && $editor.previewOutdated}>
                <div class="border-b border-neutral-200 px-4 py-3"><p class="text-[9px] uppercase tracking-widest text-neutral-500">{$ui('Subject')}</p><p class="mt-1 break-words text-sm font-medium">{activePreview.subject}</p></div>
                {#if format === 'html'}<div inert><iframe title={$ui('Synthetic HTML email preview')} srcdoc={previewHTML} sandbox="" referrerpolicy="no-referrer" tabindex="-1" class="h-[430px] w-full border-0 pointer-events-none" aria-hidden="true"></iframe></div>
                {:else}<pre class="max-h-[430px] overflow-auto whitespace-pre-wrap break-words p-4 font-sans text-xs leading-relaxed">{activePreview.text}</pre>{/if}
              </div>
              <p class="mt-3 flex items-center gap-1.5 text-[10px] text-text-muted"><ShieldCheck class="size-3" /> {$ui('Required content preserved · revision {revision}', { revision: activePreview.revision })}</p>
            {:else}
              <div class="flex min-h-[330px] flex-col items-center justify-center rounded-lg border border-dashed border-border px-6 text-center"><Mail class="mb-3 size-7 stroke-1 text-text-muted" /><p class="text-sm font-medium text-text-primary">{$ui('Review before saving')}</p><p class="mt-2 max-w-xs text-xs leading-relaxed text-text-secondary">{$ui('Generate a sample to see your design and introduction together with Hash’s required content.')}</p></div>
            {/if}
            <div class="mt-5">{#key $editor.selected.kind + ':' + $editor.selected.revision}<EmailTemplateSampleSend kind={$editor.selected.kind} revision={$editor.selected.revision} disabled={busy || $editor.dirty || !$editor.authorized || $editor.conflict} />{/key}</div>
          </aside>
        </div>
        <footer class="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-bg-elevated px-5 py-4">
          <p class="max-w-sm text-xs text-text-secondary">{$ui(!editable ? 'Built-in content is unchanged.' : $editor.dirty ? 'Save or cancel before choosing another template.' : 'Changes apply to new emails. Already queued messages keep their saved content.')}</p>
          {#if editable}<div class="flex items-center gap-2"><button type="button" class="btn btn-secondary" disabled={busy || !$editor.dirty} onclick={() => editor.cancel()}>{$ui('Cancel')}</button><button type="button" class="btn btn-primary" disabled={locked || !$editor.dirty || invalid || $editor.conflict || !!$editor.proposal} aria-busy={$editor.busy === 'saving'} onclick={() => editor.save()}><Save class="size-3.5" /> {$ui($editor.busy === 'saving' ? 'Saving…' : 'Save changes')}</button></div>{:else}<span class="text-xs text-text-muted">{$ui('Read only')}</span>{/if}
        </footer>
      </section>
    </div>
  {/if}
</div>

<style>
  .email-kind { width: 100%; }
  .email-kind-selected { background: var(--color-bg-hover); box-shadow: inset 2px 0 var(--color-text-primary); }
  .email-kind:disabled { opacity: .55; cursor: not-allowed; }
  .email-kind-selected:disabled { opacity: 1; }
  .format-button { display: flex; align-items: center; gap: .35rem; border-radius: .35rem; padding: .35rem .55rem; font-size: .625rem; color: var(--color-text-secondary); }
  .format-active { background: var(--color-bg-surface); color: var(--color-text-primary); box-shadow: 0 1px 3px rgb(0 0 0 / .08); }
  .preview-outdated { opacity: .65; }
</style>
