<script lang="ts">
  import { onDestroy, onMount, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { APIError, getMe, getTemplate, createHTMLTemplate, updateHTMLTemplate, previewHTMLTemplate, approveHTMLTemplate,
    type TemplateResponse, type HTMLTemplatePreview } from '$lib/api/client';
  import { blankHTMLAuthorDraft, blankHTMLContractProfile, blankHTMLSigningPage, draftFromHTMLTemplate, htmlAuthorInput, htmlAuthorFingerprint, htmlAssetFromFile, assetByteLength } from '$lib/htmlAuthor';
  import { htmlContractProfile, htmlPreviewSections, htmlProfileIssues, htmlSigningPageIssues, htmlSigningPageColours, htmlSigningPageColourLabels, htmlPartyBindings, htmlPartyLabels, requiredHTMLContractTerms, htmlTemplateFields, htmlValuesForSubmission, isApprovedHTMLTemplate, type HTMLContractProfile } from '$lib/htmlTemplate';
  import VerifiedPDFPages from './VerifiedPDFPages.svelte';

  type Identity = Awaited<ReturnType<typeof getMe>>;
  type Navigation = { cancel: () => void; willUnload: boolean; from: { url: URL } | null; to: { url: URL } | null };
  type PageProof = { key: string; allPagesSeen: boolean };
  let { templateID }: { templateID: string | null } = $props();
  const sourceID = untrack(() => templateID);
  let knownID = $state(sourceID);
  let me = $state<Identity | null>(null);
  let orgScope: string | null = null;
  let saved = $state<TemplateResponse | null>(null);
  let latest = $state<TemplateResponse | null>(null);
  let draft = $state(blankHTMLAuthorDraft());
  let baseline = $state(untrack(() => htmlAuthorFingerprint(draft)));
  let samples = $state<Record<string, string>>({});
  let sectionSamples = $state<Record<string, string>>({});
  let sampleBaseline = $state('{}');
  let loading = $state(true);
  let busy = $state<string | null>(null);
  let error = $state<string | null>(null);
  let needsRefresh = $state(false);
  let writeUncertain = $state(false);
  let acknowledgedSave = $state<{ id: string; version: number; contentSHA256: string } | null>(null);
  let preview = $state.raw<HTMLTemplatePreview | null>(null);
  let previewSamples = $state('');
  let previewActor = $state('');
  let previewSequence = $state(0);
  let allPagesSeen = $state(false);
  let acknowledged = $state(false);
  let now = $state(Date.now());
  let assetName = $state('');
  let pendingAssetFile = $state.raw<File | null>(null);
  let assetFile = $state.raw<HTMLInputElement | null>(null);
  let disposed = false;
  let operation = 0;
  let rowKey = 0;
  let previewAbort: AbortController | null = null;
  const current = () => !disposed && templateID === sourceID;
  const dirty = $derived(htmlAuthorFingerprint(draft) !== baseline);
  const sampleDirty = $derived(JSON.stringify({ values: samples, sections: sectionSamples }) !== sampleBaseline);
  const assetDraftDirty = $derived(!!assetName || !!pendingAssetFile);
  const canWrite = $derived(!!me && me.org_id === orgScope && (!sourceID || saved !== null) && (me.role === 'owner' || me.role === 'sender'));
  const canApprove = $derived(canWrite && me?.role === 'owner');
  const approved = $derived(saved !== null && isApprovedHTMLTemplate(saved));
  const profileProblem = $derived.by(() => {
    if (draft.schema_version === 1) return null;
    try { htmlContractProfile({ schema_version: draft.schema_version, html: draft.html, css: draft.css, values: draft.values, sections: draft.sections, assets: draft.assets,
      ...(draft.signing_page ? { signing_page: draft.signing_page } : {}),
      ...(draft.contract_profile ? { contract_profile: draft.contract_profile } : {}) }); return null; }
    catch (e) { return (e as Error).message; }
  });
  const previewKey = $derived(`preview-${previewSequence}`);
  const previewValid = $derived(!!preview && !!saved && !dirty && !assetDraftDirty && !needsRefresh && !writeUncertain
    && preview.templateID === saved.id && preview.version === saved.version && preview.contentSHA256 === saved.content_sha256
    && previewActor === me?.user_id && previewSamples === JSON.stringify({ values: samples, sections: sectionSamples }) && now < Date.parse(preview.expiresAt));
  let observedDraft = untrack(() => htmlAuthorFingerprint(draft));
  let observedSamples = untrack(() => JSON.stringify({ values: samples, sections: sectionSamples }));
  let observedAssetIntent = '';
  $effect(() => {
    const nextDraft = htmlAuthorFingerprint(draft), nextSamples = JSON.stringify({ values: samples, sections: sectionSamples });
    const assetIntent = `${assetName}:${pendingAssetFile?.name ?? ''}:${pendingAssetFile?.lastModified ?? ''}`;
    if (nextDraft !== observedDraft || nextSamples !== observedSamples || assetIntent !== observedAssetIntent) {
      observedDraft = nextDraft; observedSamples = nextSamples;
      observedAssetIntent = assetIntent;
      untrack(invalidatePreview);
    }
  });
  $effect(() => { if (!previewValid) acknowledged = false; });

  function invalidatePreview() {
    previewAbort?.abort(); previewAbort = null;
    preview = null; allPagesSeen = false; acknowledged = false;
  }
  function detail(next: TemplateResponse, id: string): TemplateResponse {
    if (next.id !== id || next.org_id !== orgScope || next.source_kind !== 'html'
        || !next.html_approval || next.html_approval.version !== next.version || next.html_approval.content_sha256 !== next.content_sha256
        || !!next.html_approval.approved_by !== !!next.html_approval.approved_at) throw new Error('The server returned a different or incomplete saved design.');
    draftFromHTMLTemplate(next);
    return next;
  }
  function samePin(first: TemplateResponse, second: TemplateResponse) {
    return first.id === second.id && first.org_id === second.org_id && first.version === second.version && first.content_sha256 === second.content_sha256;
  }
  function adopt(next: TemplateResponse) {
    invalidatePreview();
    const nextDraft = draftFromHTMLTemplate(next);
    saved = next; knownID = next.id; draft = nextDraft; baseline = htmlAuthorFingerprint(nextDraft);
    samples = Object.fromEntries(htmlTemplateFields(next).map((field) => [field.name, field.defaultValue]));
    sectionSamples = Object.fromEntries((next.html_master_json!.sections ?? []).map((section) => [section.name, section.default_text]));
    sampleBaseline = JSON.stringify({ values: samples, sections: sectionSamples });
    rowKey = Math.max(nextDraft.values.length, nextDraft.sections.length);
    latest = null; needsRefresh = false; writeUncertain = false; error = null;
    acknowledgedSave = null;
    assetName = ''; pendingAssetFile = null; if (assetFile) assetFile.value = '';
  }
  function recordError(e: unknown) {
    error = (e as Error).message;
    if (e instanceof APIError && (e.status === 401 || e.status === 403)) { me = null; invalidatePreview(); }
    if (e instanceof APIError && e.status === 409) needsRefresh = true;
  }
  function checkedIdentity(identity: Identity): Identity {
    const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
    const usableID = (id: unknown) => typeof id === 'string' && uuid.test(id) && id !== '00000000-0000-0000-0000-000000000000';
    if (!identity || !usableID(identity.user_id) || !usableID(identity.org_id) || !['owner', 'sender', 'viewer'].includes(identity.role)) {
      me = null; invalidatePreview();
      throw new Error('The current session identity could not be verified. Your local design inputs are retained.');
    }
    return identity;
  }
  async function loadInitial() {
    if (!current() || busy) return;
    if (knownID && (saved || dirty || writeUncertain)) { await readLatest(); return; }
    const selected = ++operation; loading = true; error = null;
    try {
      const response = await getMe();
      if (!current() || selected !== operation) return;
      const identity = checkedIdentity(response);
      if (orgScope && identity.org_id !== orgScope) {
        me = null; invalidatePreview();
        throw new Error('The active organisation changed. Return to the library in the correct organisation; your local inputs are retained.');
      }
      orgScope = identity.org_id; me = identity;
      if (sourceID) {
        const response = await getTemplate(sourceID);
        if (!current() || selected !== operation) return;
        adopt(detail(response, sourceID));
      }
    } catch (e) { if (current() && selected === operation) recordError(e); }
    finally { if (current() && selected === operation) loading = false; }
  }
  async function save(event: Event) {
    event.preventDefault();
    if (!current() || !canWrite || loading || busy || needsRefresh || writeUncertain || (knownID && !saved) || (saved && !dirty)) return;
    let input;
    if (assetDraftDirty) { error = 'Add or clear the selected local asset before saving the design.'; return; }
    try { input = htmlAuthorInput(draft); } catch (e) { recordError(e); return; }
    const selected = ++operation, submitted = htmlAuthorFingerprint(draft), previous = saved, target = knownID;
    let writeAccepted = false;
    busy = 'save'; error = null; invalidatePreview();
    try {
      const response = target && previous ? await updateHTMLTemplate(target, previous.version, input) : await createHTMLTemplate(input);
      if (!current() || selected !== operation || submitted !== htmlAuthorFingerprint(draft)) return;
      if (!response.id || response.org_id !== orgScope || response.source_kind !== 'html'
          || (target && response.id !== target) || (previous && response.version !== previous.version + 1)) throw new Error('The save response could not be confirmed.');
      draftFromHTMLTemplate(response);
      writeAccepted = true;
      acknowledgedSave = { id: response.id, version: response.version, contentSHA256: response.content_sha256! };
      knownID = response.id;
      const fresh = await getTemplate(response.id);
      if (!current() || selected !== operation || submitted !== htmlAuthorFingerprint(draft)) return;
      detail(fresh, response.id);
      if (!samePin(fresh, response)) {
        latest = fresh; needsRefresh = true;
        error = 'The saved design changed again. Your local source is retained; inspect the current revision before continuing.';
        return;
      }
      adopt(fresh);
    } catch (e) {
      if (current() && selected === operation) {
        recordError(e);
        if (writeAccepted || !(e instanceof APIError) || e.status >= 500) {
          writeUncertain = true;
          error = writeAccepted
            ? 'The save succeeded, but its saved revision could not be read back. Inspect that saved design before another write. Your entered source, defaults and assets are retained here.'
            : 'We could not confirm the save. Check the saved revision or template library before another write. Your entered source, defaults and assets are retained here.';
        }
      }
    } finally { if (current() && selected === operation) busy = null; }
  }
  async function readLatest() {
    if (!current() || !knownID || busy) return;
    const target = knownID, selected = ++operation;
    busy = 'refresh'; error = null; invalidatePreview();
    try {
      const responseIdentity = await getMe();
      if (!current() || selected !== operation) return;
      const identity = checkedIdentity(responseIdentity);
      if (identity.org_id !== orgScope) {
        me = null; invalidatePreview();
        throw new Error('The active organisation changed. Return to the library in the correct organisation; your local inputs are retained.');
      }
      me = identity;
      const response = await getTemplate(target);
      if (!current() || selected !== operation || knownID !== target) return;
      latest = detail(response, target);
    } catch (e) { if (current() && selected === operation) recordError(e); }
    finally { if (current() && selected === operation) busy = null; }
  }
  function adoptLatest() {
    if (!current() || busy || !latest) return;
    if ((dirty || sampleDirty || assetDraftDirty || writeUncertain) && !window.confirm('Discard local source, defaults, local file selections and preview values, and load this current saved revision? An earlier uncertain request may still complete.')) return;
    adopt(latest);
  }
  async function addAsset() {
    if (!current() || !canWrite || busy || loading) return;
    const file = pendingAssetFile; if (!file) return;
    const selected = ++operation, submitted = htmlAuthorFingerprint(draft);
    busy = 'asset'; error = null; invalidatePreview();
    try {
      const asset = await htmlAssetFromFile(file, assetName, draft.assets);
      if (!current() || selected !== operation || submitted !== htmlAuthorFingerprint(draft)) return;
      draft.assets = [...draft.assets, asset]; assetName = ''; pendingAssetFile = null; if (assetFile) assetFile.value = '';
    } catch (e) { if (current() && selected === operation) recordError(e); }
    finally { if (current() && selected === operation) busy = null; }
  }
  function addValue() { if (canWrite && !busy) draft.values = [...draft.values, { key: ++rowKey, name: '', required: false, max_chars: 256, default_value: '' }]; }
  function addSection() { if (canWrite && !busy) draft.sections = [...draft.sections, { key: ++rowKey, name: '', max_chars: 4096, default_text: '' }]; }
  function changeProfile(event: Event) {
    if (!canWrite || busy) return;
    const enabled = (event.currentTarget as HTMLInputElement).checked;
    if (!enabled && draft.contract_profile && !window.confirm('Remove these contract checks, intended parties and any appended signing page from the local design? Saving creates a generic version 1 revision for owner review.')) {
      (event.currentTarget as HTMLInputElement).checked = true;
      return;
    }
    draft.schema_version = enabled ? 2 : 1;
    draft.contract_profile = enabled ? blankHTMLContractProfile() : null;
    draft.signing_page = null;
  }
  function changeSigningPage(event: Event) {
    if (!canWrite || busy || !draft.contract_profile) return;
    const enabled = (event.currentTarget as HTMLInputElement).checked;
    if (!enabled && !window.confirm('Remove the appended signing page from this local design? Saving creates a new version 2 revision for owner review. Existing documents keep their saved page.')) {
      (event.currentTarget as HTMLInputElement).checked = true;
      return;
    }
    draft.schema_version = enabled ? 3 : 2;
    draft.signing_page = enabled ? blankHTMLSigningPage() : null;
  }
  function changeSigningLogo(event: Event) {
    if (!canWrite || busy || !draft.signing_page) return;
    const name = (event.currentTarget as HTMLSelectElement).value;
    if (!name) {
      draft.signing_page.logo_asset = ''; draft.signing_page.logo_sha256 = ''; draft.signing_page.logo_alt = '';
      return;
    }
    const asset = draft.assets.find((candidate) => candidate.name === name && ['image/png', 'image/jpeg'].includes(candidate.media_type));
    if (!asset) return;
    draft.signing_page.logo_asset = asset.name; draft.signing_page.logo_sha256 = asset.sha256;
    draft.signing_page.logo_alt = asset.name.replaceAll('_', ' ');
  }
  function changeProfileKind(event: Event) {
    if (!canWrite || busy || !draft.contract_profile) return;
    const kind = (event.currentTarget as HTMLSelectElement).value as HTMLContractProfile['kind'];
    if (!['proposal', 'b2b_services'].includes(kind)) return;
    draft.contract_profile.kind = kind;
    for (const name of requiredHTMLContractTerms(kind)) if (!draft.contract_profile.terms.some((term) => term.name === name)) {
      draft.contract_profile.terms.push({ name, value: '' });
    }
  }
  function changeTermBinding(index: number, event: Event) {
    if (!canWrite || busy || !draft.contract_profile) return;
    const target = (event.currentTarget as HTMLSelectElement).value, term = draft.contract_profile.terms[index];
    draft.contract_profile.terms[index] = target.startsWith('section:')
      ? { name: term.name, section: target.slice(8) } : { name: term.name, value: target.startsWith('value:') ? target.slice(6) : '' };
  }
  async function generatePreview() {
    if (!current() || !canWrite || !saved || dirty || assetDraftDirty || busy || loading || needsRefresh || writeUncertain) return;
    const target = saved, actor = me!.user_id, fingerprint = JSON.stringify({ values: samples, sections: sectionSamples }), selected = ++operation;
    let values, sections;
    try {
      values = htmlValuesForSubmission(htmlTemplateFields(target), samples);
      sections = htmlPreviewSections(target.html_master_json!, sectionSamples);
      const profile = htmlContractProfile(target.html_master_json!);
      const issues = profile ? [...htmlProfileIssues(profile, values, sections), ...(target.html_master_json!.schema_version === 3 ? htmlSigningPageIssues(profile, values) : [])] : [];
      if (issues.length) throw new Error(issues[0]);
    } catch (e) { recordError(e); return; }
    invalidatePreview(); const controller = new AbortController(); previewAbort = controller;
    busy = 'preview'; error = null;
    try {
      const response = await previewHTMLTemplate(target.id, target.version, target.content_sha256!, values, controller.signal, sections);
      if (!current() || selected !== operation || !saved || !samePin(saved, target) || dirty || assetDraftDirty || controller.signal.aborted || JSON.stringify({ values: samples, sections: sectionSamples }) !== fingerprint || me?.user_id !== actor) return;
      preview = response; previewSamples = fingerprint; previewActor = actor; previewSequence++;
    } catch (e) { if (current() && selected === operation && !controller.signal.aborted) recordError(e); }
    finally { if (current() && selected === operation) busy = null; }
  }
  function receiveProof(proof: PageProof) {
    if (!current() || proof.key !== previewKey || !previewValid) return;
    allPagesSeen = proof.allPagesSeen; if (!allPagesSeen) acknowledged = false;
  }
  async function approve() {
    if (!current() || !canApprove || !saved || approved || busy || !previewValid || !preview || !allPagesSeen || !acknowledged || Date.now() >= Date.parse(preview.expiresAt)) return;
    const target = saved, rendered = preview, selected = ++operation;
    let writeAccepted = false;
    busy = 'approve'; error = null;
    try {
      const result = await approveHTMLTemplate(target.id, target.version, target.content_sha256!, rendered);
      if (!current() || selected !== operation || !saved || !samePin(saved, target) || dirty || preview !== rendered) return;
      if (result.template_id !== target.id || result.version !== target.version || result.content_sha256 !== target.content_sha256
          || !result.approved_by || !Number.isFinite(Date.parse(result.approved_at))) throw new Error('The approval response could not be confirmed.');
      writeAccepted = true;
      const fresh = await getTemplate(target.id);
      if (!current() || selected !== operation || !saved || !samePin(saved, target) || dirty || preview !== rendered) return;
      detail(fresh, target.id);
      if (!samePin(fresh, target) || !isApprovedHTMLTemplate(fresh)) throw new Error('The approval no longer matches this saved revision.');
      saved = fresh; acknowledged = false;
    } catch (e) {
      if (current() && selected === operation) {
        recordError(e); invalidatePreview();
        if (writeAccepted || !(e instanceof APIError) || e.status >= 500) {
          writeUncertain = true;
          error = 'We could not confirm approval. Check the current saved revision before another approval. Your design and preview values are retained.';
        }
      }
    } finally { if (current() && selected === operation) busy = null; }
  }
  function protectNavigation(navigation: Navigation) {
    if (!navigation.willUnload && navigation.to?.url.pathname !== navigation.from?.url.pathname && (dirty || sampleDirty || assetDraftDirty || busy)
        && !window.confirm(busy ? 'This request may still complete. Leave and discard local design inputs?' : 'Leave and discard unsaved design or preview inputs?')) navigation.cancel();
  }
  beforeNavigate(protectNavigation);
  function protectUnload(event: BeforeUnloadEvent) { if (dirty || sampleDirty || assetDraftDirty || busy) { event.preventDefault(); event.returnValue = ''; } }
  onMount(() => {
    void loadInitial();
    const timer = setInterval(() => { now = Date.now(); }, 1000);
    window.addEventListener('beforeunload', protectUnload);
    return () => { clearInterval(timer); window.removeEventListener('beforeunload', protectUnload); };
  });
  onDestroy(() => { disposed = true; operation++; previewAbort?.abort(); });
</script>

<div class="px-6 py-10 max-w-6xl mx-auto space-y-6">
  <a href="/templates" class="text-sm text-text-secondary hover:underline">Back to templates</a>
  <header class="space-y-2"><p class="page-eyebrow">Reusable design</p><h1 class="page-title">{saved ? 'Edit HTML design' : 'New HTML design'}</h1>
    <p class="text-sm text-text-secondary">Preserve the HTML/CSS layout, declare the information that changes, and save a revision for an owner to review. This does not send a document.</p></header>
  {#if loading}<p role="status">Loading design and permissions…</p>{/if}
  {#if error}<p role="alert" class="card p-4 text-danger text-sm">{error}</p>{/if}
  {#if !loading && !me}<button class="btn btn-secondary" onclick={knownID ? readLatest : loadInitial}>{knownID ? 'Reload session and inspect saved revision' : 'Reload session'}</button>{/if}
  {#if saved}<div class="text-sm space-y-1"><p>Saved version {saved.version} · {approved ? 'Approved revision' : 'Awaiting owner approval'}{dirty ? ' · Unsaved changes' : ''}</p>
    {#if approved}<p class="text-text-secondary">Approved {new Date(saved.html_approval!.approved_at!).toLocaleString()}. Any saved source, default, wording or asset change creates a new revision for review.</p>{/if}
    {#if !sourceID}<a href={`/templates/${saved.id}/html`} class="underline">Open this saved design’s permanent editor link</a>{/if}</div>{/if}
  {#if needsRefresh || writeUncertain}<div class="card p-4 space-y-3 text-sm"><p>Your local inputs are retained. Inspect the current saved revision before another write.</p>
    {#if acknowledgedSave}<p>Save acknowledged for version {acknowledgedSave.version}. <a class="underline" href={`/templates/${acknowledgedSave.id}/html`}>Open that saved design</a>.</p>{/if}
    {#if knownID}<button class="btn btn-secondary" disabled={!!busy} onclick={readLatest}>Check current saved revision</button>{:else}<a href="/templates" class="underline">Check the template library</a>{/if}</div>{/if}
  {#if latest}<div class="card p-4 space-y-3 text-sm"><p>Current saved version {latest.version} · {isApprovedHTMLTemplate(latest) ? 'Approved' : 'Unapproved'}. Loading it will replace local editor and preview inputs.</p>
    <button class="btn btn-secondary" disabled={!!busy} onclick={adoptLatest}>Load this saved revision</button></div>{/if}
  {#if !loading}
    {#if !canWrite}<p role="note" class="text-sm">A sender or owner in this organisation may edit and preview designs. An owner must approve them.</p>{/if}
    <form onsubmit={save} class="space-y-6">
      <fieldset disabled={!canWrite || !!busy || writeUncertain || needsRefresh} class="space-y-6 min-w-0">
        <section class="card p-6 space-y-4" aria-label="Design source">
          <label class="block text-sm">Design name<input bind:value={draft.name} required maxlength="200" class="mt-1 block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated" /></label>
          <p class="text-sm text-text-secondary">Use an HTML body fragment and separate print CSS. Scripts, event handlers, remote resources and forms are refused. Values use declared text markers.</p>
          <label class="block text-sm">HTML body fragment<textarea bind:value={draft.html} spellcheck={false} rows="14" class="mt-1 block w-full max-w-full px-3 py-2 font-mono text-xs rounded-md border border-border-light bg-bg-elevated"></textarea></label>
          <label class="block text-sm">Print CSS<textarea bind:value={draft.css} spellcheck={false} rows="9" class="mt-1 block w-full max-w-full px-3 py-2 font-mono text-xs rounded-md border border-border-light bg-bg-elevated"></textarea></label>
        </section>
        <section class="card p-6 space-y-4" aria-label="Reviewed contract profile">
          <h2 class="font-display text-lg">Contract checks and intended parties</h2>
          <label class="flex items-start gap-3 text-sm"><input type="checkbox" checked={draft.schema_version !== 1} onchange={changeProfile} class="mt-1" />
            <span>Declare a reviewed proposal or ordinary B2B services profile. Hash requires both named parties and the mapped information before sending.</span></label>
          <p class="text-sm text-text-secondary">Map these checks to values and wording printed by this design. An owner reviews the exact revision. These checks do not establish legal sufficiency, verify identity or prove representative authority.</p>
          {#if draft.contract_profile}
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label class="text-sm">Profile identifier<input bind:value={draft.contract_profile.id} required maxlength="64" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>
              <label class="text-sm">Profile version<input type="number" bind:value={draft.contract_profile.version} required min="1" max="1000000" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>
              <label class="text-sm">Contract type<select value={draft.contract_profile.kind} onchange={changeProfileKind} class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated"><option value="proposal">Proposal</option><option value="b2b_services">Ordinary B2B services</option></select></label>
            </div>
            {#each draft.contract_profile.parties as party (party.slot)}
              <div class="border border-border-light rounded-md p-4 space-y-3"><h3 class="font-medium">{party.slot === 'provider' ? 'Our company (provider)' : 'Customer'}</h3>
                {#each htmlPartyBindings as binding (binding)}<label class="block text-sm">{htmlPartyLabels[binding]}
                  <select bind:value={party[binding]} class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" required>
                    <option value="">Choose a required printed value…</option>
                    {#each draft.values.filter((value) => value.required && value.name) as value (value.key)}<option value={value.name}>{value.name.replaceAll('_', ' ')}</option>{/each}
                  </select></label>{/each}
              </div>
            {/each}
            <div class="border border-border-light rounded-md p-4 space-y-3"><h3 class="font-medium">Commercial terms</h3>
              <p class="text-sm text-text-secondary">Required term names: {requiredHTMLContractTerms(draft.contract_profile.kind).join(', ')}. Each needs its own printed value or wording section.</p>
              {#each draft.contract_profile.terms as term, index (index)}<div class="grid grid-cols-1 sm:grid-cols-[1fr_2fr_auto] gap-3 items-end">
                <label class="text-sm">Term name<input bind:value={term.name} required maxlength="64" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>
                <label class="text-sm">Printed information<select value={term.section !== undefined ? `section:${term.section}` : term.value ? `value:${term.value}` : ''} onchange={(event) => changeTermBinding(index, event)} required class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated">
                  <option value="">Choose its own value or wording section…</option>
                  <optgroup label="Required printed values">{#each draft.values.filter((value) => value.required && value.name) as value (value.key)}<option value={`value:${value.name}`}>{value.name.replaceAll('_', ' ')}</option>{/each}</optgroup>
                  <optgroup label="Approved wording sections">{#each draft.sections.filter((section) => section.name) as section (section.key)}<option value={`section:${section.name}`}>{section.name.replaceAll('_', ' ')}</option>{/each}</optgroup>
                </select></label>
                <button type="button" class="btn btn-secondary text-xs" onclick={() => { if (draft.contract_profile) draft.contract_profile.terms = draft.contract_profile.terms.filter((_, i) => i !== index); }}>Remove</button>
              </div>{/each}
              <button type="button" class="btn btn-secondary" disabled={draft.contract_profile.terms.length >= 16} onclick={() => draft.contract_profile?.terms.push({ name: '', value: '' })}>Add another term</button>
            </div>
            <p class="text-sm text-text-secondary">Both representatives will sign; their names and email addresses come from the printed document values. Changing those values creates a fresh PDF for review. Pre-signing on someone’s behalf is unavailable.</p>
            <div class="border border-border-light rounded-md p-4 space-y-4" aria-label="Appended signing page">
              <label class="flex items-start gap-3 text-sm"><input type="checkbox" checked={draft.schema_version === 3} onchange={changeSigningPage} class="mt-1" /><span>Append a branded signing page with fixed signature locations for both parties.</span></label>
              <p class="text-sm text-text-secondary">The saved page uses the same printed party details. Its appearance and signature locations require owner review of the complete PDF. Colours, fonts and logo stay fixed in documents made from this approved design.</p>
              {#if draft.signing_page}
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {#each htmlSigningPageColours as colour (colour)}<label class="text-sm">{htmlSigningPageColourLabels[colour]}<input type="color" value={draft.signing_page.branding[colour]} oninput={(event) => { if (draft.signing_page) draft.signing_page.branding[colour] = event.currentTarget.value.toUpperCase(); }} class="mt-1 block w-full h-10 border border-border-light rounded-md bg-bg-elevated" /></label>{/each}
                </div>
                <p class="text-sm text-text-secondary">Text and secondary text require at least 4.5:1 contrast with the background; headings and signatures require 3:1. Preview the saved page to inspect readability.</p>
                <p class="text-sm">Heading and body font: bundled Inter, saved with this page design. This page supports the bundled Latin glyphs; other scripts require a future approved page design.</p>
                <label class="block text-sm">Signing-page logo<select value={draft.signing_page.logo_asset} onchange={changeSigningLogo} class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated">
                  <option value="">No logo (saved choice)</option>
                  {#each draft.assets.filter((asset) => ['image/png', 'image/jpeg'].includes(asset.media_type)) as asset (asset.name)}<option value={asset.name}>{asset.name.replaceAll('_', ' ')}</option>{/each}
                </select></label>
                {#if draft.signing_page.logo_asset}<label class="block text-sm">Logo description (80 characters and display units)<input bind:value={draft.signing_page.logo_alt} required maxlength="160" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>{/if}
                <p class="text-sm text-text-secondary">Choose a local image added below, or approve the explicit no-logo choice. Review its size and readability on the final preview page.</p>
              {/if}
            </div>
            {#if profileProblem}<p class="text-sm text-warning" role="status">{profileProblem}</p>{/if}
          {:else}<p class="text-sm text-text-secondary">This generic version 1 design has no declared contract profile. Its owner and sender must review completeness and intended parties themselves.</p>{/if}
        </section>
        <section class="card p-6 space-y-4" aria-label="Declared values and defaults">
          <h2 class="font-display text-lg">Declared values and saved defaults</h2>
          <p class="text-sm text-text-secondary">Use an empty text marker such as <code class="break-all">&lt;span data-hash-value="company_name"&gt;&lt;/span&gt;</code>. Names use lowercase letters, digits and underscores. Required defaults may stay blank until a document is populated.</p>
          {#each draft.values as value (value.key)}<div class="border border-border-light rounded-md p-4 space-y-3">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3"><label class="text-sm">Value name<input bind:value={value.name} required maxlength="64" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>
              <label class="text-sm">Character limit<input type="number" bind:value={value.max_chars} required min="1" max="8192" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label></div>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={value.required} /> Required when populated</label>
            <label class="block text-sm">Saved default text<textarea bind:value={value.default_value} rows="2" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated"></textarea></label>
            <button type="button" class="btn btn-secondary text-xs" onclick={() => draft.values = draft.values.filter((row) => row.key !== value.key)}>Remove declaration</button>
          </div>{/each}
          <button type="button" class="btn btn-secondary" disabled={draft.values.length >= 64} onclick={addValue}>Add declared value</button>
        </section>
        <section class="card p-6 space-y-4" aria-label="Approved wording sections">
          <h2 class="font-display text-lg">Wording sections</h2>
          <p class="text-sm text-text-secondary">Use one empty text marker per section, such as <code class="break-all">&lt;div data-hash-section="scope"&gt;&lt;/div&gt;</code>. Formatting belongs outside the marker. An owner reviews every saved wording change; Hash does not determine legal completeness.</p>
          {#each draft.sections as section (section.key)}<div class="border border-border-light rounded-md p-4 space-y-3">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3"><label class="text-sm">Section name<input bind:value={section.name} required maxlength="64" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>
              <label class="text-sm">Character limit<input type="number" bind:value={section.max_chars} required min="1" max="32768" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label></div>
            <label class="block text-sm">Saved wording<textarea bind:value={section.default_text} rows="5" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated"></textarea></label>
            <button type="button" class="btn btn-secondary text-xs" onclick={() => draft.sections = draft.sections.filter((row) => row.key !== section.key)}>Remove section</button>
          </div>{/each}<button type="button" class="btn btn-secondary" disabled={draft.sections.length >= 64} onclick={addSection}>Add wording section</button>
        </section>
        <section class="card p-6 space-y-4" aria-label="Local design assets">
          <h2 class="font-display text-lg">Local images and fonts</h2><p class="text-sm text-text-secondary">PNG, JPEG, WOFF and WOFF2 only: 2 MiB per file, 16 files / 8 MiB total. Reference them as <code>hash-asset:asset_name</code> in supported image or font locations. Files are validated and scanned on save; inspect them in the PDF preview.</p>
          {#each draft.assets as asset (asset.name)}<div class="border border-border-light rounded-md p-3 text-sm space-y-2"><p class="break-words">{asset.name} · {asset.media_type} · {Math.ceil(assetByteLength(asset) / 1024)} KiB</p><p class="font-mono text-xs break-all">SHA-256 {asset.sha256}</p>
            <button type="button" class="btn btn-secondary text-xs" disabled={draft.signing_page?.logo_asset === asset.name} onclick={() => draft.assets = draft.assets.filter((row) => row.name !== asset.name)}>Remove asset</button>
            {#if draft.signing_page?.logo_asset === asset.name}<p class="text-text-secondary">This is the saved signing-page logo. Choose another image or no logo before removing it.</p>{/if}</div>{/each}
          <label class="block text-sm">New asset name<input bind:value={assetName} maxlength="64" class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated" /></label>
          <label class="block text-sm">Local file<input type="file" bind:this={assetFile} onchange={() => { pendingAssetFile = assetFile?.files?.[0] ?? null; }} accept=".png,.jpg,.jpeg,.woff,.woff2" class="mt-1 block w-full text-sm" /></label>
          <button type="button" class="btn btn-secondary" disabled={draft.assets.length >= 16} onclick={addAsset}>Add local asset</button>
          {#if assetDraftDirty}<p class="text-sm text-text-secondary">This local selection is not part of the design until added.</p><button type="button" class="btn btn-secondary text-xs" onclick={() => { assetName = ''; pendingAssetFile = null; if (assetFile) assetFile.value = ''; }}>Clear local selection</button>{/if}
        </section>
      </fieldset>
      <div class="flex flex-wrap gap-2"><button class="btn btn-primary" type="submit" disabled={!canWrite || !!busy || needsRefresh || writeUncertain || (!!saved && !dirty)}>{busy === 'save' ? 'Saving revision…' : saved ? 'Save new revision' : 'Save design'}</button>
        {#if saved}<button type="button" class="btn btn-secondary" disabled={!!busy} onclick={readLatest}>Inspect saved revision</button>{/if}</div>
    </form>
  {/if}
  {#if saved}
    <section class="card p-6 space-y-4" aria-label="Saved design preview and approval">
      <h2 class="font-display text-lg">Preview saved revision {saved.version}</h2>
      <p class="text-sm text-text-secondary">These values and wording samples are for this preview only. They do not change saved defaults or wording. Preview this saved design; an owner must personally review and approve it before use.</p>
      {#if saved.html_master_json?.schema_version === 3}<p class="text-sm">This preview includes the appended signing page. Review both printed party details, saved colours and logo, and the fixed signature locations on its final page.</p>{/if}
      {#if dirty}<p class="text-sm text-warning" role="note">Save the editor changes before generating a new preview.</p>{/if}
      <fieldset disabled={!canWrite || !!busy || dirty || assetDraftDirty || needsRefresh || writeUncertain} class="space-y-3">
        {#each htmlTemplateFields(saved) as field (field.name)}<label class="block text-sm capitalize">Preview {field.label}{field.required ? ' (required)' : ''}<textarea bind:value={samples[field.name]} rows="2" maxlength={field.max_chars * 2} class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated"></textarea></label>{/each}
        {#each saved.html_master_json?.sections ?? [] as section (section.name)}<label class="block text-sm capitalize">Preview-only {section.name.replaceAll('_', ' ')} wording<textarea bind:value={sectionSamples[section.name]} rows="4" maxlength={section.max_chars * 2} placeholder={section.default_text ? undefined : 'Enter synthetic wording for owner preview'} class="mt-1 block w-full px-3 py-2 border border-border-light rounded-md bg-bg-elevated"></textarea></label>{/each}
      </fieldset>
      <button type="button" class="btn btn-secondary" disabled={!canWrite || !!busy || dirty || assetDraftDirty || needsRefresh || writeUncertain} onclick={generatePreview}>{busy === 'preview' ? 'Rendering saved design…' : 'Generate PDF preview'}</button>
      {#if preview}
        {#key previewKey}<VerifiedPDFPages bytes={preview.bytes} expectedPages={preview.pages} proofKey={previewKey} onProof={receiveProof} />{/key}
        {#if !previewValid && !approved}<p role="note" class="text-sm text-warning">This preview is no longer current. Generate a new preview before approving.</p>{/if}
        {#if canApprove && !approved}
          <label class="flex items-start gap-3 text-sm"><input type="checkbox" bind:checked={acknowledged} disabled={!!busy || !previewValid || !allPagesSeen} class="mt-1" /><span>I have reviewed every PDF page, saved source, defaults, wording, local assets{saved.html_master_json?.schema_version !== 1 ? ', contract checks and intended party mappings' : ''}{saved.html_master_json?.schema_version === 3 ? ', appended signing page, saved branding and fixed signature locations' : ''}, and approve this exact design revision. Preview sample values and wording are separate from saved defaults.</span></label>
          {#if !allPagesSeen}<p class="text-sm text-text-secondary">Open every page before approving this revision.</p>{/if}
          <button type="button" class="btn btn-primary" disabled={!!busy || !previewValid || !allPagesSeen || !acknowledged} onclick={approve}>{busy === 'approve' ? 'Recording approval…' : 'Approve saved design revision'}</button>
        {/if}
      {/if}
      {#if !canApprove && !approved}<p role="note" class="text-sm">An owner must open this saved revision and generate their own preview before approving it.</p>{/if}
      {#if approved}<p role="status" class="text-sm text-success">This saved revision is approved. Return to the template library to populate a fresh document.</p>{/if}
    </section>
  {/if}
</div>
