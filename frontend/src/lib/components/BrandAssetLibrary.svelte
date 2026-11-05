<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { staffLocale } from '$lib/staffPreferences';
  import { getMe, APIError } from '$lib/api/client';
  import { listBrandAssets, prepareBrandAsset, uploadBrandAsset, inspectBrandAssetUpload, brandAssetContentURL, type BrandAsset, type PreparedBrandAsset } from '$lib/api/brandAssets';
  import { Image, Upload, Download, Eye } from 'lucide-svelte';
  const text = (en: string, sv: string) => $staffLocale === 'sv' ? sv : en;
  let assets = $state<BrandAsset[]>([]);
  let selected = $state<BrandAsset | null>(null);
  let previewDark = $state(false);
  let owner = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');
  let name = $state('');
  let originals = $state<FileList | null>(null);
  let variants = $state<FileList | null>(null);
  let pending = $state<PreparedBrandAsset | null>(null);
  let canLoadMore = $state(false);
  let disposed = false;
  const controller = new AbortController();
  let action: AbortController | null = null;
  async function load(more = false) {
    const page = await listBrandAssets(controller.signal, more ? assets.at(-1)?.asset_id : undefined);
    if (disposed) return;
    const seen = new Set(assets.map(a => a.asset_id));
    assets = more ? [...assets, ...page.filter(a => !seen.has(a.asset_id))] : page;
    canLoadMore = page.length === 50;
  }
  onMount(() => {
    void Promise.all([load(), getMe().then(me => { if (!disposed) owner = me.role === 'owner'; })])
      .catch(() => { if (!disposed) error = text('The brand library could not be loaded.', 'Varumärkesbiblioteket kunde inte laddas.'); })
      .finally(() => { if (!disposed) loading = false; });
  });
  onDestroy(() => { disposed = true; controller.abort(); action?.abort(); });
  async function accept(asset: BrandAsset) {
    pending = null; selected = asset; originals = null; variants = null; name = '';
    assets = [asset, ...assets.filter(item => item.asset_id !== asset.asset_id)];
    notice = text('Original and rendering variant saved with verified checksums.', 'Original och renderingsvariant sparade med verifierade kontrollsummor.');
    try { await load(); }
    catch { if (!disposed) error = text('The asset is saved. The list could not be refreshed; the selected asset remains available.', 'Filen är sparad. Listan kunde inte uppdateras; den valda filen finns kvar.'); }
  }
  async function submit(event: SubmitEvent) {
    event.preventDefault(); if (busy || pending || !owner || !originals?.[0]) return;
    busy = true; error = ''; notice = '';
    action = new AbortController(); const timer = setTimeout(() => action?.abort(), 65000);
    try {
      const prepared = await prepareBrandAsset(name, originals[0], variants?.[0]);
      if (disposed) return;
      pending = prepared;
      const asset = await uploadBrandAsset(prepared, action.signal);
      if (!disposed) await accept(asset);
    } catch (failure) {
      if (failure instanceof APIError && [400, 402, 413, 415, 422].includes(failure.status)) pending = null;
      if (!disposed) error = failure instanceof APIError && failure.status === 402
        ? text('Your workspace plan does not include brand uploads.', 'Arbetsytans plan omfattar inte uppladdning av varumärkesfiler.')
        : pending
        ? text('Upload was not confirmed. Check its status before starting another upload.', 'Uppladdningen kunde inte bekräftas. Kontrollera status innan du laddar upp på nytt.')
        : text('Enter a name and choose an SVG or PNG original. SVG needs a PNG rendering variant. Originals: PNG max 8 MiB, SVG max 2 MiB; rendering PNG max 2 MiB.', 'Ange ett namn och välj ett SVG- eller PNG-original. SVG behöver en PNG-variant. Original: PNG högst 8 MiB, SVG högst 2 MiB; renderings-PNG högst 2 MiB.');
    } finally { clearTimeout(timer); action = null; if (!disposed) busy = false; }
  }
  async function inspect() {
    if (!pending || busy) return; busy = true; error = ''; action = new AbortController();
    const timer = setTimeout(() => action?.abort(), 15000);
    try {
      const asset = await inspectBrandAssetUpload(pending, action.signal);
      if (!disposed) { if (asset) await accept(asset); else notice = text('This exact upload is still being prepared. Keep its reference and check again shortly.', 'Den här uppladdningen förbereds fortfarande. Spara referensen och kontrollera snart igen.'); }
    } catch { if (!disposed) error = text('The upload status could not be confirmed. Keep the reference; no new upload was sent.', 'Status kunde inte bekräftas. Spara referensen; ingen ny uppladdning skickades.'); }
    finally { clearTimeout(timer); action = null; if (!disposed) busy = false; }
  }
  async function resume() {
    if (!pending || busy || !owner) return;
    busy = true; error = ''; action = new AbortController();
    const timer = setTimeout(() => action?.abort(), 65000);
    try { const asset = await uploadBrandAsset(pending, action.signal); if (!disposed) await accept(asset); }
    catch { if (!disposed) error = text('The same upload is still unconfirmed. Keep the reference and check its status.', 'Samma uppladdning är fortfarande obekräftad. Spara referensen och kontrollera status.'); }
    finally { clearTimeout(timer); action = null; if (!disposed) busy = false; }
  }
</script>

<section class="card p-5 mt-6 space-y-5" aria-label={text('Brand assets', 'Varumärkesfiler')}>
  <div><h2 class="text-lg font-semibold flex items-center gap-2"><Image class="size-4" />{text('Brand assets', 'Varumärkesfiler')}</h2>
    <p class="text-sm text-text-secondary mt-2">{text('Keep real logos and symbols in your workspace. Your AI can select these exact versions through the organisation brand profile. Uploads preserve the original artwork.', 'Spara riktiga logotyper och symboler i arbetsytan. Din AI kan välja de här exakta versionerna via organisationens varumärkesprofil. Uppladdningen bevarar originalet.')}</p></div>
  {#if error}<p class="text-sm text-danger" role="alert">{error}</p>{/if}
  {#if notice}<p class="text-sm text-success" role="status">{notice}</p>{/if}
  {#if owner}
    <form onsubmit={submit} class="space-y-4 border border-border-light rounded-xl p-4">
      <label class="block text-sm font-medium">{text('Asset name', 'Filnamn i biblioteket')}<input class="mt-1 w-full rounded-md border border-border-light bg-bg-elevated px-3 py-2" bind:value={name} maxlength="160" required disabled={busy || !!pending} /></label>
      <div class="grid sm:grid-cols-2 gap-4">
        <label class="block text-sm font-medium">{text('Original SVG or PNG', 'Original i SVG eller PNG')}<input class="block mt-2 text-sm max-w-full" type="file" accept="image/png,image/svg+xml,.png,.svg" bind:files={originals} required disabled={busy || !!pending} /></label>
        <label class="block text-sm font-medium">{text('PNG rendering variant (optional for small PNG)', 'PNG-variant för rendering (valfri för liten PNG)')}<input class="block mt-2 text-sm max-w-full" type="file" accept="image/png,.png" bind:files={variants} disabled={busy || !!pending} /></label>
      </div>
      <p class="text-xs text-text-muted">{text('Use a matching supplied PNG for SVG or large originals. Rendering variants are limited to 4 megapixels; Hash validates the files before storage. Adding an asset does not change existing documents.', 'Välj en motsvarande levererad PNG för SVG eller stora original. Renderingsvarianter får vara högst 4 megapixlar; Hash validerar filerna innan de lagras. Befintliga dokument ändras inte.')}</p>
      <button class="btn btn-primary" type="submit" disabled={busy || !!pending || !originals?.[0] || !name.trim()}><Upload class="size-4" />{text(busy ? 'Working…' : 'Upload original', busy ? 'Arbetar…' : 'Ladda upp original')}</button>
      {#if pending}<div class="space-y-2"><p class="text-xs break-all font-mono">{text('Upload reference', 'Uppladdningsreferens')}: {pending.input.request_id}</p><div class="flex flex-wrap gap-2"><button class="btn btn-secondary" type="button" onclick={inspect} disabled={busy}>{text('Check upload status', 'Kontrollera uppladdningsstatus')}</button><button class="btn btn-secondary" type="button" onclick={resume} disabled={busy}>{text('Retry this exact upload', 'Försök igen med samma uppladdning')}</button></div></div>{/if}
    </form>
  {/if}
  {#if loading}<p class="text-sm text-text-muted">{text('Loading brand assets…', 'Laddar varumärkesfiler…')}</p>
  {:else if assets.length === 0}<p class="text-sm text-text-muted">{text('No brand assets yet.', 'Inga varumärkesfiler ännu.')}</p>
  {:else}
    <div class="grid md:grid-cols-2 gap-4">
      <div class="space-y-2 max-h-96 overflow-y-auto">
        {#each assets as asset (asset.asset_id)}<button type="button" class="w-full rounded-lg border p-3 text-left transition-colors {selected?.asset_id === asset.asset_id ? 'border-accent bg-accent/5' : 'border-border-light hover:bg-bg-elevated'}" onclick={() => { selected = asset; }}>
          <span class="flex items-center gap-2 text-sm font-medium"><Eye class="size-4 shrink-0" /><span class="break-all">{asset.name}</span></span>
          <span class="block text-xs text-text-muted mt-1">r{asset.revision} · {asset.original.media_type === 'image/svg+xml' ? 'SVG' : 'PNG'} · {asset.original.width} × {asset.original.height}</span>
        </button>{/each}
        {#if canLoadMore}<button class="btn btn-secondary" type="button" onclick={() => { void load(true).catch(() => { error = text('Could not load more assets.', 'Kunde inte ladda fler filer.'); }); }}>{text('Load more', 'Visa fler')}</button>{/if}
      </div>
      {#if selected}<div class="border border-border-light rounded-xl p-4 space-y-3 min-w-0">
        <div class="flex flex-wrap gap-2 text-xs"><span class="py-2 text-text-secondary">{text('Preview background', 'Förhandsvisningens bakgrund')}</span><button class="btn btn-secondary" type="button" aria-pressed={!previewDark} onclick={() => { previewDark = false; }}>{text('Light', 'Ljus')}</button><button class="btn btn-secondary" type="button" aria-pressed={previewDark} onclick={() => { previewDark = true; }}>{text('Dark', 'Mörk')}</button></div>
        <div class="rounded-lg h-40 p-5 flex items-center justify-center {previewDark ? 'bg-neutral-900' : 'bg-neutral-100'}"><img src={brandAssetContentURL(selected, 'render')} alt={selected.name} class="max-w-full max-h-full object-contain" /></div>
        <p class="text-xs text-text-muted break-all">{text('Stable asset ID', 'Stabilt fil-ID')}: <code>{selected.asset_id}</code> · r{selected.revision}</p>
        <p class="text-xs text-text-muted break-all">SHA-256 <code>{selected.original.sha256}</code></p>
        <a class="btn btn-secondary" href={brandAssetContentURL(selected, 'original')} download><Download class="size-4" />{text('Download original', 'Ladda ner original')}</a>
      </div>{:else}<p class="text-sm text-text-muted p-4">{text('Choose an asset to preview its safe PNG variant.', 'Välj en fil för att förhandsvisa dess säkra PNG-variant.')}</p>{/if}
    </div>
  {/if}
</section>
