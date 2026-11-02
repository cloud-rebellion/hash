<script lang="ts">
  import { onMount } from 'svelte';
  import { ui } from '$lib/staffPreferences';
  import { ShieldCheck, ShieldAlert, Key, Upload, FileCheck2, CheckCircle2, XCircle } from 'lucide-svelte';

  type VerifyBundleCheck = {
    name: string;
    ok: boolean;
    expected: string;
    actual: string;
    detail?: string;
  };
  type VerifyBundleReport = {
    ok: boolean;
    document_id: string;
    document_name: string;
    issuer: string;
    generated_at: string;
    signature_valid: boolean;
    signature_note?: string;
    manifest_signature_valid: boolean;
    key_trusted: boolean;
    manifest_key_trusted: boolean;
    certificate_key_trusted: boolean;
    manifest_public_key_b64?: string;
    certificate_public_key_b64?: string;
    checks: VerifyBundleCheck[];
    errors?: string[];
    warnings?: string[];
  };

  let serverPubKey = $state<string>('');
  let pubKey = $state('');
  let payload = $state('');
  let sig = $state('');
  let result = $state<'idle' | 'valid' | 'untrusted' | 'invalid' | 'error'>('idle');
  let checking = $state(false);
  let errorMsg = $state<string | null>(null);

  let dragging = $state(false);
  let bundleReport = $state<VerifyBundleReport | null>(null);
  let bundleError = $state<string | null>(null);
  let bundleLoading = $state(false);

  onMount(async () => {
    try {
      const res = await fetch('/.well-known/hash-public-key');
      if (res.ok) {
        const body = await res.json();
        serverPubKey = body.public_key_b64 ?? '';
        if (!pubKey && serverPubKey) pubKey = serverPubKey;
      }
    } catch (_) {
      // best-effort; user can still paste a key manually
    }
  });

  async function check(e: Event) {
    e.preventDefault();
    if (checking) return;
    checking = true;
    result = 'idle';
    errorMsg = null;
    try {
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          public_key_b64: pubKey.trim(),
          payload,
          signature_b64: sig.trim()
        })
      });
      if (!res.ok) {
        result = 'error';
        errorMsg = await res.text();
        return;
      }
      const body = await res.json();
      result = body.authentic_hash_evidence ? 'valid' : body.valid ? 'untrusted' : 'invalid';
    } catch (e) {
      result = 'error';
      errorMsg = (e as Error).message;
    } finally { checking = false; }
  }

  async function verifyBundle(file: File) {
    if (bundleLoading) return;
    bundleError = null;
    bundleReport = null;
    bundleLoading = true;
    try {
      const form = new FormData();
      form.append('bundle', file);
      const res = await fetch('/api/verify-bundle', {
        method: 'POST',
        body: form
      });
      if (!res.ok) {
        bundleError = await res.text();
        return;
      }
      bundleReport = (await res.json()) as VerifyBundleReport;
    } catch (e) {
      bundleError = (e as Error).message;
    } finally {
      bundleLoading = false;
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    if (bundleLoading) return;
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.pdf')) {
      bundleError = 'expected a Hash evidence bundle PDF';
      return;
    }
    verifyBundle(file);
  }

  function onPick(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) verifyBundle(file);
  }

  function abbrev(hex: string): string {
    if (!hex) return '';
    if (hex.length <= 16) return hex;
    return hex.slice(0, 8) + '…' + hex.slice(-8);
  }
</script>

<div class="max-w-5xl mx-auto px-5 sm:px-6 py-8 sm:py-10">
  <div class="mb-7"><p class="page-eyebrow mb-2">{$ui('Trust & evidence')}</p><h1 class="page-title">{$ui('Verify document evidence')}</h1><p class="text-sm text-text-secondary mt-3 max-w-2xl">{$ui('Check that a completed document and its signing evidence match the package issued by Hash.')}</p></div>
  <div class="grid sm:grid-cols-3 gap-4 mb-7">
    <div class="card p-5"><span class="text-xs font-mono text-text-muted">01</span><h2 class="font-medium text-sm mt-2">{$ui('Export the evidence')}</h2><p class="text-sm text-text-secondary mt-2">{$ui('Open a completed document and choose Export evidence package.')}</p></div>
    <div class="card p-5"><span class="text-xs font-mono text-text-muted">02</span><h2 class="font-medium text-sm mt-2">{$ui('Choose the evidence PDF')}</h2><p class="text-sm text-text-secondary mt-2">{$ui('Use the exported package, which includes the document and its audit evidence.')}</p></div>
    <div class="card p-5"><span class="text-xs font-mono text-text-muted">03</span><h2 class="font-medium text-sm mt-2">{$ui('Review the result')}</h2><p class="text-sm text-text-secondary mt-2">{$ui('Hash checks the file hashes, audit events, cryptographic signatures and issuer keys.')}</p></div>
  </div>
  <div class="rounded-xl border border-info/20 bg-info/5 p-4 text-sm text-text-secondary mb-7"><p class="font-medium text-text-primary mb-1">{$ui('Checked by this Hash server')}</p><p>{$ui('Selecting a PDF uploads the complete evidence package to this server. Only upload documents you are authorized to share. This page does not verify files offline.')}</p></div>
    <section class="mb-8">
      <h2 class="text-lg font-medium mb-2">{$ui('Verify an evidence package')}</h2>
      <p class="text-text-secondary text-sm mb-4">{$ui('Choose a Hash evidence bundle PDF. A regular contract PDF on its own does not contain the full verification package.')}</p>
      <label for="evidence-bundle" class="block rounded-2xl border-2 border-dashed p-7 sm:p-10 text-center transition-colors" class:border-border={!dragging} class:border-accent={dragging} class:bg-bg-elevated={dragging} ondragover={e => { e.preventDefault(); if (!bundleLoading) dragging = true; }} ondragleave={() => dragging = false} ondrop={onDrop}>
        <Upload class="size-8 mx-auto mb-3 text-text-secondary" />
        <span class="block text-sm font-medium mb-4">{$ui('Drop your evidence PDF here, or choose a file')}</span>
        <input id="evidence-bundle" type="file" accept="application/pdf,.pdf" disabled={bundleLoading} aria-label={$ui('Choose evidence PDF')} class="block mx-auto max-w-full text-sm text-text-secondary file:mr-3 file:rounded-lg file:border-0 file:bg-accent file:px-4 file:py-2.5 file:font-medium file:text-accent-foreground" onchange={onPick} />
      </label>

      {#if bundleLoading}
        <p class="text-text-muted text-xs mt-3">{$ui('Verifying…')}</p>
      {/if}
      {#if bundleError}
        <div class="card p-4 mt-4 border border-danger/30">
          <p class="text-danger text-sm">{$ui(bundleError)}</p>
        </div>
      {/if}
      {#if bundleReport}
        <div class="card p-6 mt-4 space-y-4" role="status" aria-live="polite">
          <div class="flex items-start gap-3">
            {#if bundleReport.ok}
              <ShieldCheck class="size-7 text-success shrink-0" />
              <div>
                <h3 class="text-lg font-medium text-success">{$ui('Core Hash bundle verified')}</h3>
                <p class="text-text-muted text-xs">{$ui('Artifact hashes, signed identity, ceremony event rows, both signatures, and both issuer keys verified. Optional extension warnings are reported separately.')}</p>
              </div>
            {:else}
              <ShieldAlert class="size-7 text-danger shrink-0" />
              <div>
                <h3 class="text-lg font-medium text-danger">{$ui('Verification failed')}</h3>
                <p class="text-text-muted text-xs">{$ui('An artifact, signed commitment, signature, or trusted-key check failed. See details below.')}</p>
              </div>
            {/if}
          </div>

          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
            {#if bundleReport.document_name}
              <div><dt class="text-text-muted">{$ui('Document')}</dt><dd>{bundleReport.document_name}</dd></div>
            {/if}
            {#if bundleReport.document_id}
              <div><dt class="text-text-muted">{$ui('Document ID')}</dt><dd class="font-mono break-all">{bundleReport.document_id}</dd></div>
            {/if}
            {#if bundleReport.issuer}
              <div><dt class="text-text-muted">{$ui('Issuer')}</dt><dd>{bundleReport.issuer}</dd></div>
            {/if}
            {#if bundleReport.generated_at}
              <div><dt class="text-text-muted">{$ui('Generated')}</dt><dd>{bundleReport.generated_at}</dd></div>
            {/if}
          </dl>

          <div>
            <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">{$ui('Cryptographic signatures and issuer trust')}</h4>
            <div class="flex items-center gap-2 text-sm">
              {#if bundleReport.signature_valid && bundleReport.manifest_signature_valid && bundleReport.key_trusted}
                <CheckCircle2 class="size-4 text-success" />
                <span><strong>{$ui('Both Ed25519 signatures valid')}</strong>; the certificate key is current or retained historical, and the export-manifest key is current.</span>
              {:else}
                <XCircle class="size-4 text-danger" />
                <span>{bundleReport.signature_note ?? 'certificate/manifest signature or issuer trust could not be verified'}</span>
              {/if}
            </div>
            {#if bundleReport.certificate_public_key_b64}
              <p class="text-text-muted text-xs mt-2 break-all font-mono">Certificate key: {bundleReport.certificate_public_key_b64}</p>
            {/if}
            {#if bundleReport.manifest_public_key_b64}
              <p class="text-text-muted text-xs mt-1 break-all font-mono">Export key: {bundleReport.manifest_public_key_b64}</p>
            {/if}
          </div>

          <div>
            <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">{$ui('Artifact hashes')}</h4>
            <ul class="space-y-1 text-xs">
              {#each bundleReport.checks as c (c.name)}
                <li class="flex items-center gap-2">
                  {#if c.ok}
                    <CheckCircle2 class="size-3.5 text-success shrink-0" />
                  {:else}
                    <XCircle class="size-3.5 text-danger shrink-0" />
                  {/if}
                  <code class="font-mono">{c.name}</code>
                  <span class="text-text-muted">·</span>
                  <span class="text-text-muted">{$ui('expected')}</span>
                  <code class="font-mono text-[10px]">{abbrev(c.expected)}</code>
                  {#if c.detail}
                    <span class="text-danger">({c.detail})</span>
                  {:else if !c.ok}
                    <span class="text-text-muted">·</span>
                    <span class="text-text-muted">{$ui('actual')}</span>
                    <code class="font-mono text-[10px] text-danger">{abbrev(c.actual)}</code>
                  {/if}
                </li>
              {/each}
            </ul>
          </div>

          {#if bundleReport.errors && bundleReport.errors.length}
            <div>
              <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">{$ui('Errors')}</h4>
              <ul class="text-xs text-danger space-y-1">
                {#each bundleReport.errors as e}<li>{e}</li>{/each}
              </ul>
            </div>
          {/if}

          {#if bundleReport.warnings && bundleReport.warnings.length}
            <div class="card p-3 border border-warning/40">
              <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">{$ui('Warnings')}</h4>
              <ul class="text-xs text-warning space-y-1">
                {#each bundleReport.warnings as warning}<li>{warning}</li>{/each}
              </ul>
            </div>
          {/if}
        </div>
      {/if}
    </section>

    <details class="card p-5 sm:p-6 mt-8">
      <summary class="cursor-pointer font-medium flex items-center gap-2"><FileCheck2 class="size-4" />{$ui('Advanced: verify an audit certificate')}</summary>
      <p class="text-text-secondary text-sm my-4">{$ui('Use this when you already have the certificate body, signature and public key. For a complete exported package, use the PDF check above.')}</p>
    {#if serverPubKey}
      <div class="card p-4 mb-6">
        <div class="flex items-center gap-2 text-text-muted text-xs mb-2">
          <Key class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">{$ui("This server's public key")}</span>
        </div>
        <code class="block break-all text-xs font-mono">{serverPubKey}</code>
      </div>
    {/if}
    <form onsubmit={check} class="card p-6 space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1" for="pub">{$ui('Public key (base64)')}</label>
        <input id="pub" bind:value={pubKey} required class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs" />
      </div>
      <div>
        <label class="block text-sm font-medium mb-1" for="payload">{$ui('Certificate body (the bytes that were signed)')}</label>
        <textarea id="payload" bind:value={payload} rows="6" required class="w-full p-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs"></textarea>
      </div>
      <div>
        <label class="block text-sm font-medium mb-1" for="sig">{$ui('Signature (base64)')}</label>
        <input id="sig" bind:value={sig} required class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs" />
      </div>
      <button type="submit" class="btn btn-primary" disabled={checking}>{$ui(checking ? 'Verifying…' : 'Verify certificate')}</button>

      {#if result === 'valid'}
        <div class="flex items-center gap-2 text-success p-3 rounded-md bg-bg-elevated">
          <ShieldCheck class="size-5" />
          <span><strong>{$ui('Authentic Hash evidence.')}</strong> {$ui('The signature is valid and the public key is trusted by this Hash verifier.')}</span>
        </div>
      {:else if result === 'untrusted'}
        <div class="flex items-center gap-2 text-danger p-3 rounded-md bg-bg-elevated">
          <ShieldAlert class="size-5" />
          <span><strong>{$ui('Cryptographically valid, but not trusted as Hash-issued.')}</strong> {$ui("The supplied key is not in this verifier's current or historical issuer set.")}</span>
        </div>
      {:else if result === 'invalid'}
        <div class="flex items-center gap-2 text-danger p-3 rounded-md bg-bg-elevated">
          <ShieldAlert class="size-5" />
          <span><strong>{$ui('Invalid.')}</strong> {$ui('The signature does not match the body bytes for this public key.')}</span>
        </div>
      {:else if result === 'error'}
        <div class="text-danger text-sm">{$ui('Error')}: {$ui(errorMsg ?? "")}</div>
      {/if}
    </form>

    <p class="text-text-muted text-xs mt-6">
      {$ui('Independent offline verification can use a local Ed25519 library. This page uses the Hash server. Algorithm: ed25519. Domain separator:')}
      <code class="font-mono">hash:audit-cert:v1:</code>
    </p>
    </details>
</div>
