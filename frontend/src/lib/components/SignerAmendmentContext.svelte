<script lang="ts">
 import { signerAmendmentProcess, type SignerAmendmentDisclosure } from '$lib/signerAmendment';
 let { disclosure }: { disclosure: SignerAmendmentDisclosure } = $props();
</script>
<section class="amendment-disclosure" aria-label="Amendment to an earlier agreement">
 <p class="eyebrow">Amendment to an earlier agreement</p>
 <h2>{disclosure.original_name}</h2>
 <p>Selected process: <strong>{signerAmendmentProcess(disclosure.mode)}</strong></p>
 <p>{disclosure.mode === 'signature' ? 'This separate amendment asks for fresh signatures.' : 'This separate amendment asks for an explicit acknowledgement using Accept. No signature is collected.'} Review the current amendment and accompanying documents before responding.</p>
 <p>The original signed agreement and its evidence remain saved. This reference describes the recorded relationship; it does not determine when changes take legal effect.</p>
 <details><summary>Saved agreement and amendment references</summary>
  <dl>
   <dt>Original agreement ID</dt><dd>{disclosure.original_document_id}</dd>
   <dt>Original signed PDF SHA-256</dt><dd>{disclosure.original_final_pdf_sha256}</dd>
   <dt>Original evidence report SHA-256</dt><dd>{disclosure.original_report_sha256}</dd>
   <dt>Original evidence report PDF SHA-256</dt><dd>{disclosure.original_report_pdf_sha256}</dd>
   <dt>Amendment ID</dt><dd>{disclosure.amendment_id}</dd>
   <dt>Amendment revision</dt><dd>{disclosure.revision}</dd>
   <dt>Saved amendment file commitment SHA-256</dt><dd>{disclosure.file_commitment_sha256}</dd>
  </dl>
  <p>These are saved document identifiers. This link permits review of the current amendment; access to the original agreement's private files is separate.</p>
 </details>
</section>
<style>
 .amendment-disclosure { border: 1px solid var(--t-border-light); background: var(--t-bg); color: var(--t-text); border-radius: .5rem; padding: 1.25rem; display: grid; gap: .65rem; font-size: .875rem; }
 .eyebrow { font-size: .7rem; letter-spacing: .08em; text-transform: uppercase; color: var(--t-text-muted); }
 h2 { font-size: 1.15rem; font-weight: 600; overflow-wrap: anywhere; }
 summary { cursor: pointer; }
 dl { display: grid; gap: .3rem; margin-top: .8rem; }
 dt { margin-top: .4rem; color: var(--t-text-muted); }
 dd { font-family: monospace; font-size: .75rem; overflow-wrap: anywhere; }
 details p { margin-top: .8rem; color: var(--t-text-muted); }
</style>
