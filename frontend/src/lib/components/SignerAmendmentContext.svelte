<script lang="ts">
 import { signerAmendmentProcess, type SignerAmendmentDisclosure } from '$lib/signerAmendment';
 import { locale } from '$lib/i18n';
 import { signerRoomText } from '$lib/signerRoomUi';
 let { disclosure }: { disclosure: SignerAmendmentDisclosure } = $props();
</script>
<section class="amendment-disclosure" aria-label={signerRoomText($locale, 'Amendment to an earlier agreement')}>
 <p class="eyebrow">{signerRoomText($locale, 'Amendment to an earlier agreement')}</p>
 <h2>{disclosure.original_name}</h2>
 <p>{signerRoomText($locale, 'Selected process')}: <strong>{signerRoomText($locale, signerAmendmentProcess(disclosure.mode))}</strong></p>
 <p>{signerRoomText($locale, disclosure.mode === 'signature' ? 'This separate amendment asks for fresh signatures.' : 'This separate amendment asks for an explicit acknowledgement using Accept. No signature is collected.')} {signerRoomText($locale, 'Review the current amendment and accompanying documents before responding.')}</p>
 <p>{signerRoomText($locale, 'The original signed agreement and its evidence remain saved. This reference describes the recorded relationship; it does not determine when changes take legal effect.')}</p>
 <details><summary>{signerRoomText($locale, 'Saved agreement and amendment references')}</summary>
  <dl>
   <dt>{signerRoomText($locale, 'Original agreement ID')}</dt><dd>{disclosure.original_document_id}</dd>
   <dt>{signerRoomText($locale, 'Original signed PDF SHA-256')}</dt><dd>{disclosure.original_final_pdf_sha256}</dd>
   <dt>{signerRoomText($locale, 'Original evidence report SHA-256')}</dt><dd>{disclosure.original_report_sha256}</dd>
   <dt>{signerRoomText($locale, 'Original evidence report PDF SHA-256')}</dt><dd>{disclosure.original_report_pdf_sha256}</dd>
   <dt>{signerRoomText($locale, 'Amendment ID')}</dt><dd>{disclosure.amendment_id}</dd>
   <dt>{signerRoomText($locale, 'Amendment revision')}</dt><dd>{disclosure.revision}</dd>
   <dt>{signerRoomText($locale, 'Saved amendment file commitment SHA-256')}</dt><dd>{disclosure.file_commitment_sha256}</dd>
  </dl>
  <p>{signerRoomText($locale, "These are saved document identifiers. This link permits review of the current amendment; access to the original agreement's private files is separate.")}</p>
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
