// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"fmt"
	"strings"
)

// The original final-document formatter shared without changing its bytes.
func BuildHTMLDocumentV1(brandCSS, body, cert string) string {
	certificateStart := ""
	if strings.TrimSpace(body) == "" && strings.TrimSpace(cert) != "" {
		// Standalone evidence has no preceding contract body. Forcing a page
		// break here otherwise leaves a blank branded page before the cert.
		certificateStart = finalCertificateStartV1
	}
	// Branding CSS is emitted FIRST so its custom properties on :root are
	// available to the base stylesheet's rules below. The base styles use
	// var(--hash-text) etc. with safe fallbacks so an unconfigured
	// org still renders with the system defaults.
	// Layout note: every visible rule is scoped under .hash-doc so injecting
	// this whole document into the signer SPA via {@html} can't leak typography
	// onto the app chrome. The content lives in a centered, fixed-measure column
	// (Google-Docs feel); page geometry/margins are set by Gotenberg on render.
	return fmt.Sprintf(finalDocumentHTMLFormatV1, brandCSS, SignatureCSSV1(), certificateStart, body, cert)
}

const finalCertificateStartV1 = ".hash-doc > .hash-cert-page { page-break-before: auto; break-before: auto; }"

// Format percent escapes shrink; all substitutions are priced separately.
// This derives the fixed stylesheet, signature font stylesheet and conditional
// certificate rule allowance without formatting any customer-provided input.
func FinalDocumentHTMLFixedBytesV1() int64 {
	return int64(len(finalDocumentHTMLFormatV1) + len(SignatureCSSV1()) + len(finalCertificateStartV1))
}

const finalDocumentHTMLFormatV1 = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" />
%s
<style>
  * { box-sizing: border-box; }
  body { margin: 0; }
  .hash-doc { max-width: 46rem; margin: 0 auto; font-family: var(--hash-font-body, Inter), system-ui, -apple-system, sans-serif; font-size: 11.5px; line-height: 1.65; color: var(--hash-text, #18181b); }
  .hash-doc__rule { height: 3px; border-radius: 2px; background: var(--hash-accent, #0891B2); margin: 0 0 26px; }
  .hash-doc h1 { font-family: var(--hash-font-heading, Geist), sans-serif; font-weight: 600; font-size: 24px; line-height: 1.2; letter-spacing: -0.01em; margin: 6px 0 14px; color: var(--hash-primary, #18181b); }
  .hash-doc h2 { font-family: var(--hash-font-heading, Geist), sans-serif; font-weight: 600; font-size: 14.5px; margin: 22px 0 9px; padding-left: 11px; border-left: 3px solid var(--hash-accent, #0891B2); color: var(--hash-primary, #18181b); }
  .hash-doc h3 { font-family: var(--hash-font-heading, Geist), sans-serif; font-weight: 600; font-size: 12.5px; margin: 16px 0 6px; color: var(--hash-primary, #18181b); }
  .hash-doc p { margin: 8px 0; }
  /* Pagination: keep each section (heading + its content) whole; if it would be
     cut by a page edge, move it to the next page instead of splitting it. */
  .hash-doc .doc-section { break-inside: avoid; page-break-inside: avoid; margin: 0 0 12px; }
  .hash-doc .doc-section:first-child { margin-top: 0; }
  .hash-doc a { color: var(--hash-accent, #0891B2); }
  .hash-doc ul, .hash-doc ol { margin: 9px 0; padding-left: 22px; }
  .hash-doc li { margin: 5px 0; }
  .hash-doc strong { font-weight: 600; color: var(--hash-primary, #18181b); }
  .hash-doc table { border-collapse: collapse; width: 100%%; margin: 10px 0; break-inside: auto; }
  .hash-doc th, .hash-doc td { padding: 6px 9px; border-bottom: 1px solid #e7e5e4; text-align: left; vertical-align: top; }
  .hash-doc th { font-size: 8.5px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--hash-muted, #52525b); }
  /* A table may span pages, but never split a row; repeat the header on each page. */
  .hash-doc thead { display: table-header-group; }
  .hash-doc tr, .hash-doc th, .hash-doc td { break-inside: avoid; page-break-inside: avoid; }
  .hash-doc hr { border: 0; border-top: 1px solid #e7e5e4; margin: 16px 0; }
  .hash-doc p, .hash-doc li, .hash-doc blockquote { break-inside: avoid; page-break-inside: avoid; }
  .hash-doc h1, .hash-doc h2, .hash-doc h3 { break-after: avoid; page-break-after: avoid; }
  .hash-doc blockquote { margin: 12px 0; padding: 11px 16px; border-left: 3px solid var(--hash-accent, #0891B2); background: rgba(8,145,178,0.06); color: var(--hash-text, #18181b); border-radius: 0 7px 7px 0; }
  .hash-doc blockquote p { margin: 0; }
  .hash-doc pre { background: #f5f5f4; border: 1px solid #e7e5e4; border-radius: 6px; padding: 10px; font-size: 11px; overflow-x: auto; }
  .hash-doc img { max-width: 100%%; }
  %s
  .hash-doc .hash-cert-page table { table-layout: fixed; }
  .hash-doc .hash-cert-page td, .hash-doc .hash-cert-page code { overflow-wrap: anywhere; }
  /* Both certificate finishers append the crypto footer as the final direct div. */
  .hash-doc > .hash-cert-page > div:last-child { break-inside: avoid; page-break-inside: avoid; }
  .hash-doc .hash-cert-page > table:first-of-type th:nth-child(1) { width: 12%%; }
  .hash-doc .hash-cert-page > table:first-of-type th:nth-child(2) { width: 23%%; }
  .hash-doc .hash-cert-page > table:first-of-type th:nth-child(3) { width: 12%%; }
  .hash-doc .hash-cert-page > table:first-of-type th:nth-child(4) { width: 17%%; }
  .hash-doc .hash-cert-page > table:first-of-type th:nth-child(5) { width: 13%%; }
  .hash-doc .hash-cert-page > table:first-of-type th:nth-child(6) { width: 23%%; }
  %s
  .hash-field--signed { display: inline-block; min-width: 340px; border-bottom: 1.5px solid var(--hash-primary, #18181b); padding: 0.15em 0.4em 0.3em; background: transparent; }
  .hash-field--unsigned { display: inline-block; min-width: 340px; border-bottom: 1.5px dashed var(--hash-accent, #0891B2); padding: 0.5em 0.4em; color: var(--hash-muted, #52525b); font-style: italic; }
</style>
</head><body>
<div class="hash-doc">
<div class="hash-doc__rule"></div>
%s
%s
</div>
</body></html>`
