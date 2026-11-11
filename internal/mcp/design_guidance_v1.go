// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import "github.com/bright-interaction/hash/internal/htmlmaster"

const designedDocumentGuideV1 = `Choose the authoring route deliberately.
For proposals, quotes, reports and page-layout brochures, default to a designed
HTML master. If the user explicitly wants a simple document, or the task is
structured content/contract clauses without page-layout requirements, use native
blocks. import_html converts fragments into blocks; it is not layout-preserving.
create_pdf_document is compatibility PDF intake and loses the editable HTML
master. Do not choose it as a shortcut for a new editable designed document.

Before drafting, establish document type, audience, purpose, scope and supplied
commercial terms. Preserve supplied numbers, currency, cancellation/binding
terms and qualifications exactly. Flag missing material facts; do not invent
governing law, prices, currency, discounts, binding periods, recipients or claims.
Use purpose=document or presentation for internal content; signing is a separate
explicit choice. Creating or reviewing a design does not authorize email/Send.

Discover the complete brand profile and exact asset revisions. Resolve a design
bundle; follow its semantic colors, typography, spacing, clear space, minimum
logo size, allowed backgrounds, voice and do/don't guidance. Original SVGs and
oversized original PNGs are catalog/source assets, not automatically usable
HTML assets. Select exact opaque profile/revision/asset_slots; reference the
resolver's safe PNG names as hash-asset:brand_<slot>. The server resolves verified
bytes before complete native master admission; do not copy PNG base64 through
the model or collide with those reserved selected names. Retain the asset SHA
and exact profile revision. Do not fetch
network assets or retype a logo. Extra vetted embedded WOFF/WOFF2 fonts may be
used within native master limits; use consistent supplied font bytes when exact
typography matters. No customer's palette, logo or content is a product default.
Use bounded absolute HTTPS <a href> links for supplied sources and retain
visible source URLs. The renderer never fetches linked source pages. Native
PDF sanitization removes ordinary hyperlink annotations; retained HTML anchors
do not prove clickable links in the saved/final Hash PDF. Inspect the exact
Hash PDF and report this limitation; never bypass the PDF security proof.

Compose a suitable hierarchy: an informative opening, clear section levels,
concise body text, readable tables, selective emphasis and useful whitespace.
Plan page size/orientation, margins, realistic page count and header/footer
clearance for the audience and document type. Use @page and native break-before,
break-after/break-inside controls. Keep headings with following content and
tables readable. Use declared values/sections for editable plain text. The
native CSS subset has no CSS custom properties, arbitrary at-rules or @page
margin boxes. Do not assume a running footer cannot overlap content.
Use inert body tags such as main/section/article/header/footer/div/span,
headings, paragraphs, lists, tables, img and HTTPS a links. Use div instead of
aside. Global class/id/title/lang/dir attributes and declared text markers are
supported; arbitrary data-* bookkeeping attributes are not. Prefer explicit
classes to functional selectors such as :nth-child(...); CSS comments, escapes
and the child-combinator > are refused by the native subset. Use font-variant
rather than font-variant-numeric. Print-color-adjust properties are unsupported.

Save a versioned design using create_design_template or update_design_template.
Read back its version/content commitment, then preview_design_template with
those exact pins. Download the returned exact PDF bytes. RENDER EVERY PAGE TO
AN IMAGE AND VISUALLY INSPECT EVERY PAGE at useful scale: typography, contrast,
logo fidelity, truncation, overflow, table splits, page breaks, blank pages and
header/footer collisions. Inspect each page individually; a contact sheet is
only an overview. Fix the editable master and re-render/re-inspect all pages.

Storage success, source readback, hashes, page count and successful rendering
are NOT visual proof. If the host cannot obtain/render/view these page images,
say visual review is pending and do not approve or claim the design is ready.
Template approval is a human act. No tool approves a design: after you have
inspected every page, tell the user the design is ready for review and an owner
approves the exact version in the Hash app. Until then the template is not
approved and create_document_from_design refuses it.

Instantiate the exact approved design using create_document_from_design with
an explicit purpose and a unique request_id. The document freezes that approved
master/version/assets. Inspect the resulting document's exact PDF on EVERY PAGE
again because populated text may change pagination. Only then explicitly
review_document_design with its current updated_at, source commitment/PDF SHA
and every reviewed page. Agents may review only non-signing documents (purpose
document or presentation); a signing document, acknowledgement mode included, is
reviewed by a human in a staff session and this tool refuses it.
No tool adds recipients, sends, or approves terms here.

get_document_design_source identifies the frozen origin and editable template.
Pass its editable_template.read_arguments to get_design_template to recover the
exact immutable version/content SHA, even after the parent template advances.
That read separates current_parent_version/name from selected version/master
and selected revision approval. Omitting both pins reads the current template;
never substitute that current source for a document's older frozen source.
get_document_design_history and download_document_pdf inspect exact retained
PDFs. revise_document_design_values changes declared plain text only and resets
review/field placement. Layout/assets edits require a new editable template
version, preview, approval by a human owner in the app and a new document from that version;
they do not rewrite an existing document's frozen design or signed artifacts.
When updating a catalog-bound master returned by get_design_template, omit the
selected server-injected brand_<slot> entries from input.html_master_json.assets and pass the
same exact brand_profile/asset_slots instead. The server re-resolves them;
client collisions with selected names are refused. Keep other authored assets.
Report saved, rendered, visually inspected, explicitly approved and sent states
separately, with the exact document/version/PDF commitment and any pending work.`

func htmlMasterSchemaV1() map[string]any {
	text := func(max int) map[string]any { return map[string]any{"type": "string", "maxLength": max} }
	name := func() map[string]any { return map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"} }
	return map[string]any{
		"schema": schemaObject(map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"html":           text(htmlmaster.MaxHTMLBytes), "css": text(htmlmaster.MaxCSSBytes),
			"values":   map[string]any{"type": "array", "maxItems": htmlmaster.MaxDefinitions, "items": schemaObject(map[string]any{"name": name(), "required": map[string]any{"type": "boolean"}, "max_chars": map[string]any{"type": "integer", "minimum": 1, "maximum": htmlmaster.MaxValueChars}}, []string{"name", "max_chars"})},
			"sections": map[string]any{"type": "array", "maxItems": htmlmaster.MaxDefinitions, "items": schemaObject(map[string]any{"name": name(), "default_text": text(htmlmaster.MaxSectionChars), "max_chars": map[string]any{"type": "integer", "minimum": 1, "maximum": htmlmaster.MaxSectionChars}}, []string{"name", "default_text", "max_chars"})},
			"assets":   map[string]any{"type": "array", "maxItems": htmlmaster.MaxAssets, "items": schemaObject(map[string]any{"name": name(), "media_type": map[string]any{"type": "string", "enum": []string{"image/png", "image/jpeg", "font/woff", "font/woff2"}}, "data_base64": map[string]any{"type": "string"}, "sha256": map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"}}, []string{"name", "media_type", "data_base64", "sha256"})},
		}, []string{"schema_version", "html", "css"}),
		"scope":           "Generic content design schema 1. Native reviewed-contract/signing-page schemas 2/3 retain their separate exact legal/party/placement policies.",
		"text_bindings":   map[string]string{"value": "<span data-hash-value=\"company\"></span>", "section": "<div data-hash-section=\"scope\"></div>"},
		"asset_reference": "hash-asset:<asset.name>; no network resource URLs, arbitrary SVG, scripts, template evaluation or CSS custom properties. Supplied source links may use bounded absolute HTTPS <a href> navigation.",
		"limits":          map[string]int{"master_bytes": htmlmaster.MaxMasterJSONBytes, "html_bytes": htmlmaster.MaxHTMLBytes, "css_bytes": htmlmaster.MaxCSSBytes, "asset_bytes": htmlmaster.MaxAssetBytes, "total_asset_bytes": htmlmaster.MaxTotalAssetBytes},
		"transport":       "The MCP request envelope has its own bounded limit; native master maxima are not a promise that one MCP request can carry that many bytes.",
	}
}
