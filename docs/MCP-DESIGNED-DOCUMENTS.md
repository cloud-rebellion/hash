# Branded designed documents through MCP

Use the versioned HTML design workflow for proposals, quotes, reports and
page-layout brochures. Native blocks remain the explicit simple route and suit
structured content or contracts without custom page-layout requirements. Start
with `hash://guides/designed-documents`, `hash://schema/html-master` and the
`draft_branded_document` prompt. Preserve supplied commercial terms; flag missing
facts instead of inventing prices, currency, binding periods, governing law,
cancellation terms, claims or recipients.

This is a source contract, not evidence that a particular installation has been
deployed, configured or visually accepted.

## Discover a brand and usable assets

`list_brand_profiles`, `get_brand_profile` and `list_brand_profile_revisions`
provide complete semantic colors, typography, spacing, usage guidance and exact
asset references. Reads may request a current revision; design writes bind the
returned explicit `profile_id`, `revision` and `content_sha256`.

`list_brand_assets` / `get_brand_asset` distinguish retained originals from safe
PNG render variants. SVG and oversized PNG originals are source assets; they
are not automatically usable in a master. Metadata omits storage keys, URLs and
object VersionIDs. Owner tools `save_brand_profile`, `upload_brand_asset` and
`select_default_brand_profile` retain native authorization, revision CAS and the
branding entitlement. Saving a profile does not silently select a default or
rewrite existing documents.

Call `resolve_brand_design_assets` with exact profile pins and selected
`asset_slots`. It returns names such as `brand_logo_primary`, dimensions, usage,
asset IDs/revisions and PNG commitments without transporting image bytes through
the model. A catalog can contain more than 16 assets; select only the slots used
in this design. An individual native master still permits at most 16 total
assets, 2 MiB per asset and 8 MiB total. Additional embedded WOFF/WOFF2 font assets
count toward those limits.

## Save an editable source

```json
{
  "brand_profile": {
    "profile_id": "<observed profile UUID>",
    "revision": 3,
    "content_sha256": "<observed lowercase SHA-256>",
    "asset_slots": ["logo_primary"]
  },
  "input": {
    "name": "Example organization proposal design",
    "html_master_json": {
      "schema_version": 1,
      "html": "<main><img src=\"hash-asset:brand_logo_primary\" alt=\"Example organization\"><h1>Proposal for <span data-hash-value=\"customer\"></span></h1><div data-hash-section=\"scope\"></div></main>",
      "css": "@page{size:A4;margin:20mm;}main{font-family:Arial;color:#172033;}img{width:160px;}h1{font-size:28px;}div{white-space:pre-wrap;}",
      "values": [{"name":"customer","required":true,"max_chars":200}],
      "sections": [{"name":"scope","default_text":"Supplied scope, unchanged.","max_chars":4000}]
    },
    "variables_json": {"customer":"Example customer"}
  }
}
```

Pass this to `create_design_template`. The server resolves the exact selected
safe PNG versions, refuses collisions with client asset names, acquires bounded
memory before expansion, then admits and canonicalizes the complete expanded
master through the native HTML producer. Profile provenance binds atomically to
the saved template revision. No arbitrary network URLs are fetched.

The master contains an inert HTML body fragment and separate CSS. It is not a
full `html/head/body` document. Dynamic declared values and sections are plain
text, escaped during materialization. Arbitrary SVG, scripts, CSS custom
properties and `@page` margin boxes are unsupported. Use supported page/break
controls and leave enough physical space for headers and footers.
Supplied source references may use bounded absolute HTTPS `<a href>` links and
should retain visible URLs. Linked pages are not fetched; remote resource URLs
remain forbidden. Native PDF sanitization removes ordinary hyperlink annotations:
retained editable HTML anchors do not establish clickable links in the saved or
final Hash PDF. Check the exact PDF and report that limitation. No PDF security
proof exception is part of this workflow.

`update_design_template` accepts the same shape plus `template_id` and
`input.expected_version`. It produces a new editable design version and requires
fresh preview/approval. Existing documents retain their frozen approved origin.
When editing a master read back from a catalog-bound template, omit its selected
server-injected `brand_<slot>` assets from `input.html_master_json.assets` and provide the exact
`brand_profile`/`asset_slots` again. The server re-resolves those bytes and refuses
client collisions. Preserve unrelated authored assets such as embedded fonts.

## Preview, inspect and explicitly approve

`preview_design_template` takes `template_id` and
`input:{expected_version,expected_content_sha256,values?,sections?}`. It returns
exact `pdf_base64`, `pdf_sha256`, `page_count`, a materialization commitment and an
expiring `preview_receipt` bound to the exact API key, actor, organization,
template/version/content and PDF. It neither approves nor creates a document.

Render these exact PDF bytes to page images and inspect **every page individually**
at useful scale. Check logo fidelity, typography, contrast, clipping, overflow,
tables, breaks, blank pages and header/footer collisions. A contact sheet is an
overview only. Fix the editable design, render again and inspect every page.
If the host cannot obtain, render or view page images, report visual review
pending; do not approve or call the design ready.

After actual inspection an owner may call `approve_design_template` with:

```json
{
  "template_id":"<design UUID>",
  "visually_reviewed":true,
  "reviewed_pages":[1,2],
  "input":{
    "expected_version":3,
    "expected_content_sha256":"<observed SHA-256>",
    "preview_receipt":"<receipt from this exact preview>",
    "expected_preview_pdf_sha256":"<preview PDF SHA-256>"
  }
}
```

`reviewed_pages` must cover exactly `1..page_count`. This is an explicit caller
attestation; it is not machine proof of aesthetics, approval of contractual terms
or authorization to send. A cookie preview receipt cannot substitute for an
API-key receipt. Revocation, expiry or changed source still refuses approval.

## Create and iterate on an internal draft

`create_document_from_design` requires `template_id`, explicit top-level
`purpose:document|presentation|signing` and
`input:{name,expected_template_version,expected_template_content_sha256,request_id,values?,sections?}`.
Use a fresh UUID `request_id` for each intended creation and retain it to recover
an uncertain outcome; identical requests use the native creation record. A
design's approval does not approve the document's terms. Creation adds no
recipients and does not send. Ordinary internal content uses `document` or
`presentation`, not an inferred signing workflow.

`get_document_design_source` exposes declared text, current source/PDF pins,
frozen template origin and retained brand provenance. Pass its
`editable_template.read_arguments` to `get_design_template`:
`{template_id,version,expected_content_sha256}` reads the exact retained editable
source after later template updates. The result separates
`current_parent_version`/`current_parent_name` from the selected `version`,
master/defaults, commitment and revision approval. Omitting both selection pins
reads the current template; it does not recover an older document's source.
The live current tenant/credential is authorized for either read.
`get_document_design_history` lists retained
materialization revisions with exact source/PDF/page-count commitments.

`download_document_pdf` requires `document_id` and
`input:{expected_updated_at,expected_pdf_sha256,expected_html_source_commitment?}`.
For HTML use the source commitment; optional `input.revision` chooses retained
HTML history. Reads verify the stored exact version and recheck unchanged source
and the original live credential after storage/parser waits. Delegated
publication follows its separate visible-PDF workflow. A source PDF is not an
executed final contract; completed evidence has separate existing tools.

Inspect **every page of the instantiated PDF**, since real values can change
pagination. Then use `review_document_design` with `document_id`,
`visually_reviewed:true`, all `reviewed_pages` and
`input:{expected_updated_at,expected_pdf_sha256,expected_html_source_commitment}`.

`revise_document_design_values` accepts current updated-at/source pins, string
`values`/`sections` and optional plain-text `summary`. It revises declared text
only, preserves prior exact PDFs and resets PDF review/field placement. It cannot
replace layout/assets. For layout edits update the editable template, preview,
inspect, explicitly approve the new version and create a new document from it.
No existing frozen document or signed artifact is rewritten.

Report saved, rendered, visually inspected, explicitly approved and sent states
separately. Save/readback, hashes and successful rendering are never visual proof.
Recipients and Send remain separate explicit actions with existing permissions.

## Compatibility intake

`create_pdf_document` retains its old PDF/HTML intake behavior for compatibility.
HTML is rendered once into a PDF source; the editable HTML master is lost.
`import_html` parses a fragment into native blocks. Neither is the preferred
editable designed-document workflow.
