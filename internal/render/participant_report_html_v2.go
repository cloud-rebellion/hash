// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Presentation changes independently of the canonical report schema. Archived
// HTMLV1 and CanonicalV1 remain unchanged; both exact presentations are verified.
const ParticipantReportHTMLV2Start = `<section class="hash-participant-report"><div class="hash-participant-report-v2" data-hash-participant-report-layout="2">`

// Native report admission already reserves 8192 bytes per retained row and
// 64KiB of fixed framing, in addition to 96 times measured source bytes. These
// conservative markup bounds include labels and the canonical field names;
// variable values and escaping remain covered by the measured source quote.
const ParticipantReportHTMLV2RecordMarkupBytes int64 = 4096
const ParticipantReportHTMLV2FixedMarkupBytes int64 = 16384

const participantReportHTMLV2Styles = `<style>
.hash-doc .hash-participant-report-v2 { font-size:11px; line-height:1.55; }
.hash-doc .hash-participant-report-v2 h4 { font-size:12px; margin:22px 0 8px; padding-bottom:5px; border-bottom:2px solid #d4d4d8; break-after:avoid; }
.hash-doc .hash-participant-report-v2 h5 { font-size:11px; margin:0 0 7px; break-after:avoid; }
.hash-doc .hash-participant-report-v2 .hash-report-record { margin:0 0 13px; padding:10px 0 4px; border-top:1px solid #e4e4e7; break-inside:auto; page-break-inside:auto; }
.hash-doc .hash-participant-report-v2 .hash-report-meta { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:5px 18px; margin:0 0 8px; break-inside:avoid; }
.hash-doc .hash-participant-report-v2 .hash-report-field { min-width:0; margin:0; }
.hash-doc .hash-participant-report-v2 .hash-report-label { display:block; font-size:9px; font-weight:600; color:#52525b; }
.hash-doc .hash-participant-report-v2 .hash-report-value { display:block; white-space:pre-wrap; overflow-wrap:anywhere; }
.hash-doc .hash-participant-report-v2 .hash-report-identity { font-family:monospace; font-size:9px; line-height:1.5; }
.hash-doc .hash-participant-report-v2 .hash-report-text { display:block; width:100%; margin:8px 0 12px; break-inside:auto; page-break-inside:auto; }
.hash-doc .hash-participant-report-v2 .hash-report-text .hash-report-value { white-space:pre-wrap; overflow-wrap:anywhere; break-inside:auto; page-break-inside:auto; }
.hash-doc .hash-participant-report-v2 .hash-report-empty { font-size:10px; color:#52525b; }
.hash-doc .hash-participant-report-v2 .hash-report-canonical-heading { break-before:page; page-break-before:always; }
.hash-doc .hash-participant-report-v2 pre.hash-participant-report-canonical { font-size:8px !important; line-height:1.5; white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; overflow:visible; break-inside:auto; page-break-inside:auto; }
</style>`

type participantReportHTMLV2Writer struct{ strings.Builder }

func (b *participantReportHTMLV2Writer) section(title string, count int) {
	fmt.Fprintf(&b.Builder, "<h4>%s (%d)</h4>", title, count)
	if count == 0 {
		b.WriteString(`<p class="hash-report-empty">No retained records in this section.</p>`)
	}
}
func (b *participantReportHTMLV2Writer) record(kind string, index int) {
	fmt.Fprintf(&b.Builder, `<div class="hash-report-record"><h5>%s %d</h5><div class="hash-report-meta">`, kind, index+1)
}
func (b *participantReportHTMLV2Writer) field(label, value string, identity bool) {
	b.WriteString(`<div class="hash-report-field"><span class="hash-report-label">`)
	b.WriteString(label) // All labels are fixed literals in this formatter.
	b.WriteString(`</span><span class="hash-report-value`)
	if identity {
		b.WriteString(` hash-report-identity`)
	}
	b.WriteString(`">`)
	if value == "" {
		b.WriteString("Not recorded")
	} else {
		b.WriteString(certificateEscapeV1(value))
	}
	b.WriteString(`</span></div>`)
}
func (b *participantReportHTMLV2Writer) text(label, value string) {
	b.WriteString(`<div class="hash-report-text"><span class="hash-report-label">`)
	b.WriteString(label)
	b.WriteString(`</span><div class="hash-report-value">`)
	if value == "" {
		b.WriteString("Not recorded")
	} else {
		b.WriteString(certificateEscapeV1(value))
	}
	b.WriteString(`</div></div>`)
}
func (b *participantReportHTMLV2Writer) endMeta()   { b.WriteString(`</div>`) }
func (b *participantReportHTMLV2Writer) endRecord() { b.WriteString(`</div>`) }

// HTMLV2 renders every retained field with an explicit label. Long negotiation
// text occupies the full printable width and may continue across pages. IDs and
// fingerprints remain complete, with compact typography and safe line breaks.
// The escaped canonical JSON is still visible in a separate evidence appendix.
func (r ParticipantReportV1) HTMLV2() (string, string, error) {
	raw, sum, err := r.CanonicalV1()
	if err != nil {
		return "", "", err
	}
	digest := hex.EncodeToString(sum[:])
	var b participantReportHTMLV2Writer
	b.WriteString(ParticipantReportHTMLV2Start)
	b.WriteString(participantReportHTMLV2Styles)
	b.WriteString(`<h3>Participant negotiation and signature report</h3><p>Complete retained participant history through the cutoff below. Later completion publication is outside this cutoff. Private event kinds and internal notes are excluded. This document subset does not prove organization-chain continuity. Historical text marked unverified has no retrospective body or actor attestation. Revision metadata and proposal states are retained database observations; no content attestation is inferred.</p><div class="hash-report-meta">`)
	b.field("Document ID", r.DocumentID, true)
	b.field("History cutoff (UTC)", r.Cutoff, false)
	b.field("Canonical report schema", r.Schema, true)
	b.field("Canonical report SHA-256", digest, true)
	b.endMeta()
	b.section("Shared negotiation comments", len(r.Comments))
	for i, c := range r.Comments {
		b.record("Comment", i)
		b.field("Author", c.AuthorName, false)
		b.field("Recorded at (UTC)", c.At, false)
		b.field("Side", c.Side, false)
		b.field("Actor ID", c.ActorID, true)
		b.field("Document ID", c.DocumentID, true)
		b.field("Comment ID", c.ID, true)
		b.field("Evidence association", c.Evidence, false)
		b.field("Event ID", c.EventID, true)
		b.field("Event row SHA-256", c.EventRowSHA256, true)
		b.endMeta()
		b.text("Shared comment", c.Body)
		b.endRecord()
	}
	b.section("Shared negotiation proposals - retained state at cutoff", len(r.Proposals))
	for i, p := range r.Proposals {
		b.record("Proposal", i)
		b.field("Proposal kind", p.Kind, false)
		b.field("Status at cutoff", p.Status, false)
		b.field("Created at (UTC)", p.At, false)
		b.field("Updated at (UTC)", p.UpdatedAt, false)
		b.field("Document ID", p.DocumentID, true)
		b.field("Block ID", p.BlockID, true)
		b.field("Proposal ID", p.ID, true)
		b.endMeta()
		b.text("Proposed text", p.Text)
		b.text("Rationale", p.Rationale)
		b.endRecord()
	}
	b.section("Retained revision metadata", len(r.Revisions))
	for i, v := range r.Revisions {
		b.record("Revision", i)
		b.field("Revision number", fmt.Sprint(v.Number), false)
		b.field("Name", v.Name, false)
		b.field("Recorded at (UTC)", v.At, false)
		b.field("Source kind", v.SourceKind, false)
		b.field("Document ID", v.DocumentID, true)
		b.field("Revision ID", v.ID, true)
		b.endMeta()
		b.endRecord()
	}
	b.section("Frozen legal package originals", len(r.Members))
	for i, m := range r.Members {
		b.record("Package original", i)
		b.field("Package position", fmt.Sprint(m.Position), false)
		b.field("Title", m.Title, false)
		b.field("Category", m.Category, false)
		b.field("Document ID", m.DocumentID, true)
		b.field("PDF pages", fmt.Sprint(m.PDFPages), false)
		b.field("PDF bytes", fmt.Sprint(m.PDFBytes), false)
		b.field("PDF SHA-256", m.PDFSHA256, true)
		b.field("Exact PDF version ID", m.PDFVersionID, true)
		b.endMeta()
		b.endRecord()
	}
	b.section("Whole-package consent and response receipts", len(r.Responses))
	for i, p := range r.Responses {
		b.record("Response receipt", i)
		b.field("Response kind", p.Kind, false)
		b.field("Recorded at (UTC)", p.At, false)
		b.field("Recipient ID", p.RecipientID, true)
		b.field("Send attempt ID", p.AttemptID, true)
		b.field("Signature ID", p.SignatureID, true)
		b.field("Response event ID", p.EventID, true)
		b.field("Package manifest SHA-256", p.ManifestSHA256, true)
		b.field("Legal commitment SHA-256", p.LegalCommitmentSHA256, true)
		b.field("Response event row SHA-256", p.EventRowSHA256, true)
		b.field("Incorporation statement version", p.IncorporationVersion, true)
		b.field("Incorporation statement SHA-256", p.IncorporationSHA256, true)
		b.endMeta()
		b.endRecord()
	}
	b.section("Events - original row commitments", len(r.Events))
	for i, e := range r.Events {
		b.record("Event", i)
		b.field("Event kind", e.Kind, false)
		b.field("Recorded at (UTC)", e.At, false)
		b.field("Staff actor ID", e.ActorID, true)
		b.field("Recipient subject ID", e.RecipientID, true)
		b.field("Document ID", e.DocumentID, true)
		b.field("Event ID", e.ID, true)
		b.field("Original event row SHA-256", e.RowSHA256, true)
		b.endMeta()
		b.endRecord()
	}
	b.WriteString(`<h4 class="hash-report-canonical-heading">Canonical evidence appendix</h4><p>The complete canonical JSON below is included in the detached signed payload. Its SHA-256 fingerprint is shown at the start of this report. The readable records above preserve the same retained values.</p>`)
	// Keep the canonical carrier shape shared with archived V1 reports. The
	// verifier still requires the complete exact V1 or V2 formatter output.
	fmt.Fprintf(&b.Builder, `<pre class="hash-participant-report-canonical" style="white-space:pre-wrap;font-size:7px">%s</pre></div></section>`, certificateEscapeV1(string(raw)))
	return b.String(), digest, nil
}
