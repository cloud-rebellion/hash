// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const ParticipantReportHTMLV3Start = `<section class="hash-participant-report"><div class="hash-participant-report-v3" data-hash-participant-report-layout="3">`

const participantReportHTMLV3Styles = `<style>
.hash-doc .hash-participant-report-v3 { font-size:11px;line-height:1.55; }
.hash-doc .hash-participant-report-v3 h4 { margin:22px 0 8px;border-bottom:2px solid #d4d4d8;break-after:avoid; }
.hash-doc .hash-participant-report-v3 h5 { margin:0 0 7px;break-after:avoid; }
.hash-doc .hash-participant-report-v3 .hash-report-record { margin:0 0 13px;padding:10px 0 4px;border-top:1px solid #e4e4e7;break-inside:auto;page-break-inside:auto; }
.hash-doc .hash-participant-report-v3 .hash-report-meta { display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:5px 18px;break-inside:auto; }
.hash-doc .hash-participant-report-v3 .hash-report-field { min-width:0;margin:0; }
.hash-doc .hash-participant-report-v3 .hash-report-label { display:block;font-size:9px;font-weight:600;color:#52525b; }
.hash-doc .hash-participant-report-v3 .hash-report-value { display:block;white-space:pre-wrap;overflow-wrap:anywhere; }
.hash-doc .hash-participant-report-v3 .hash-report-identity { font-family:monospace;font-size:9px;line-height:1.5; }
.hash-doc .hash-participant-report-v3 .hash-report-text { display:block;width:100%;margin:8px 0 12px;break-inside:auto;page-break-inside:auto; }
.hash-doc .hash-participant-report-v3 .hash-report-canonical-heading { break-before:page;page-break-before:always; }
.hash-doc .hash-participant-report-v3 pre.hash-participant-report-canonical-v2 { font-size:8px!important;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;overflow:visible;break-inside:auto;page-break-inside:auto; }
</style>`

// The first pass counts exact escaped output with no output buffer. The second
// reserves that exact capped length once. Canonical C and HTML H coexist through
// appendix retirement; each <= the unchanged 4MiB payload ceiling. Native owns
// both allocations plus source/projection/validation scratch before calling.
type participantHTMLWriterV3 struct {
	builder *strings.Builder
	count   int
	err     error
}

func (w *participantHTMLWriterV3) write(value string) {
	if w.err != nil {
		return
	}
	if len(value) > MaxCertificatePayloadBytesV1-w.count {
		w.err = ErrCertificatePayloadCapacityV1
		return
	}
	w.count += len(value)
	if w.builder != nil {
		w.builder.WriteString(value)
	}
}
func (w *participantHTMLWriterV3) text(value string) {
	if w.err != nil {
		return
	}
	if len(value) > MaxCertificatePayloadBytesV1-w.count {
		w.err = ErrCertificatePayloadCapacityV1
		return
	}
	if !reportStringV2(value) {
		w.err = ErrParticipantReportV1
		return
	}
	start := 0
	for i := 0; i < len(value); i++ {
		replacement := ""
		switch value[i] {
		case '&':
			replacement = "&amp;"
		case '<':
			replacement = "&lt;"
		case '>':
			replacement = "&gt;"
		case '"':
			replacement = "&#34;"
		case '\'':
			replacement = "&#39;"
		}
		if replacement != "" {
			w.write(value[start:i])
			w.write(replacement)
			start = i + 1
		}
		if w.err != nil {
			return
		}
	}
	w.write(value[start:])
}
func (w *participantHTMLWriterV3) escapedBytes(value []byte) {
	if w.err != nil {
		return
	}
	if len(value) > MaxCertificatePayloadBytesV1-w.count {
		w.err = ErrCertificatePayloadCapacityV1
		return
	}
	start := 0
	for i := 0; i < len(value); i++ {
		replacement := ""
		switch value[i] {
		case '&':
			replacement = "&amp;"
		case '<':
			replacement = "&lt;"
		case '>':
			replacement = "&gt;"
		case '"':
			replacement = "&#34;"
		case '\'':
			replacement = "&#39;"
		}
		if replacement != "" {
			w.bytes(value[start:i])
			w.write(replacement)
			start = i + 1
		}
		if w.err != nil {
			return
		}
	}
	w.bytes(value[start:])
}
func (w *participantHTMLWriterV3) bytes(value []byte) {
	if w.err != nil {
		return
	}
	if len(value) > MaxCertificatePayloadBytesV1-w.count {
		w.err = ErrCertificatePayloadCapacityV1
		return
	}
	w.count += len(value)
	if w.builder != nil {
		w.builder.Write(value)
	}
}
func (w *participantHTMLWriterV3) field(label, value string, identity bool) {
	w.write(`<div class="hash-report-field"><span class="hash-report-label">`)
	w.write(label)
	w.write(`</span><span class="hash-report-value`)
	if identity {
		w.write(` hash-report-identity`)
	}
	w.write(`">`)
	if value == "" {
		w.write("Not recorded")
	} else {
		w.text(value)
	}
	w.write(`</span></div>`)
}
func (w *participantHTMLWriterV3) textField(label, value string) {
	w.write(`<div class="hash-report-text"><span class="hash-report-label">`)
	w.write(label)
	w.write(`</span><div class="hash-report-value">`)
	if value == "" {
		w.write("Not recorded")
	} else {
		w.text(value)
	}
	w.write(`</div></div>`)
}
func (w *participantHTMLWriterV3) section(title string, count int) {
	w.write("<h4>")
	w.write(title)
	w.write(fmt.Sprintf(" (%d)</h4>", count))
	if count == 0 {
		w.write(`<p>No retained records in this section.</p>`)
	}
}
func (w *participantHTMLWriterV3) record(kind string, index int) {
	w.write(`<div class="hash-report-record"><h5>`)
	w.write(kind)
	w.write(fmt.Sprintf(" %d</h5><div class=\"hash-report-meta\">", index+1))
}
func (w *participantHTMLWriterV3) endMeta()   { w.write(`</div>`) }
func (w *participantHTMLWriterV3) endRecord() { w.write(`</div>`) }

func (r ParticipantReportV2) writeHTMLV3(w *participantHTMLWriterV3, canonical []byte, digest string) {
	w.write(ParticipantReportHTMLV3Start)
	w.write(participantReportHTMLV3Styles)
	w.write(`<h3>Participant negotiation and signature report</h3><p>This is the issuer's account of the complete retained shared history in the declared native root and direct envelope family at one cutoff. Original source rows were checked by the native producer before public projection. The public report excludes private original preimages and cannot independently recompute their row hashes. Only change requests and decisions currently have typed payload details; other visible events explicitly retain metadata with details unavailable. Author display names, revision metadata and proposal state are retained observations. A recorded name is not verified identity or company authority. No BankID, qualified signature, legal-effect or organization-chain assurance is asserted.</p><div class="hash-report-meta">`)
	w.field("Document ID", r.DocumentID, true)
	w.field("History cutoff (UTC)", r.Cutoff, false)
	w.field("Canonical report schema", r.Schema, true)
	w.field("Canonical report SHA-256", digest, true)
	w.field("Event projection version", r.EventProjectionVersion, true)
	w.field("Native history scope", r.HistoryScope.Kind, false)
	w.field("Organization ID", r.HistoryScope.OrgID, true)
	w.field("History root document ID", r.HistoryScope.RootDocumentID, true)
	w.endMeta()
	w.section("Exact native history documents", len(r.HistoryScope.DocumentIDs))
	for _, id := range r.HistoryScope.DocumentIDs {
		w.field("Root or direct envelope child", id, true)
	}
	w.write(`<p>Selected legal-package attachment originals below do not import their independent earlier negotiations into this history. The machine events.json attachment remains ceremony-root only; it is not a complete family preimage export. Later completion publication is outside this cutoff.</p>`)
	w.section("Shared negotiation comments", len(r.Comments))
	for i, c := range r.Comments {
		w.record("Comment", i)
		w.field("Author display name (retained observation)", c.AuthorName, false)
		w.field("Recorded at (UTC)", c.At, false)
		w.field("Side", c.Side, false)
		w.field("Actor ID", c.ActorID, true)
		w.field("Document ID", c.DocumentID, true)
		w.field("Comment ID", c.ID, true)
		w.field("Evidence association", c.Evidence, false)
		w.field("Event ID", c.EventID, true)
		w.field("Event row SHA-256", c.EventRowSHA256, true)
		w.endMeta()
		w.textField("Complete shared comment", c.Body)
		w.endRecord()
	}
	w.section("Shared negotiation proposals - retained observations at cutoff", len(r.Proposals))
	for i, p := range r.Proposals {
		w.record("Proposal", i)
		w.field("Proposal kind", p.Kind, false)
		w.field("Status at cutoff (observation)", p.Status, false)
		w.field("Created at (UTC)", p.At, false)
		w.field("Updated at (UTC)", p.UpdatedAt, false)
		w.field("Document ID", p.DocumentID, true)
		w.field("Block ID", p.BlockID, true)
		w.field("Proposal ID", p.ID, true)
		w.endMeta()
		w.textField("Complete proposed text", p.Text)
		w.textField("Complete rationale", p.Rationale)
		w.endRecord()
	}
	w.section("Retained revision metadata - observations", len(r.Revisions))
	for i, v := range r.Revisions {
		w.record("Revision", i)
		w.field("Revision number", fmt.Sprint(v.Number), false)
		w.field("Name", v.Name, false)
		w.field("Recorded at (UTC)", v.At, false)
		w.field("Source kind", v.SourceKind, false)
		w.field("Document ID", v.DocumentID, true)
		w.field("Revision ID", v.ID, true)
		w.endMeta()
		w.endRecord()
	}
	w.section("Frozen legal package originals", len(r.Members))
	for i, m := range r.Members {
		w.record("Package original", i)
		w.field("Package position", fmt.Sprint(m.Position), false)
		w.field("Title", m.Title, false)
		w.field("Category", m.Category, false)
		w.field("Document ID", m.DocumentID, true)
		w.field("PDF pages", fmt.Sprint(m.PDFPages), false)
		w.field("PDF bytes", fmt.Sprint(m.PDFBytes), false)
		w.field("PDF SHA-256", m.PDFSHA256, true)
		w.field("Exact PDF version ID", m.PDFVersionID, true)
		w.endMeta()
		w.endRecord()
	}
	w.section("Whole-package consent and response receipts", len(r.Responses))
	for i, p := range r.Responses {
		w.record("Response receipt", i)
		label := "Signature recorded"
		if p.Kind == "accepted" {
			label = "Explicit acknowledgement recorded"
		}
		w.field("Response", label, false)
		w.field("Original response kind", p.Kind, false)
		w.field("Recorded at (UTC)", p.At, false)
		w.field("Recipient ID", p.RecipientID, true)
		w.field("Send attempt ID", p.AttemptID, true)
		w.field("Signature ID", p.SignatureID, true)
		w.field("Response event ID", p.EventID, true)
		w.field("Package manifest SHA-256", p.ManifestSHA256, true)
		w.field("Legal commitment SHA-256", p.LegalCommitmentSHA256, true)
		w.field("Response event row SHA-256", p.EventRowSHA256, true)
		w.field("Incorporation statement version", p.IncorporationVersion, true)
		w.field("Incorporation statement SHA-256", p.IncorporationSHA256, true)
		w.endMeta()
		w.endRecord()
	}
	w.section("Recorded events and original row commitments", len(r.Events))
	for i, f := range r.Events {
		e := f.Event
		w.record("Event", i)
		w.field("Event kind", e.Kind, false)
		w.field("Recorded at (UTC)", e.At, false)
		w.field("Staff actor ID", e.ActorID, true)
		w.field("Recipient subject ID", e.RecipientID, true)
		w.field("Document ID", e.DocumentID, true)
		w.field("Event ID", e.ID, true)
		w.field("Original event row SHA-256", e.RowSHA256, true)
		w.field("Detail variant", f.Detail, false)
		w.endMeta()
		switch f.Detail {
		case narrativeUnavailable402:
			w.write(`<p>Details unavailable for this historical or unsupported event shape. Only the original event metadata and row commitment are attested here; no additional payload fact or legal effect is inferred.</p>`)
		case narrativeRequest402:
			q := f.Request
			w.write(`<h5>A participant requested changes</h5>`)
			w.field("Request ID", q.ID, true)
			w.textField("Complete request message", q.Message)
			w.textField("Document reference", q.BlockID)
			w.textField("Complete quoted text", q.Quote)
			w.textField("Complete context", q.Context)
			w.textField("Complete proposed wording", q.Proposed)
		case narrativeDecision402:
			d := f.Decision
			w.write(`<h5>A request decision was recorded</h5>`)
			w.field("Request ID", d.RequestID, true)
			w.field("Recorded decision", d.Resolution, false)
			w.field("Original request event ID", d.RequestEventID, true)
			w.field("Request association", d.Link, false)
			w.write(`<p>Approval records a decision about the request. It does not itself prove applied wording, signature, acknowledgement or acceptance of a later version. Notice, invitation, reminder and view records are not signatures or explicit acknowledgement.</p>`)
		}
		w.endRecord()
	}
	w.write(`<h4 class="hash-report-canonical-heading">Canonical public evidence appendix</h4><p>This complete closed public projection and the exact readable presentation are bound by the issuer's detached certificate signature. Original private forensic preimages are not included. This report is evidence about the cutoff; it is not part of a previously executed contract body or acceptance of later terms.</p>`)
	w.write(ParticipantReportCanonicalCarrierV2)
	w.escapedBytes(canonical)
	w.write(`</pre></div></section>`)
}

func (r ParticipantReportV2) HTMLV3() (string, string, error) {
	canonical, sum, err := r.CanonicalV2()
	if err != nil {
		return "", "", err
	}
	digest := hex.EncodeToString(sum[:])
	measure := participantHTMLWriterV3{}
	r.writeHTMLV3(&measure, canonical, digest)
	if measure.err != nil {
		return "", "", measure.err
	}
	var builder strings.Builder
	builder.Grow(measure.count)
	w := participantHTMLWriterV3{builder: &builder}
	r.writeHTMLV3(&w, canonical, digest)
	if w.err != nil || w.count != measure.count {
		return "", "", ErrParticipantReportV1
	}
	return builder.String(), digest, nil
}
