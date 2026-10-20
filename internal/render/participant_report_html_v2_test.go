// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"encoding/hex"
	"html"
	"reflect"
	"strings"
	"testing"
)

func participantReportHTMLFixtureV2() ParticipantReportV1 {
	return ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: "11111111-1111-4111-8111-111111111111", Cutoff: "2026-10-19T09:30:00Z",
		Events:    []ParticipantReportEventV1{{ID: "event-id", DocumentID: "event-document", Kind: "document.signed", At: "event-time", ActorID: "staff-actor", RecipientID: "recipient-subject", RowSHA256: strings.Repeat("a", 64)}},
		Comments:  []ParticipantReportCommentV1{{ID: "comment-id", DocumentID: "comment-document", AuthorName: `Åsa <Example> & "Co"`, Side: "signer", ActorID: "comment-actor", At: "comment-time", Body: "The complete <DPA> remains part of the agreement.\nA second paragraph with Å, ä and ö.", Evidence: "body-and-actor-associated", EventID: "comment-event", EventRowSHA256: strings.Repeat("b", 64)}},
		Revisions: []ParticipantReportRevisionV1{{ID: "revision-id", DocumentID: "revision-document", Name: "Reviewed <agreement>", SourceKind: "pdf-import", At: "revision-time", Number: 3}},
		Proposals: []ParticipantReportProposalV1{{ID: "proposal-id", DocumentID: "proposal-document", Kind: "replace", BlockID: "service-period", Text: "The service starts after onboarding.", Rationale: "Align <delivery> and invoicing.", Status: "accepted", At: "proposal-time", UpdatedAt: "proposal-update"}},
		Members:   []ParticipantReportMemberV1{{Position: 1, DocumentID: "member-document", Title: "Data processing agreement", Category: "DPA", PDFSHA256: strings.Repeat("c", 64), PDFVersionID: `opaque<&"version`, PDFBytes: 24000, PDFPages: 2}},
		Responses: []ParticipantReportResponseV1{{RecipientID: "response-recipient", AttemptID: "response-attempt", ManifestSHA256: strings.Repeat("d", 64), LegalCommitmentSHA256: strings.Repeat("e", 64), Kind: "signed", SignatureID: "response-signature", EventID: "response-event", EventRowSHA256: strings.Repeat("f", 64), At: "response-time", IncorporationVersion: "hash-package-incorporation-v1", IncorporationSHA256: strings.Repeat("1", 64)}},
	}
}

func TestParticipantReportHTMLV2PreservesCanonicalV1AndAllRetainedFields(t *testing.T) {
	r := participantReportHTMLFixtureV2()
	raw, sum, err := r.CanonicalV1()
	if err != nil {
		t.Fatal(err)
	}
	v1, v1Digest, err := r.HTMLV1()
	if err != nil {
		t.Fatal(err)
	}
	v2, digest, err := r.HTMLV2()
	if err != nil || digest != v1Digest || digest != hex.EncodeToString(sum[:]) || v2 == v1 {
		t.Fatal("presentation changed canonical evidence identity", err)
	}
	const carrier = `<pre class="hash-participant-report-canonical" style="white-space:pre-wrap;font-size:7px">`
	start := strings.Index(v2, carrier) + len(carrier)
	end := strings.Index(v2[start:], "</pre>")
	if start < len(carrier) || end < 0 || !bytes.Equal([]byte(html.UnescapeString(v2[start:start+end])), raw) {
		t.Fatal("V2 canonical appendix changed or omitted retained bytes")
	}
	// Check the readable region independently of the canonical carrier. Every
	// string field must remain visible even when it is an ID, digest or HTML-like
	// user text; a correct appendix alone cannot excuse an omitted narrative.
	readable := v2[:start-len(carrier)]
	for _, values := range []any{r.Events, r.Comments, r.Revisions, r.Proposals, r.Members, r.Responses} {
		rows := reflect.ValueOf(values)
		for i := 0; i < rows.Len(); i++ {
			row := rows.Index(i)
			for j := 0; j < row.NumField(); j++ {
				if row.Field(j).Kind() == reflect.String && !strings.Contains(readable, certificateEscapeV1(row.Field(j).String())) {
					t.Fatalf("readable report omitted %s.%s", row.Type().Name(), row.Type().Field(j).Name)
				}
			}
		}
	}
	for _, label := range []string{"Shared comment", "Proposed text", "Rationale", "Author", "Actor ID", "Comment ID", "Event ID", "History cutoff (UTC)", "Revision number", "PDF pages", "PDF bytes", "Exact PDF version ID", "Recipient ID", "Signature ID", "Incorporation statement SHA-256", "Original event row SHA-256"} {
		if !strings.Contains(readable, `<span class="hash-report-label">`+label+`</span>`) {
			t.Fatalf("readable report omitted explicit label %q", label)
		}
	}
	if strings.Contains(v2, "<table") || strings.Contains(v2, "<DPA>") || strings.Contains(v2, "<Example>") {
		t.Fatal("V2 restored narrow tables or allowed user HTML markup")
	}
	if again, againDigest, err := r.HTMLV1(); err != nil || again != v1 || againDigest != v1Digest {
		t.Fatal("V2 formatting mutated archived V1 output")
	}
}

func TestParticipantReportHTMLV2LongBodiesHaveFullWidthAndRemainComplete(t *testing.T) {
	r := participantReportHTMLFixtureV2()
	long := strings.Repeat("This entire paragraph remains readable across page boundaries. ", 500) + `LAST <script>alert("x")</script> Å`
	r.Comments[0].Body = long
	r.Proposals[0].Text = long + " PROPOSAL END"
	r.Proposals[0].Rationale = long + " RATIONALE END"
	value, _, err := r.HTMLV2()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{long, long + " PROPOSAL END", long + " RATIONALE END"} {
		if !strings.Contains(value, `<div class="hash-report-value">`+certificateEscapeV1(body)+`</div>`) {
			t.Fatal("a full-width body was truncated, moved into metadata, or not escaped")
		}
	}
	for _, forbidden := range []string{"display:none", "visibility:hidden", "text-overflow", "line-clamp", "overflow:hidden", "<script>"} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("report hides or executes retained data: %s", forbidden)
		}
	}
}

func TestParticipantReportHTMLV2MarkupFitsNativeAdmissionEnvelope(t *testing.T) {
	empty := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: "11111111-1111-4111-8111-111111111111", Cutoff: "2026-10-19T09:30:00Z"}
	framing, _, err := empty.HTMLV2()
	if err != nil || int64(len(framing)) > ParticipantReportHTMLV2FixedMarkupBytes || ParticipantReportHTMLV2FixedMarkupBytes > 65536 {
		t.Fatal("fixed V2 markup exceeds funded native framing", err)
	}
	for _, add := range []func(*ParticipantReportV1){
		func(r *ParticipantReportV1) { r.Events = []ParticipantReportEventV1{{}} },
		func(r *ParticipantReportV1) { r.Comments = []ParticipantReportCommentV1{{}} },
		func(r *ParticipantReportV1) { r.Revisions = []ParticipantReportRevisionV1{{}} },
		func(r *ParticipantReportV1) { r.Proposals = []ParticipantReportProposalV1{{}} },
		func(r *ParticipantReportV1) { r.Members = []ParticipantReportMemberV1{{}} },
		func(r *ParticipantReportV1) { r.Responses = []ParticipantReportResponseV1{{}} },
	} {
		r := empty
		add(&r)
		value, _, err := r.HTMLV2()
		if err != nil || int64(len(value)-len(framing)) > ParticipantReportHTMLV2RecordMarkupBytes || ParticipantReportHTMLV2RecordMarkupBytes > 8192 {
			t.Fatal("V2 record labels/canonical framing exceed existing native per-row quote", err)
		}
	}
	for _, mutate := range []func(*ParticipantReportV1){
		func(r *ParticipantReportV1) { r.Schema = "unknown" },
		func(r *ParticipantReportV1) { r.Cutoff = "not-a-cutoff" },
		func(r *ParticipantReportV1) {
			r.Events = make([]ParticipantReportEventV1, MaxParticipantReportRowsV1+1)
		},
		func(r *ParticipantReportV1) {
			r.Comments = []ParticipantReportCommentV1{{Body: strings.Repeat("x", int(MaxParticipantReportRawBytesV1))}}
		},
	} {
		r := empty
		mutate(&r)
		if _, _, err := r.HTMLV2(); err == nil {
			t.Fatal("V2 bypassed existing canonical schema/cutoff/size refusal")
		}
	}
}
