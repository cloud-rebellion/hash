// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
)

// Even a freshly trusted issuer signature cannot bless contradictory report
// attributes, a different visible narrative or a noncanonical projection.
func TestVerifyParticipantReportCanonicalAssociationV1(t *testing.T) {
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	doc, org := uuid.NewString(), uuid.NewString()
	report := render.ParticipantReportV1{Schema: render.ParticipantReportSchemaV1, DocumentID: doc, Cutoff: "2026-10-18T12:00:00Z", Comments: []render.ParticipantReportCommentV1{{ID: uuid.NewString(), DocumentID: doc, AuthorName: "Participant", Side: "signer", ActorID: uuid.NewString(), At: "2026-10-18T11:00:00Z", Body: "Original shared statement", Evidence: "legacy-text-not-verified"}}}
	for _, formatter := range []struct {
		name string
		html func() (string, string, error)
	}{{"archived-v1", report.HTMLV1}, {"readable-v2", report.HTMLV2}} {
		t.Run(formatter.name, func(t *testing.T) {
			section, digest, err := formatter.html()
			if err != nil {
				t.Fatal(err)
			}
			claims := render.CertificateEvidenceClaimsV1{DocumentID: doc, OrgID: org, DocumentNameSHA256: strings.Repeat("a", 64), FinalPDFSHA256: strings.Repeat("b", 64), CompletionEffectiveAt: "2026-10-18T12:00:00Z", PreFinalChainHeadSHA256: strings.Repeat("c", 64), PreFinalChainHeadCreatedAt: "2026-10-18T11:59:00Z", PreFinalChainScope: "organization", DocumentEventsSHA256: strings.Repeat("d", 64), DocumentEventsCount: 1, DocumentEventsScope: "ceremony-root", ParticipantReportSchema: render.ParticipantReportSchemaV1, ParticipantReportSHA256: digest, ParticipantReportCutoff: report.Cutoff, ParticipantReportRows: 1}
			valid := claims.HTML() + section
			for _, name := range []string{"valid", "legacy", "digest", "cutoff", "count", "visible-text", "label", "style", "layout", "inserted-html", "duplicate-body", "mixed-format-bodies", "missing-body", "noncanonical-json", "wrong-document"} {
				t.Run(name, func(t *testing.T) {
					payload := valid
					want := false
					switch name {
					case "valid":
						want = true
					case "legacy":
						legacy := claims
						legacy.ParticipantReportSchema = ""
						payload = legacy.HTML()
						want = true
					case "digest":
						payload = strings.Replace(payload, digest, strings.Repeat("f", 64), 1)
					case "cutoff":
						payload = strings.Replace(payload, `data-hash-participant-report-cutoff="2026-10-18T12:00:00Z"`, `data-hash-participant-report-cutoff="2026-10-18T12:01:00Z"`, 1)
					case "count":
						payload = strings.Replace(payload, `data-hash-participant-report-rows="1"`, `data-hash-participant-report-rows="2"`, 1)
					case "visible-text":
						payload = strings.Replace(payload, "Original shared statement", "Contradictory statement", 1)
					case "label":
						if formatter.name == "readable-v2" {
							payload = strings.Replace(payload, `>Shared comment</span>`, `>Private comment</span>`, 1)
						} else {
							payload = strings.Replace(payload, "Shared negotiation comments", "Private negotiation comments", 1)
						}
					case "style":
						if formatter.name == "readable-v2" {
							payload = strings.Replace(payload, "font-size:11px", "font-size:0px", 1)
						} else {
							payload = strings.Replace(payload, "font-size:7px", "font-size:0px", 1)
						}
					case "layout":
						if formatter.name == "readable-v2" {
							payload = strings.Replace(payload, `data-hash-participant-report-layout="2"`, `data-hash-participant-report-layout="3"`, 1)
						} else {
							payload = strings.Replace(payload, `<section class="hash-participant-report">`, `<section class="unrecognized-report">`, 1)
						}
					case "inserted-html":
						payload = strings.Replace(payload, "</pre>", "</pre><p>This arbitrary extra report claim is not canonical evidence.</p>", 1)
					case "duplicate-body":
						payload += section
					case "mixed-format-bodies":
						var other string
						if formatter.name == "readable-v2" {
							other, _, err = report.HTMLV1()
						} else {
							other, _, err = report.HTMLV2()
						}
						if err != nil {
							t.Fatal(err)
						}
						payload += other
					case "missing-body":
						payload = claims.HTML()
					case "noncanonical-json":
						payload = strings.Replace(payload, `{&quot;schema&quot;:`, `{ &quot;schema&quot;:`, 1)
					case "wrong-document":
						payload = strings.Replace(payload, `data-hash-document-id="`+doc+`"`, `data-hash-document-id="`+uuid.NewString()+`"`, 1)
					}
					if !want && payload == valid {
						t.Fatal("tampering fixture did not change the generated report")
					}
					in := verifyInput{PublicKeyB64: signer.PublicKeyBase64(), Payload: payload, SignatureB64: signer.SignPayload([]byte(payload))}
					raw, err := json.Marshal(in)
					if err != nil {
						t.Fatal(err)
					}
					server := &Server{EvidenceTrustedPublicKeys: []string{signer.PublicKeyBase64()}}
					w := httptest.NewRecorder()
					server.handleVerify(w, httptest.NewRequest("POST", "/verify", bytes.NewReader(raw)))
					if w.Code != 200 {
						t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
					}
					var result map[string]any
					if json.Unmarshal(w.Body.Bytes(), &result) != nil {
						t.Fatal("invalid response")
					}
					if result["valid"] != true || result["authentic_hash_evidence"] != want || result["certificate_commitments_valid"] != want {
						t.Fatalf("signed report consistency result=%s want=%v", w.Body.String(), want)
					}
				})
			}
		})
	}
}
