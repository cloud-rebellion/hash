// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/render"
)

func reportClaimFixture404(t *testing.T) (render.ParticipantReportV2, render.CertificateEvidenceClaimsV1, string) {
	t.Helper()
	root := "20000000-0000-0000-0000-000000000002"
	org := "10000000-0000-0000-0000-000000000001"
	recipient := "30000000-0000-0000-0000-000000000003"
	r := render.ParticipantReportV2{Schema: render.ParticipantReportSchemaV2, DocumentID: root, Cutoff: "2026-10-19T12:00:01Z", HistoryScope: render.ParticipantReportHistoryScopeV2{Kind: render.ParticipantReportHistoryScopeKindV2, OrgID: org, RootDocumentID: root, DocumentIDs: []string{root}}, EventProjectionVersion: render.ParticipantEventProjectionVersionV1,
		Events:   []render.ParticipantEventFactDraft402{{Event: render.ParticipantReportEventV1{ID: "50000000-0000-0000-0000-000000000005", DocumentID: root, Kind: "document.changes_requested", At: "2026-10-19T12:00:00Z", RecipientID: recipient, RowSHA256: strings.Repeat("e", 64)}, Detail: "change-request", Request: &render.ParticipantChangeRequestDraft402{ID: "60000000-0000-0000-0000-000000000006", Message: "Original shared request <terms>", BlockID: "payment", Quote: "Old terms", Context: "Shared context", Proposed: "Proposed terms"}}},
		Comments: []render.ParticipantReportCommentV1{{ID: "70000000-0000-0000-0000-000000000007", DocumentID: root, AuthorName: "Participant Å", Side: "signer", ActorID: recipient, At: "2026-10-19T11:00:00Z", Body: "Full retained shared text", Evidence: "legacy-text-not-verified"}}}
	section, digest, err := r.HTMLV3()
	if err != nil {
		t.Fatal(err)
	}
	c := render.CertificateEvidenceClaimsV1{DocumentID: root, OrgID: org, DocumentNameSHA256: strings.Repeat("a", 64), FinalPDFSHA256: strings.Repeat("b", 64), CompletionEffectiveAt: r.Cutoff, PreFinalChainHeadSHA256: strings.Repeat("c", 64), PreFinalChainHeadCreatedAt: "2026-10-19T12:00:00Z", PreFinalChainScope: "organization", DocumentEventsSHA256: strings.Repeat("d", 64), DocumentEventsCount: 1, DocumentEventsScope: "ceremony-root", ParticipantReportSchema: render.ParticipantReportSchemaV2, ParticipantReportSHA256: digest, ParticipantReportCutoff: r.Cutoff, ParticipantReportRows: r.SourceRowsV2()}
	return r, c, c.HTML() + section
}

func TestParticipantReportVersionedTrustedResigningCannotBlessContradictions(t *testing.T) {
	r, claims, valid := reportClaimFixture404(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	key := render.NewAuditCertificateKeyV1(private)
	for _, name := range []string{"valid", "digest", "cutoff", "count", "document", "org", "schema-unknown", "schema-downgrade", "schema-absent", "visible-request", "visible-comment", "label", "style", "layout", "inserted-html", "extra-body", "missing-body", "duplicate-body", "canonical-duplicate", "canonical-trailing", "intake-section"} {
		t.Run(name, func(t *testing.T) {
			payload := valid
			want := false
			switch name {
			case "valid":
				want = true
			case "digest":
				payload = strings.Replace(payload, `data-hash-participant-report-sha256="`+claims.ParticipantReportSHA256+`"`, `data-hash-participant-report-sha256="`+strings.Repeat("f", 64)+`"`, 1)
			case "cutoff":
				payload = strings.Replace(payload, `data-hash-participant-report-cutoff="`+r.Cutoff+`"`, `data-hash-participant-report-cutoff="2026-10-19T12:00:02Z"`, 1)
			case "count":
				payload = strings.Replace(payload, `data-hash-participant-report-rows="2"`, `data-hash-participant-report-rows="3"`, 1)
			case "document":
				payload = strings.Replace(payload, `data-hash-document-id="`+r.DocumentID+`"`, `data-hash-document-id="20000000-0000-0000-0000-000000000003"`, 1)
			case "org":
				payload = strings.Replace(payload, `data-hash-org-id="`+claims.OrgID+`"`, `data-hash-org-id="10000000-0000-0000-0000-000000000002"`, 1)
			case "schema-unknown":
				payload = strings.Replace(payload, `data-hash-participant-report-schema="hash-participant-report-v2"`, `data-hash-participant-report-schema="unknown"`, 1)
			case "schema-downgrade":
				payload = strings.Replace(payload, `data-hash-participant-report-schema="hash-participant-report-v2"`, `data-hash-participant-report-schema="hash-participant-report-v1"`, 1)
			case "schema-absent":
				payload = strings.Replace(payload, ` data-hash-participant-report-schema="hash-participant-report-v2"`, "", 1)
			case "visible-request":
				payload = strings.Replace(payload, "Original shared request &lt;terms&gt;", "Freshly signed contradictory request", 1)
			case "visible-comment":
				payload = strings.Replace(payload, "Full retained shared text", "Contradictory shared text", 1)
			case "label":
				payload = strings.Replace(payload, "A participant requested changes", "A participant signed the proposal", 1)
			case "style":
				payload = strings.Replace(payload, "font-size:11px", "font-size:0px", 1)
			case "layout":
				payload = strings.Replace(payload, `data-hash-participant-report-layout="3"`, `data-hash-participant-report-layout="2"`, 1)
			case "inserted-html":
				payload = strings.Replace(payload, "</pre>", "</pre><p>Uncommitted extra statement</p>", 1)
			case "extra-body":
				payload = strings.Replace(payload, `</pre></div></section>`, `</pre></div></section><section class="hash-participant-report">forged</section>`, 1)
			case "missing-body":
				payload = claims.HTML()
			case "duplicate-body":
				payload += strings.TrimPrefix(valid, claims.HTML())
			case "canonical-duplicate":
				payload = strings.Replace(payload, `{&#34;schema&#34;:`, `{&#34;schema&#34;:&#34;duplicate&#34;,&#34;schema&#34;:`, 1)
			case "canonical-trailing":
				payload = strings.Replace(payload, "</pre>", " {}</pre>", 1)
			case "intake-section":
				payload += `<section class="hash-redaction-report">private</section>`
			}
			if !want && payload == valid {
				t.Fatal("tampering fixture unchanged")
			}
			// Every contradictory payload is freshly signed by the SAME trusted
			// fixture issuer. Cryptographic validity alone remains true.
			sig, err := base64.StdEncoding.DecodeString(key.SignPayload([]byte(payload)))
			if err != nil {
				t.Fatal(err)
			}
			message := sha256.Sum256(append([]byte("hash:audit-cert:v1:"), []byte(payload)...))
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), message[:], sig) {
				t.Fatal("trusted issuer signature not valid")
			}
			_, err = ParseCertificateCommitments([]byte(payload))
			if (err == nil) != want {
				t.Fatalf("report consistency accepted=%v want=%v err=%v", err == nil, want, err)
			}
		})
	}
}

func TestParticipantReportVersionDispatchPreservesExactArchivedVariants(t *testing.T) {
	_, claims, _ := reportClaimFixture404(t)
	old := render.ParticipantReportV1{Schema: render.ParticipantReportSchemaV1, DocumentID: claims.DocumentID, Cutoff: claims.ParticipantReportCutoff, Comments: []render.ParticipantReportCommentV1{{Body: "Archived retained text"}}}
	for _, formatter := range []func() (string, string, error){old.HTMLV1, old.HTMLV2} {
		section, digest, err := formatter()
		if err != nil {
			t.Fatal(err)
		}
		c := claims
		c.ParticipantReportSchema = render.ParticipantReportSchemaV1
		c.ParticipantReportSHA256 = digest
		c.ParticipantReportRows = 1
		payload := []byte(c.HTML() + section)
		previous, err := parseParticipantReportClaimV1(payload, c.DocumentID)
		if err != nil {
			t.Fatal(err)
		}
		versioned, err := parseParticipantReportClaimVersioned(payload, c.DocumentID)
		if err != nil || previous != versioned {
			t.Fatal("archived dispatch changed", err)
		}
	}
	legacy := claims
	legacy.ParticipantReportSchema = ""
	legacy.ParticipantReportRows = 0
	if result, err := parseParticipantReportClaimVersioned([]byte(legacy.HTML()), legacy.DocumentID); err != nil || result.schema != "" {
		t.Fatal("legacy absence changed", err)
	}
}
