// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/net/html"
)

// This fixture uses the real native report's separate accepted and signed
// response/event associations. Presentation must not invent a signature for
// the acknowledgement or alter either response's canonical evidence.
func certificateAbsenceFixture487(t *testing.T) (reportFixture404, *generated.Document, []*generated.Recipient, []*generated.Signature, []*generated.DocumentField, CertificateEvidenceClaimsV1) {
	t.Helper()
	f := newReportFixture404(t)
	claims := reportCertificateClaims404(t, f)
	completion, err := time.Parse(time.RFC3339Nano, claims.CompletionEffectiveAt)
	if err != nil {
		t.Fatal(err)
	}
	doc := &generated.Document{ID: f.scope.Root, OrgID: f.scope.Org, Name: "Certificate <absence> Å", CompletionEffectiveAtBound: true, CompletionEffectiveAt: pgtype.Timestamptz{Time: completion, Valid: true}}
	var recs []*generated.Recipient
	var sigs []*generated.Signature
	for _, kind := range []string{"accepted", "signed"} {
		found := false
		for _, response := range f.old.Responses {
			if response.Kind != kind {
				continue
			}
			if found {
				t.Fatal("fixture contains duplicate response kind", kind)
			}
			found = true
			rec := &generated.Recipient{ID: uuid.MustParse(response.RecipientID), DocumentID: doc.ID, Role: "signer", Name: kind + " participant", Email: kind + "@example.test", Status: kind}
			if kind == "signed" {
				at, err := time.Parse(time.RFC3339Nano, response.At)
				if err != nil || response.SignatureID == "" {
					t.Fatal("signed fixture association absent", err)
				}
				rec.SignedAt = pgtype.Timestamptz{Time: at.In(time.FixedZone("fixture-offset", 7200)), Valid: true}
				sigs = append(sigs, &generated.Signature{ID: uuid.MustParse(response.SignatureID), RecipientID: rec.ID, DocumentID: doc.ID, Font: "<script>Font & Å</script>", ImageSha256: bytes.Repeat([]byte{0xab}, 32), SignedAt: rec.SignedAt})
			} else if response.SignatureID != "" {
				t.Fatal("acknowledgement fixture claims a drawn signature")
			}
			recs = append(recs, rec)
		}
		if !found {
			t.Fatal("native response fixture missing", kind)
		}
	}
	fields := []*generated.DocumentField{{DocumentID: doc.ID, Type: "text", Page: 1, Label: pgtype.Text{String: "Reference", Valid: true}, Value: pgtype.Text{String: "Accepted without a drawn signature", Valid: true}}}
	return f, doc, recs, sigs, fields, claims
}

func TestCertificateV2AbsenceLabelsPreserveResponsesAndSignedEvidence487(t *testing.T) {
	f, doc, recs, sigs, fields, claims := certificateAbsenceFixture487(t)
	canonicalBefore, digestBefore, err := f.report.CanonicalV2()
	if err != nil {
		t.Fatal(err)
	}
	claimsBefore, docBefore := claims, *doc
	acceptedBefore, signedBefore, signatureBefore, fieldBefore := *recs[0], *recs[1], *sigs[0], *fields[0]
	imageBefore := bytes.Clone(sigs[0].ImageSha256)
	prefix, err := CertificatePrefixV1(doc, recs, sigs, claims)
	if err != nil {
		t.Fatal(err)
	}
	key := certificatePayloadKeyV1()
	complete, payload, signature, err := CertificateFinishV2(prefix, doc, fields, claims, nil, key, "Org Å", "https://hash.example")
	if err != nil || signature == "" || !strings.HasPrefix(complete, payload) {
		t.Fatal("complete V2 certificate failed", err)
	}
	verifyCertificatePayloadSignatureV1(t, key, payload, signature)
	rows := certificateTableRows487(t, payload, []string{"Role", "Recipient", "Status", "Signed at", "Font", "Image SHA-256"})
	if len(rows) != 2 || !reflect.DeepEqual(rows[0], []string{"signer", "accepted participant <accepted@example.test>", "accepted", "Not recorded", "Not recorded", "Not recorded"}) {
		t.Fatalf("acknowledgement display fabricated or obscured signature evidence: %#v", rows)
	}
	if !reflect.DeepEqual(rows[1], []string{"signer", "signed participant <signed@example.test>", "signed", recs[1].SignedAt.Time.UTC().Format(time.RFC3339), sigs[0].Font, hex.EncodeToString(sigs[0].ImageSha256)}) {
		t.Fatalf("recorded signature/timestamp/escaped font changed: %#v", rows[1])
	}
	if strings.Contains(payload, "<script>") || !strings.Contains(payload, `<strong>Sent at:</strong> Not recorded</p>`) {
		t.Fatal("font escaping or absent sent timestamp changed")
	}
	filled := certificateTableRows487(t, payload, []string{"Label", "Type", "Page", "Value", "Filled at"})
	if !reflect.DeepEqual(filled, [][]string{{"Reference", "text", "1", "Accepted without a drawn signature", "Not recorded"}}) {
		t.Fatalf("absent field completion timestamp obscured: %#v", filled)
	}
	if !strings.Contains(payload, claims.ParticipantReportHTML) || !strings.Contains(payload, "Explicit acknowledgement recorded") || !strings.Contains(payload, "Signature recorded") {
		t.Fatal("complete native response narratives omitted")
	}
	decoded, reportDigest, err := ParseParticipantReportHTMLV3(claims.ParticipantReportHTML)
	if err != nil || reportDigest != hex.EncodeToString(digestBefore[:]) || !reflect.DeepEqual(decoded.Responses, f.report.Responses) {
		t.Fatal("canonical response evidence changed", err)
	}
	canonicalAfter, digestAfter, err := f.report.CanonicalV2()
	if err != nil || !bytes.Equal(canonicalBefore, canonicalAfter) || digestBefore != digestAfter || claims != claimsBefore || !reflect.DeepEqual(*doc, docBefore) || !reflect.DeepEqual(*recs[0], acceptedBefore) || !reflect.DeepEqual(*recs[1], signedBefore) || !reflect.DeepEqual(*sigs[0], signatureBefore) || !bytes.Equal(sigs[0].ImageSha256, imageBefore) || !reflect.DeepEqual(*fields[0], fieldBefore) {
		t.Fatal("formatting mutated source rows, claims or canonical report", err)
	}
	// A genuine legacy schema continues to select the original formatter even
	// when an unsigned recipient exists; the independent sign package byte
	// oracle separately covers its entire HTML/payload/signature projection.
	legacyClaims := claims
	legacyClaims.ParticipantReportSchema = ParticipantReportSchemaV1
	legacyPrefix, err := CertificatePrefixV1(doc, recs, sigs, legacyClaims)
	if err != nil {
		t.Fatal(err)
	}
	legacyRows := certificateTableRows487(t, legacyPrefix, []string{"Role", "Recipient", "Status", "Signed at", "Font", "Image SHA-256"})
	if !reflect.DeepEqual(legacyRows[0][3:], []string{", ", ", ", ", "}) || len(prefix)-len(legacyPrefix) != 40 {
		t.Fatal("legacy absence bytes changed or V2 prefix growth unaccounted")
	}
}

func TestCertificateV2AbsenceLabelsRemainWithinOriginalPayloadLimit487(t *testing.T) {
	_, doc, recs, sigs, fields, claims := certificateAbsenceFixture487(t)
	prefix, err := CertificatePrefixV1(doc, recs, sigs, claims)
	if err != nil {
		t.Fatal(err)
	}
	base, err := CertificatePayloadV2(prefix, doc, fields, claims, nil)
	if err != nil || len(base) >= MaxCertificatePayloadBytesV1 {
		t.Fatal("actual absence-label certificate fixture invalid", err)
	}
	// Use the actual corrected prefix and filled fields, then fill the existing
	// manifest suffix to the unchanged complete signed-payload boundary.
	manifest := strings.Repeat("m", MaxCertificatePayloadBytesV1-len(base))
	bounded, err := CertificatePayloadV2(prefix, doc, fields, claims, &manifest)
	if err != nil || len(bounded) != MaxCertificatePayloadBytesV1 || !strings.HasPrefix(bounded, base) {
		t.Fatal("inclusive payload limit or mandatory evidence changed", err)
	}
	manifest += "m"
	if output, err := CertificatePayloadV2(prefix, doc, fields, claims, &manifest); output != "" || !errors.Is(err, ErrCertificatePayloadCapacityV1) || !errors.Is(err, ErrParticipantReportV1) {
		t.Fatal("expanded labels bypassed original limit or returned partial evidence", err)
	}
	// A nil key cannot conceal whether capacity refusal preceded signing.
	if complete, payload, signature, err := CertificateFinishV2(prefix, doc, fields, claims, &manifest, nil, "Org", "https://hash.example"); complete != "" || payload != "" || signature != "" || !errors.Is(err, ErrCertificatePayloadCapacityV1) {
		t.Fatal("overflow was signed or returned partial outputs", err)
	}
}

// Parse the real output rather than asserting a copied formatter string. The
// existing x/net/html dependency also verifies decoded text and escaped fonts.
func certificateTableRows487(t *testing.T, markup string, headers []string) [][]string {
	t.Helper()
	root, err := html.Parse(strings.NewReader(markup))
	if err != nil {
		t.Fatal(err)
	}
	var text func(*html.Node) string
	text = func(n *html.Node) string {
		if n.Type == html.TextNode {
			return n.Data
		}
		var s strings.Builder
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			s.WriteString(text(c))
		}
		return s.String()
	}
	var matches [][][]string
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "table" {
			var tableHeaders []string
			var rows [][]string
			var scan func(*html.Node)
			scan = func(part *html.Node) {
				if part.Type == html.ElementNode && part.Data == "tr" {
					var row []string
					for c := part.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.ElementNode && c.Data == "th" {
							tableHeaders = append(tableHeaders, text(c))
						} else if c.Type == html.ElementNode && c.Data == "td" {
							row = append(row, text(c))
						}
					}
					if len(row) > 0 {
						rows = append(rows, row)
					}
					return
				}
				for c := part.FirstChild; c != nil; c = c.NextSibling {
					scan(c)
				}
			}
			scan(n)
			if reflect.DeepEqual(tableHeaders, headers) {
				matches = append(matches, rows)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(root)
	if len(matches) != 1 {
		t.Fatalf("expected one certificate table %v, got %d", headers, len(matches))
	}
	return matches[0]
}
