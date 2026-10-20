// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func reportCertificateClaims404(t *testing.T, f reportFixture404) CertificateEvidenceClaimsV1 {
	t.Helper()
	section, digest, err := f.report.HTMLV3()
	if err != nil {
		t.Fatal(err)
	}
	return CertificateEvidenceClaimsV1{DocumentID: f.report.DocumentID, OrgID: f.report.HistoryScope.OrgID, DocumentNameSHA256: strings.Repeat("a", 64), FinalPDFSHA256: strings.Repeat("b", 64), CompletionEffectiveAt: f.report.Cutoff, PreFinalChainHeadSHA256: strings.Repeat("c", 64), PreFinalChainHeadCreatedAt: f.report.Cutoff, PreFinalChainScope: "organization", DocumentEventsSHA256: strings.Repeat("d", 64), DocumentEventsCount: 1, DocumentEventsScope: "ceremony-root", ParticipantReportSchema: ParticipantReportSchemaV2, ParticipantReportSHA256: digest, ParticipantReportCutoff: f.report.Cutoff, ParticipantReportRows: f.report.SourceRowsV2(), ParticipantReportHTML: section}
}

func TestCertificatePayloadV2ParticipantPrivacyAndLegacyAssembly(t *testing.T) {
	f := newReportFixture404(t)
	claims := reportCertificateClaims404(t, f)
	doc := &generated.Document{ID: f.scope.Root, OrgID: f.scope.Org, MetadataRedactionReport: []byte(`{"schema_version":2,"items":[{"asset":"PRIVATE-INTAKE-404","method":"PRIVATE-SANITIZER-404"}]}`)}
	key := NewAuditCertificateKeyV1(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	_, payload, signature, err := CertificateFinishV2(`<div class="hash-cert-page"><h2>Audit Certificate</h2>`, doc, nil, claims, nil, key, "Org Å", "https://hash.example")
	if err != nil || signature == "" || !strings.Contains(payload, claims.ParticipantReportHTML) || !strings.Contains(payload, claims.ParticipantReportSHA256) {
		t.Fatal("new mandatory report absent", err)
	}
	for _, private := range []string{"PRIVATE-INTAKE-404", "PRIVATE-SANITIZER-404", "hash-redaction-report", "PRIVATE-UA-402", "PRIVATE-NOTICE-402", "PRIVATE-PAYLOAD-404"} {
		if strings.Contains(payload, private) {
			t.Fatal("private forensic content included in participant certificate", private)
		}
	}
	oldClaims := claims
	oldClaims.ParticipantReportSchema = ""
	oldClaims.ParticipantReportHTML = ""
	legacy, err := CertificatePayloadV1("prefix", doc, nil, oldClaims, nil)
	if err != nil || !strings.Contains(legacy, `<section class="hash-redaction-report">`) || !strings.Contains(legacy, "PRIVATE-INTAKE-404") {
		t.Fatal("old V1 assembly was scrubbed or changed", err)
	}
	for _, name := range []string{"document", "org", "schema-downgrade", "cutoff", "count", "digest", "visible-text", "root-machine-scope", "intake-prefix", "intake-manifest"} {
		t.Run(name, func(t *testing.T) {
			c := claims
			d := *doc
			prefix := "prefix"
			var manifest *string
			switch name {
			case "document":
				d.ID = uuid.New()
			case "org":
				c.OrgID = uuid.NewString()
			case "schema-downgrade":
				c.ParticipantReportSchema = ParticipantReportSchemaV1
			case "cutoff":
				c.ParticipantReportCutoff = "2026-10-19T12:00:02Z"
			case "count":
				c.ParticipantReportRows++
			case "digest":
				c.ParticipantReportSHA256 = strings.Repeat("f", 64)
			case "visible-text":
				c.ParticipantReportHTML = strings.Replace(c.ParticipantReportHTML, "A participant requested changes", "A participant accepted changes", 1)
			case "root-machine-scope":
				c.DocumentEventsScope = "whole-family"
			case "intake-prefix":
				prefix = `<section class="hash-redaction-report">private</section>`
			case "intake-manifest":
				value := `<section class="hash-redaction-report">private</section>`
				manifest = &value
			}
			if output, err := CertificatePayloadV2(prefix, &d, nil, c, manifest); err == nil || output != "" {
				t.Fatal("wrong native certificate/report association accepted", err)
			}
		})
	}
}

func TestCertificatePayloadV2BoundedWholeAssembly(t *testing.T) {
	f := newReportFixture404(t)
	claims := reportCertificateClaims404(t, f)
	doc := &generated.Document{ID: f.scope.Root, OrgID: f.scope.Org}
	for _, prefix := range []string{strings.Repeat("p", MaxCertificatePayloadBytesV1+1), strings.Repeat("p", MaxCertificatePayloadBytesV1)} {
		if output, err := CertificatePayloadV2(prefix, doc, nil, claims, nil); !errors.Is(err, ErrParticipantReportV1) || !errors.Is(err, ErrCertificatePayloadCapacityV1) || output != "" {
			t.Fatal("oversized complete certificate returned partial/success", err)
		}
	}
	if output, err := CertificatePayloadV2("prefix", nil, nil, claims, nil); err == nil || output != "" {
		t.Fatal("missing document accepted")
	}
}
