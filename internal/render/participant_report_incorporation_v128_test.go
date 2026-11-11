// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package render

import (
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/documentpackage"
)

func TestSwedishStatementUsesActualFrozenReportPairV128(t *testing.T) {
	r := participantReportHTMLFixtureV2()
	sv := documentpackage.IncorporationCopyForLocaleV1("sv")
	r.Responses[0].IncorporationVersion, r.Responses[0].IncorporationSHA256 = sv.Version, sv.SHA256
	for _, render := range []func() (string, string, error){r.HTMLV1, r.HTMLV2} {
		html, _, err := render()
		if err != nil || !strings.Contains(html, sv.Text) || !strings.Contains(html, sv.SHA256) || !strings.Contains(html, sv.Version) {
			t.Fatal("report omitted frozen Swedish statement", err)
		}
	}
	f := newReportFixture404(t)
	f.report.Responses[0].IncorporationVersion, f.report.Responses[0].IncorporationSHA256 = sv.Version, sv.SHA256
	html, _, err := f.report.HTMLV3()
	if err != nil || !strings.Contains(html, sv.Text) {
		t.Fatal("current report omitted exact Swedish statement", err)
	}
	for _, invalid := range []ParticipantReportResponseV1{
		{IncorporationVersion: sv.Version, IncorporationSHA256: documentpackage.IncorporationSHA256V1},
		{IncorporationVersion: documentpackage.IncorporationVersionV1, IncorporationSHA256: sv.SHA256},
		{IncorporationVersion: "unsupported", IncorporationSHA256: sv.SHA256},
	} {
		if participantReportSwedishIncorporationV128(invalid) != "" {
			t.Fatal("report relabelled another proof as Swedish")
		}
	}
}

func TestLegacyEnglishReportCanonicalBytesUnchangedV128(t *testing.T) {
	r := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: "document", Cutoff: "2026-11-11T00:00:00Z", Responses: []ParticipantReportResponseV1{{RecipientID: "recipient", IncorporationVersion: documentpackage.IncorporationVersionV1, IncorporationSHA256: documentpackage.IncorporationSHA256V1}}}
	raw, _, err := r.CanonicalV1()
	const expected = `{"schema":"hash-participant-report-v1","document_id":"document","cutoff":"2026-11-11T00:00:00Z","events":null,"comments":null,"revisions":null,"proposals":null,"members":null,"responses":[{"RecipientID":"recipient","AttemptID":"","ManifestSHA256":"","LegalCommitmentSHA256":"","Kind":"","SignatureID":"","EventID":"","EventRowSHA256":"","At":"","IncorporationVersion":"hash-package-incorporation-v1","IncorporationSHA256":"ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670"}]}`
	if err != nil || string(raw) != expected {
		t.Fatal("legacy canonical report bytes changed", err)
	}
	if participantReportSwedishIncorporationV128(r.Responses[0]) != "" {
		t.Fatal("legacy English report gained new statement markup")
	}
}
