// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendments

import (
	"github.com/google/uuid"
	"strings"
	"testing"
)

func signerDisclosureFixture483() *SignerContextV1 {
	return &SignerContextV1{Schema: SignerContextSchemaV1, AmendmentID: uuid.New(), Revision: "1", DocumentID: uuid.New(), OriginalDocumentID: uuid.New(), OriginalName: " Saved original agreement ", OriginalFinalPDFSHA256: strings.Repeat("1", 64), OriginalReportSHA256: strings.Repeat("2", 64), OriginalReportPDFSHA256: strings.Repeat("3", 64), Mode: SignatureV1, FileCommitmentSHA256: strings.Repeat("4", 64)}
}
func TestSignerAmendmentDisclosureClosedShapeModeAndOriginalPinsV1(t *testing.T) {
	c := signerDisclosureFixture483()
	if c.ValidateV1(c.DocumentID, true) != nil || c.OriginalReportSHA256 == c.OriginalReportPDFSHA256 {
		t.Fatal("valid distinct saved report pins rejected")
	}
	copy := CloneSignerContextV1(c)
	if copy == c || !EqualSignerContextV1(c, copy) {
		t.Fatal("context clone aliases mutable model")
	}
	copy.OriginalName += " changed"
	if EqualSignerContextV1(c, copy) || c.OriginalName != " Saved original agreement " {
		t.Fatal("clone changed saved original")
	}
	var absent *SignerContextV1
	if absent.ValidateV1(uuid.New(), false) != nil || !EqualSignerContextV1(nil, nil) || EqualSignerContextV1(c, nil) {
		t.Fatal("unlinked ordinary mode changed")
	}
	for _, tc := range []struct {
		name   string
		change func(*SignerContextV1)
	}{
		{"unknownschema", func(v *SignerContextV1) { v.Schema = "unknown" }},
		{"zeroamendment", func(v *SignerContextV1) { v.AmendmentID = uuid.Nil }},
		{"zerorevision", func(v *SignerContextV1) { v.Revision = "0" }},
		{"noncanonicalrevision", func(v *SignerContextV1) { v.Revision = "01" }},
		{"excessrevision", func(v *SignerContextV1) { v.Revision = "65" }},
		{"differentcandidate", func(v *SignerContextV1) { v.DocumentID = uuid.New() }},
		{"selforiginal", func(v *SignerContextV1) { v.OriginalDocumentID = v.DocumentID }},
		{"missingname", func(v *SignerContextV1) { v.OriginalName = "" }},
		{"blankname", func(v *SignerContextV1) { v.OriginalName = "  " }},
		{"namebytebound", func(v *SignerContextV1) { v.OriginalName = strings.Repeat("ö", 257) }},
		{"controlname", func(v *SignerContextV1) { v.OriginalName = "saved\u0085original" }},
		{"invalidutf8name", func(v *SignerContextV1) { v.OriginalName = string([]byte{0xff}) }},
		{"badfinal", func(v *SignerContextV1) { v.OriginalFinalPDFSHA256 = "" }},
		{"badcanonicalreport", func(v *SignerContextV1) { v.OriginalReportSHA256 = strings.Repeat("A", 64) }},
		{"badreportpdf", func(v *SignerContextV1) { v.OriginalReportPDFSHA256 = "unknown" }},
		{"badfilecommitment", func(v *SignerContextV1) { v.FileCommitmentSHA256 = strings.Repeat("0", 63) }},
		{"noticeisnotceremony", func(v *SignerContextV1) { v.Mode = AgreedNoticeV1 }},
		{"wrongceremonymode", func(v *SignerContextV1) { v.Mode = AcknowledgementV1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := CloneSignerContextV1(c)
			tc.change(v)
			if v.ValidateV1(c.DocumentID, true) == nil {
				t.Fatal("unverified disclosure admitted")
			}
		})
	}
	c.Mode = AcknowledgementV1
	if c.ValidateV1(c.DocumentID, false) != nil || c.ValidateV1(c.DocumentID, true) == nil {
		t.Fatal("acknowledgement presented as signature")
	}
}
