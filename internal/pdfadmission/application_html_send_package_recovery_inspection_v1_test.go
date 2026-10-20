// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"testing"
)

func TestDurablePackageInspectionReconstructsDetachedCaptureV1(t *testing.T) {
	r, id, want := inspectionFixture236()
	got, err := htmlSendRecoveryCaptureV1(r, id, want.OrgID, want.DocumentID)
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	r.ManifestSha256[0]++
	r.LegalCommitmentSha256[0]++
	if got.CanonicalSHA256 != want.CanonicalSHA256 || got.CommitmentSHA256 != want.CommitmentSHA256 {
		t.Fatal("capture aliases SQL buffers")
	}
}

func TestDurablePackageInspectionRejectsUntrustedHistoryV1(t *testing.T) {
	cases := []struct {
		name string
		edit func(*generated.InspectDocumentPackageSendAttemptStateV1Row)
	}{
		{"foreign attempt", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.AttemptID = uuid.New() }},
		{"foreign tenant", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.OrgID = uuid.New() }},
		{"foreign root", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.DocumentID = uuid.New() }},
		{"missing capture", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ExactCapture = false }},
		{"missing creator", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ActorUserID = uuid.Nil }},
		{"missing package", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PackageID = uuid.Nil }},
		{"missing capture time", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CaptureCreatedAt.Valid = false }},
		{"missing historical clock", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CapturedRootUpdatedAt.Valid = false }},
		{"revision gap", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CaptureRevision++ }},
		{"zero generation", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CapturedDraftGeneration = 0 }},
		{"oversize manifest", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ManifestBytes = 65537 }},
		{"empty manifest", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ManifestBytes = 0 }},
		{"too many members", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.MemberCount = 18 }},
		{"no members", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.MemberCount = 0 }},
		{"oversize PDF", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PdfBytes = (50 << 20) + 1 }},
		{"no PDF bytes", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PdfBytes = 0 }},
		{"too many pages", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PdfPages = 501 }},
		{"no pages", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PdfPages = 0 }},
		{"short raw hash", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.ManifestSha256 = r.ManifestSha256[:31]
		}},
		{"long legal hash", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.LegalCommitmentSha256 = append(r.LegalCommitmentSha256, 0)
		}},
		{"zero raw hash", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ManifestSha256 = make([]byte, 32) }},
		{"zero legal hash", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.LegalCommitmentSha256 = make([]byte, 32)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, id, want := inspectionFixture236()
			c.edit(r)
			got, e := htmlSendRecoveryCaptureV1(r, id, want.OrgID, want.DocumentID)
			if e == nil || got != (HTMLSendPackageCaptureMetadataV1{}) {
				t.Fatal(got, e)
			}
		})
	}
}

func TestDurablePackageInspectionValidatesActualFrozenSubjectsV1(t *testing.T) {
	for _, kind := range []string{"valid", "no members", "extra member", "missing member", "nil row", "out of order", "duplicate", "zero subject", "wrong main"} {
		t.Run(kind, func(t *testing.T) {
			_, _, c := inspectionFixture236()
			c.MemberCount = 2
			rows := []*generated.ListDocumentPackageSendAttemptSubjectsV1Row{{MemberPosition: 0, MemberDocumentID: c.DocumentID}, {MemberPosition: 1, MemberDocumentID: uuid.New()}}
			switch kind {
			case "no members":
				c.MemberCount = 0
			case "extra member":
				rows = append(rows, &generated.ListDocumentPackageSendAttemptSubjectsV1Row{MemberPosition: 2, MemberDocumentID: uuid.New()})
			case "missing member":
				rows = rows[:1]
			case "nil row":
				rows[1] = nil
			case "out of order":
				rows[1].MemberPosition = 2
			case "duplicate":
				rows[1].MemberDocumentID = c.DocumentID
			case "zero subject":
				rows[1].MemberDocumentID = uuid.Nil
			case "wrong main":
				rows[0].MemberDocumentID = uuid.New()
			}
			got, e := htmlSendRecoverySubjectsV1(rows, c)
			if kind == "valid" {
				if e != nil || got[0] != c.DocumentID || got[1] != rows[1].MemberDocumentID {
					t.Fatal(got, e)
				}
			} else if e == nil {
				t.Fatal("malformed original subjects accepted", got)
			}
		})
	}
}
