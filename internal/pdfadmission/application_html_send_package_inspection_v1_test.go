// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func inspectionFixture236() (*generated.InspectDocumentPackageSendAttemptStateV1Row, uuid.UUID, HTMLSendPackageCaptureMetadataV1) {
	stamp := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
	now := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	id := uuid.New()
	c := HTMLSendPackageCaptureMetadataV1{Present: true, OrgID: uuid.New(), DocumentID: uuid.New(), PackageID: uuid.New(), CreatedBy: uuid.New(), Revision: 2, PreviousRevision: 1, DraftGeneration: 3, RootUpdatedAt: now.Add(-time.Second), CreatedAt: now, ManifestBytes: 512, MemberCount: 1, PDFBytes: 128, PDFPages: 2}
	c.CanonicalSHA256[0] = 1
	c.CommitmentSHA256[0] = 2
	r := &generated.InspectDocumentPackageSendAttemptStateV1Row{AttemptID: id, OrgID: c.OrgID, DocumentID: c.DocumentID, PackageID: c.PackageID, CaptureRevision: c.Revision, PreviousRevision: c.PreviousRevision, CapturedDraftGeneration: c.DraftGeneration, CapturedRootUpdatedAt: stamp(c.RootUpdatedAt), ManifestBytes: c.ManifestBytes, MemberCount: c.MemberCount, PdfBytes: c.PDFBytes, PdfPages: c.PDFPages, ManifestSha256: append([]byte(nil), c.CanonicalSHA256[:]...), LegalCommitmentSha256: append([]byte(nil), c.CommitmentSHA256[:]...), ActorUserID: c.CreatedBy, ExactCapture: true, CaptureCreatedAt: stamp(c.CreatedAt), CreatedAt: stamp(now.Add(time.Second)), Article13NoticeEpochAt: stamp(now.Add(time.Second)), RetainUntil: stamp(storage.EvidenceRetentionDeadline(now.Add(time.Second), article13.RetentionYearsV1)), IntentAttemptID: pgtype.UUID{Bytes: id, Valid: true}, IntentActorUserID: pgtype.UUID{Bytes: c.CreatedBy, Valid: true}}
	r.IntentArticle13NoticeEpochAt = r.Article13NoticeEpochAt
	r.IntentRetainUntil = r.RetainUntil
	return r, id, c
}
func TestExactPackageAttemptClassifiesOnlyValidatedHistoryV1(t *testing.T) {
	for _, kind := range []string{"active", "active-retention-started", "active-retention-complete", "completed", "aborted"} {
		t.Run(kind, func(t *testing.T) {
			r, id, c := inspectionFixture236()
			want := HTMLSendPackageAttemptActiveV1
			if kind == "active-retention-started" || kind == "active-retention-complete" || kind == "completed" {
				r.RetentionStartedAt = r.CreatedAt
				r.IntentRetentionStartedAt = r.RetentionStartedAt
			}
			if kind == "active-retention-complete" || kind == "completed" {
				r.RetentionCompletedAt = r.CreatedAt
				r.IntentRetentionCompletedAt = r.RetentionCompletedAt
			}
			if kind == "completed" || kind == "aborted" {
				r.TerminalOutcome = pgtype.Text{String: kind, Valid: true}
				r.TerminalAt = r.CreatedAt
				r.IntentAttemptID = pgtype.UUID{}
				r.IntentActorUserID = pgtype.UUID{}
				if kind == "completed" {
					want = HTMLSendPackageAttemptCompletedV1
				} else {
					want = HTMLSendPackageAttemptAbortedV1
				}
			}
			got, e := htmlSendPackageAttemptObservationV1(r, id, c)
			if e != nil || got.Outcome != want || got.AttemptID != id || got.Capture != c || !got.RetainUntil.Equal(r.RetainUntil.Time) {
				t.Fatal(got, e)
			}
			got.Capture.CanonicalSHA256[0]++
			if c.CanonicalSHA256[0] != 1 {
				t.Fatal("copied observation changed private expectation")
			}
		})
	}
}
func TestExactPackageAttemptRejectsEveryBindingAndStateDriftV1(t *testing.T) {
	cases := []struct {
		name string
		edit func(*generated.InspectDocumentPackageSendAttemptStateV1Row)
	}{
		{"attempt", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.AttemptID = uuid.New() }},
		{"tenant", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.OrgID = uuid.New() }},
		{"root", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.DocumentID = uuid.New() }},
		{"package", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PackageID = uuid.New() }},
		{"capture revision", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CaptureRevision++ }},
		{"predecessor", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PreviousRevision++ }},
		{"draft generation", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CapturedDraftGeneration++ }},
		{"root clock", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.CapturedRootUpdatedAt.Time = r.CapturedRootUpdatedAt.Time.Add(time.Microsecond)
		}},
		{"root infinity", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.CapturedRootUpdatedAt.InfinityModifier = pgtype.Infinity
		}},
		{"manifest bytes", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ManifestBytes++ }},
		{"members", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.MemberCount++ }},
		{"pdf bytes", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PdfBytes++ }},
		{"pdf pages", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.PdfPages++ }},
		{"raw commitment", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ManifestSha256[0]++ }},
		{"legal commitment", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.LegalCommitmentSha256[0]++ }},
		{"birth actor", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ActorUserID = uuid.New() }},
		{"capture time", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.CaptureCreatedAt.Time = r.CaptureCreatedAt.Time.Add(time.Microsecond)
		}},
		{"capture absent", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.ExactCapture = false }},
		{"creation missing", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.CreatedAt.Valid = false }},
		{"epoch missing", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.Article13NoticeEpochAt.Valid = false }},
		{"epoch infinity", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.Article13NoticeEpochAt.InfinityModifier = pgtype.Infinity
		}},
		{"deadline", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.RetainUntil.Time = r.RetainUntil.Time.Add(time.Second)
		}},
		{"deadline infinity", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.RetainUntil.InfinityModifier = pgtype.Infinity
		}},
		{"retention complete without start", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.RetentionCompletedAt = r.CreatedAt }},
		{"retention start infinity", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.RetentionStartedAt = r.CreatedAt
			r.RetentionStartedAt.InfinityModifier = pgtype.Infinity
		}},
		{"intent absent", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.IntentAttemptID.Valid = false }},
		{"intent rebound", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.IntentAttemptID.Bytes = uuid.New() }},
		{"intent actor", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.IntentActorUserID.Bytes = uuid.New() }},
		{"intent actor missing", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.IntentActorUserID.Valid = false }},
		{"intent presign", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.IntentPresignExecutionID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		}},
		{"intent epoch", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.IntentArticle13NoticeEpochAt.Time = r.CreatedAt.Time.Add(time.Second)
		}},
		{"intent deadline", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.IntentRetainUntil.Valid = false }},
		{"intent progress", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.IntentRetentionStartedAt = r.CreatedAt
		}},
		{"intent completion progress", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.IntentRetentionCompletedAt = r.CreatedAt
		}},
		{"active with terminal time", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) { r.TerminalAt = r.CreatedAt }},
		{"terminal missing time", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.TerminalOutcome = pgtype.Text{String: "aborted", Valid: true}
			r.IntentAttemptID.Valid = false
		}},
		{"terminal keeps intent", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.TerminalOutcome = pgtype.Text{String: "aborted", Valid: true}
			r.TerminalAt = r.CreatedAt
		}},
		{"completed without retention", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.TerminalOutcome = pgtype.Text{String: "completed", Valid: true}
			r.TerminalAt = r.CreatedAt
			r.IntentAttemptID.Valid = false
		}},
		{"aborted after retention", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.TerminalOutcome = pgtype.Text{String: "aborted", Valid: true}
			r.TerminalAt = r.CreatedAt
			r.IntentAttemptID.Valid = false
			r.RetentionStartedAt = r.CreatedAt
		}},
		{"unknown terminal", func(r *generated.InspectDocumentPackageSendAttemptStateV1Row) {
			r.TerminalOutcome = pgtype.Text{String: "maybe", Valid: true}
			r.TerminalAt = r.CreatedAt
			r.IntentAttemptID.Valid = false
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, id, c := inspectionFixture236()
			tc.edit(r)
			got, e := htmlSendPackageAttemptObservationV1(r, id, c)
			if !errors.Is(e, ErrHTMLSendPackageInspectionV1) || got != (HTMLSendPackageAttemptObservationV1{}) {
				t.Fatal(got, e)
			}
		})
	}
}
func TestPackageAttemptReferenceRetainsActualGrantUntilJoinedCloseV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	coord, e := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 1 << 20}, Organisation: workguard.VectorV1{ParentBytes: 1 << 20}, MaxGrants: 4, MaxOrganisationGrants: 4})
	if e != nil {
		t.Fatal(e)
	}
	g, e := coord.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
	if e != nil {
		t.Fatal(e)
	}
	r := &applicationHTMLSendPackageAttemptReferenceV1{grant: g, capture: HTMLSendPackageCaptureMetadataV1{Present: true}}
	if !r.lockV1() {
		t.Fatal("reference borrow")
	}
	r.closeV1()
	r.closeV1()
	if !r.capture.Present || coord.SnapshotV1(org).Global.ParentBytes != 4096 {
		t.Fatal("close retired a live reference")
	}
	r.unlockV1()
	if r.capture.Present || r.grant != nil || coord.SnapshotV1(org).Global.ParentBytes != 0 || r.lockV1() {
		t.Fatal("joined reference retained or revived")
	}
}
func TestPackageAttemptInspectionRejectsAbsentOrCopiedWorkV1(t *testing.T) {
	var absent *ApplicationHTMLSendWorkV1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, w := range []*ApplicationHTMLSendWorkV1{absent, {}, {self: &ApplicationHTMLSendWorkV1{}}} {
		got, e := w.InspectPackageSendAttemptV1(ctx)
		if !errors.Is(e, ErrHTMLSendPackageInspectionV1) || got != (HTMLSendPackageAttemptObservationV1{}) {
			t.Fatal(got, e)
		}
	}
}
