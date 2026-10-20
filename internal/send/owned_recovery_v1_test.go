// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestOwnedSendCompletedScalarStatusMatchesOriginalV1(t *testing.T) {
	epoch := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	// Test-only translation into the exact scalar header compares the original
	// function as oracle. Production never constructs a sentinel/partial Document.
	project := func(d *generated.Document) *generated.GetHTMLSendDocumentStateHeaderV1Row {
		if d == nil {
			return nil
		}
		return &generated.GetHTMLSendDocumentStateHeaderV1Row{BoundedStatus: d.Status, EvidenceVersionPinsRequired: d.EvidenceVersionPinsRequired,
			SentAt: d.SentAt, Article13NoticeEpochAt: d.Article13NoticeEpochAt, Article13NoticeEpochV61Committed: d.Article13NoticeEpochV61Committed,
			HasSupportedArticle13NoticeSchema: article13.IsSupportedSchema(d.Article13NoticeSchema)}
	}
	base := generated.Document{EvidenceVersionPinsRequired: true, SentAt: pgtype.Timestamptz{Time: epoch, Valid: true}, Article13NoticeEpochAt: pgtype.Timestamptz{Time: epoch, Valid: true}, Article13NoticeEpochV61Committed: true, Article13NoticeSchema: article13.CurrentSchema}
	for _, status := range []string{"draft", "sealing", "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired", "unknown"} {
		t.Run(status, func(t *testing.T) {
			for _, mutate := range []func(*generated.Document){func(*generated.Document) {}, func(d *generated.Document) { d.EvidenceVersionPinsRequired = false }, func(d *generated.Document) { d.SentAt.Valid = false }, func(d *generated.Document) { d.SentAt.Time = time.Time{} }, func(d *generated.Document) { d.Article13NoticeEpochAt.Valid = false }, func(d *generated.Document) { d.Article13NoticeEpochAt.Time = d.SentAt.Time.Add(time.Second) }, func(d *generated.Document) { d.Article13NoticeEpochV61Committed = false }, func(d *generated.Document) { d.Article13NoticeSchema = "unrecognized" }, func(d *generated.Document) {
				d.SentAt.Time = d.SentAt.Time.Add(time.Nanosecond)
				d.Article13NoticeEpochAt.Time = d.SentAt.Time
			}} {
				doc := base
				doc.Status = status
				mutate(&doc)
				expected, accepted := completedSendSealingStatus(&doc)
				got, ok := completedOwnedSendStatusV1(project(&doc))
				if ok != accepted || got.Status != expected.Status || len(got.Links) != 0 {
					t.Fatalf("scalar recovery drift: original%+v/%v owned%+v/%v", expected, accepted, got, ok)
				}
			}
		})
	}
	if _, ok := completedOwnedSendStatusV1(nil); ok {
		t.Fatal("nil completed header accepted")
	}
}
