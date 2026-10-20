// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestHistoricalFinalizationChildFreezeUsesActualMonotonicClockV1(t *testing.T) {
	stamp := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	root := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), IsEnvelope: true, Status: "finalizing", CompletionEffectiveAtBound: true, CompletionEffectiveAt: stamp(now.Add(time.Second)), FinalizationRetainUntil: stamp(now.AddDate(7, 0, 0))}
	old := &generated.Document{ID: uuid.New(), OrgID: root.OrgID, ParentEnvelopeID: pgtype.UUID{Bytes: root.ID, Valid: true}, Status: "sent", UpdatedAt: stamp(now), SourceKind: "blocks", BlocksJson: []byte("{\"version\":1}"), EvidenceVersionPinsRequired: true}
	child := *old
	child.Status = "finalizing"
	child.CompletionEffectiveAtBound = root.CompletionEffectiveAtBound
	child.CompletionEffectiveAt = root.CompletionEffectiveAt
	child.FinalizationRetainUntil = root.FinalizationRetainUntil
	child.UpdatedAt = stamp(now.Add(2 * time.Second))
	if !historicalFinalizationChildFreezeTupleV1(old, &child, root) {
		t.Fatal("actual independent M67 row clock rejected")
	}
	cases := map[string]func(*generated.Document){"repeatedClock": func(d *generated.Document) { d.UpdatedAt = old.UpdatedAt }, "backwardClock": func(d *generated.Document) { d.UpdatedAt = stamp(now.Add(-time.Second)) }, "missingClock": func(d *generated.Document) { d.UpdatedAt = pgtype.Timestamptz{} }, "completion": func(d *generated.Document) {
		d.CompletionEffectiveAt.Time = d.CompletionEffectiveAt.Time.Add(time.Microsecond)
	}, "retention": func(d *generated.Document) {
		d.FinalizationRetainUntil.Time = d.FinalizationRetainUntil.Time.Add(time.Second)
	}, "pins": func(d *generated.Document) { d.EvidenceVersionPinsRequired = false }, "source": func(d *generated.Document) { d.BlocksJson = bytes.Clone(old.BlocksJson); d.BlocksJson[0] = 'x' }, "unrelatedStatus": func(d *generated.Document) { d.Status = "completed" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			copy := child
			change(&copy)
			if historicalFinalizationChildFreezeTupleV1(old, &copy, root) {
				t.Fatal("changed legal/source tuple or invalid row clock accepted")
			}
		})
	}
}
