// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

// These are predicate-only scope/clock refusals. A synthetic row grants no
// Source24 handle, callback, SQL session, body loan or serialization authority.
// The real family/source last-use journeys qualify those independent gates.
func TestHistoricalSourceContinuationRequiresExactFreshRootStateV1(t *testing.T) {
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC), Valid: true}
	d := &generated.Document{ID: uuid.MustParse("df63dce3-32eb-4bf4-b186-88ad47761479"), OrgID: uuid.MustParse("dd1b4c8a-c178-47c2-8d43-4dc511fc3795"), Status: "finalizing", SourceKind: "blocks", IsEnvelope: true, RequiresSignature: true, EvidenceVersionPinsRequired: true, UpdatedAt: stamp}
	h := &generated.GetHTMLSendDocumentStateHeaderV1Row{ID: d.ID, OrgID: d.OrgID, BoundedStatus: d.Status, IsEnvelope: true, RequiresSignature: true, EvidenceVersionPinsRequired: true, UpdatedAt: stamp}
	if !historicalSourceContinuationStateMatchesV1(d, h) {
		t.Fatal("exact real-header tuple shape rejected")
	}
	for name, change := range map[string]func(*generated.GetHTMLSendDocumentStateHeaderV1Row){
		"document": func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.ID[0] ^= 1 },
		"org":      func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.OrgID[0] ^= 1 },
		"advanced": func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) {
			x.UpdatedAt.Time = x.UpdatedAt.Time.Add(time.Microsecond)
		},
		"older": func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) {
			x.UpdatedAt.Time = x.UpdatedAt.Time.Add(-time.Microsecond)
		},
		"missingClock":  func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.UpdatedAt = pgtype.Timestamptz{} },
		"infiniteClock": func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.UpdatedAt.InfinityModifier = pgtype.Infinity },
		"status":        func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.BoundedStatus = "completed" },
		"notEnvelope":   func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.IsEnvelope = false },
		"nested": func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) {
			x.ParentEnvelopeID = pgtype.UUID{Bytes: d.ID, Valid: true}
		},
		"mode":   func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.RequiresSignature = false },
		"source": func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.IsPdfSource = true },
		"pins":   func(x *generated.GetHTMLSendDocumentStateHeaderV1Row) { x.EvidenceVersionPinsRequired = false },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *h
			change(&copy)
			if historicalSourceContinuationStateMatchesV1(d, &copy) {
				t.Fatal("changed actual root scope/clock accepted")
			}
		})
	}
}
