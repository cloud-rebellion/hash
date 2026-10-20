// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestHistoricalRenderContinuationExactScopeClockAndSourceV1(t *testing.T) {
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 12, 0, 0, 123000, time.UTC), Valid: true}
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SourceKind: "pdf", Status: "finalizing", RequiresSignature: true, EvidenceVersionPinsRequired: true, UpdatedAt: stamp}
	state := &generated.GetHTMLSendDocumentStateHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, IsPdfSource: true, BoundedStatus: doc.Status, RequiresSignature: true, EvidenceVersionPinsRequired: true, UpdatedAt: stamp}
	if !historicalRenderContinuationStateMatchesV1(doc, state) {
		t.Fatal("actual ordinary source tuple refused")
	}
	parent := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.ParentEnvelopeID = parent
	state.ParentEnvelopeID = parent
	if !historicalRenderContinuationStateMatchesV1(doc, state) {
		t.Fatal("actual member source tuple refused")
	}
	cases := map[string]func(*generated.GetHTMLSendDocumentStateHeaderV1Row){
		"document": func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.ID = uuid.New() },
		"org":      func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.OrgID = uuid.New() },
		"kind":     func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.IsPdfSource = false },
		"status":   func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.BoundedStatus = "in_progress" },
		"mode":     func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.RequiresSignature = false },
		"pins":     func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.EvidenceVersionPinsRequired = false },
		"parent": func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) {
			h.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		},
		"topology": func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.IsEnvelope = true },
		"clock": func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) {
			h.UpdatedAt.Time = h.UpdatedAt.Time.Add(time.Microsecond)
		},
		"infinite": func(h *generated.GetHTMLSendDocumentStateHeaderV1Row) { h.UpdatedAt.InfinityModifier = pgtype.Infinity },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			h := *state
			change(&h)
			if historicalRenderContinuationStateMatchesV1(doc, &h) {
				t.Fatal("changed actual source/header accepted")
			}
		})
	}
	if historicalRenderContinuationStateMatchesV1(nil, state) || historicalRenderContinuationStateMatchesV1(doc, nil) {
		t.Fatal("nil source/header accepted")
	}
}

func TestHistoricalRenderContinuationCannotInventNativeWorkV1(t *testing.T) {
	var source *ApplicationHistoricalFinalizationSourceEvidenceV1
	if doc, err := source.NewHistoricalRenderContinuationV1(context.Background(), nil); doc != nil || err == nil {
		t.Fatal("nil source admitted")
	}
	source = &ApplicationHistoricalFinalizationSourceEvidenceV1{}
	source.self = source
	work := &ApplicationHTMLSendWorkV1{}
	work.self = work
	if doc, err := source.NewHistoricalRenderContinuationV1(context.Background(), work); doc != nil || err == nil {
		t.Fatal("invented source/work admitted")
	}
}
