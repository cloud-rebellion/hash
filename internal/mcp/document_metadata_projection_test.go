// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestEnvelopeMetadataProjectionPreservesExistingWireContract(t *testing.T) {
	for _, completed := range []bool{false, true} {
		name := "draft"
		if completed {
			name = "completed"
		}
		t.Run(name, func(t *testing.T) {
			doc := &generated.Document{
				ID: uuid.New(), Name: "Named child", Status: name, SourceKind: "pdf",
				CreatedAt:             pgtype.Timestamptz{Time: time.Date(2026, 10, 10, 7, 30, 0, 123000000, time.UTC), Valid: true},
				ParentEnvelopeID:      pgtype.UUID{Bytes: uuid.New(), Valid: true},
				EnvelopePosition:      pgtype.Int4{Int32: 2, Valid: true},
				HtmlSourceJson:        json.RawMessage(`{"private":"origin design"}`),
				HtmlCurrentSourceJson: json.RawMessage(`{"private":"current design"}`),
			}
			if completed {
				doc.FinalPdfKey = pgtype.Text{String: "exact-final-pdf", Valid: true}
				doc.FinalPdfSha = bytes.Repeat([]byte{0x1a}, 32)
				doc.CompletedAt = pgtype.Timestamptz{Time: doc.CreatedAt.Time.Add(time.Hour), Valid: true}
			}
			row := &generated.ListEnvelopeChildMetadataForReadRow{
				ID: doc.ID, Name: doc.Name, Status: doc.Status, SourceKind: doc.SourceKind,
				IsEnvelope: doc.IsEnvelope, CreatedAt: doc.CreatedAt, ParentEnvelopeID: doc.ParentEnvelopeID,
				EnvelopePosition: doc.EnvelopePosition, FinalPdfKey: doc.FinalPdfKey, FinalPdfSha: doc.FinalPdfSha,
				CompletedAt: doc.CompletedAt, HasHtmlSource: true, HtmlReviewRequired: true,
			}
			before, err := json.Marshal(envelopeRow(doc))
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(envelopeMetadataRow(row))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("thin envelope read changed the existing wire metadata contract")
			}
		})
	}
}
