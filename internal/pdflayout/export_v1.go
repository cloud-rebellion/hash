// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdflayout

import (
	"bytes"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math"
)

// Original identity-free export input and kernel shared by the existing route
// and its fixed native producer. These pure values/functions supply no source,
// actor, transaction, template creation or measurement authority.
type ExportInputV1 struct {
	Name              string          `json:"name"`
	ExpectedUpdatedAt string          `json:"expected_updated_at"`
	ExpectedFieldIDs  []uuid.UUID     `json:"expected_field_ids"`
	Parties           []ExportPartyV1 `json:"parties"`
}
type ExportPartyV1 struct {
	RecipientID uuid.UUID `json:"recipient_id"`
	Role        string    `json:"role"`
	Label       string    `json:"label"`
}

func SamePDFTemplateSourceV1(a, b *generated.Document) bool {
	return a != nil && b != nil && b.SourceKind == "pdf" && a.PdfStorageKey == b.PdfStorageKey && a.PdfStorageVersionID == b.PdfStorageVersionID &&
		a.EvidenceVersionPinsRequired == b.EvidenceVersionPinsRequired && bytes.Equal(a.PdfSha256, b.PdfSha256)
}

func ExportDocumentLayoutV1(doc *generated.Document, recs []*generated.Recipient, fields []*generated.DocumentField, in ExportInputV1, pages int32) (*Layout, error) {
	if len(fields) != len(in.ExpectedFieldIDs) {
		return nil, ErrPrecondition
	}
	expected := make(map[uuid.UUID]bool, len(in.ExpectedFieldIDs))
	for _, id := range in.ExpectedFieldIDs {
		if id == uuid.Nil || expected[id] {
			return nil, fmt.Errorf("%w: observed field IDs must be unique", ErrInvalid)
		}
		expected[id] = true
	}
	currentRecipients := make(map[uuid.UUID]*generated.Recipient, len(recs))
	for _, rec := range recs {
		if rec != nil && rec.DocumentID == doc.ID {
			currentRecipients[rec.ID] = rec
		}
	}
	owners := make(map[uuid.UUID]ExportPartyV1, len(in.Parties))
	layout := &Layout{Version: 1, Parties: make([]Party, 0, len(in.Parties)), Fields: make([]Field, 0, len(fields))}
	for _, party := range in.Parties {
		if party.RecipientID == uuid.Nil || currentRecipients[party.RecipientID] == nil {
			return nil, ErrPrecondition
		}
		if _, exists := owners[party.RecipientID]; exists {
			return nil, fmt.Errorf("%w: a recipient cannot own multiple slots", ErrInvalid)
		}
		owners[party.RecipientID] = party
		layout.Parties = append(layout.Parties, Party{Role: party.Role, Label: party.Label})
	}
	used := make(map[uuid.UUID]bool, len(owners))
	for _, field := range fields {
		if field == nil || !expected[field.ID] || field.DocumentID != doc.ID {
			return nil, ErrPrecondition
		}
		if field.Type != "signature" || !field.Required || field.Value.Valid || field.CompletedAt.Valid || !field.RecipientID.Valid {
			return nil, fmt.Errorf("%w: save required signature fields only; remove fillable fields before saving", ErrInvalid)
		}
		id := uuid.UUID(field.RecipientID.Bytes)
		party, exists := owners[id]
		if !exists {
			return nil, ErrPrecondition
		}
		used[id] = true
		values := make([]float64, 4)
		for i, value := range []pgtype.Numeric{field.XPct, field.YPct, field.WPct, field.HPct} {
			number, err := value.Float64Value()
			if err != nil || !number.Valid || math.IsNaN(number.Float64) || math.IsInf(number.Float64, 0) {
				return nil, fmt.Errorf("%w: invalid persisted geometry", ErrInvalid)
			}
			values[i] = number.Float64
		}
		layout.Fields = append(layout.Fields, Field{PartyRole: party.Role, Type: "signature", Page: field.Page, XPct: values[0], YPct: values[1], WPct: values[2], HPct: values[3], Required: true, Label: field.Label.String})
	}
	if len(used) != len(owners) {
		return nil, fmt.Errorf("%w: every party must own a signature field", ErrInvalid)
	}
	if err := layout.Validate(pages); err != nil {
		return nil, err
	}
	return layout, nil
}
