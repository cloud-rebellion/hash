// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"fmt"
	"math"
	"sort"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RequiredRoles resolves signing parties from actual placed fields and a
// reviewed HTML contract's independent pinned party declaration, never from a
// mutable live template or a recipient's display order.
// Callers hold the document lock at mutation/finalization boundaries. A zero
// pageCount permits role rechecks after send; stamping checks the exact source
// page range again before producing the final artifact.
func RequiredRoles(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, pageCount int) ([]string, error) {
	if doc == nil || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.IsEnvelope {
		return nil, invalid("standalone signature-required PDF is required")
	}
	// Reviewed HTML contracts declare their intended parties independently of
	// the editable recipient and field lists. Removing both a party and its
	// placed field must not reduce the signatures needed for that contract.
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		return nil, invalid("reviewed contract parties: %v", err)
	}
	if len(rows) == 0 || len(rows) > MaxParties || len(fields) == 0 || len(fields) > MaxFields {
		return nil, invalid("PDF needs bounded recipients and placed signature fields")
	}
	byID := make(map[uuid.UUID]*generated.Recipient, len(rows))
	byRole := make(map[string]uuid.UUID, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != doc.ID || !recipients.CanRespond(row.Role) {
			return nil, invalid("PDF recipient must belong to this document and have a signing role")
		}
		if _, exists := byID[row.ID]; exists {
			return nil, invalid("duplicate PDF recipient")
		}
		if _, exists := byRole[row.Role]; exists {
			return nil, invalid("each PDF party role must have exactly one recipient")
		}
		byID[row.ID], byRole[row.Role] = row, row.ID
	}
	seen := make(map[string]bool, len(rows))
	for _, field := range fields {
		if field == nil || field.DocumentID != doc.ID || !field.RecipientID.Valid || !ValidPlacement(field, pageCount) {
			return nil, invalid("every PDF field must belong to this document and have valid placement and assignment")
		}
		owner, exists := byID[uuid.UUID(field.RecipientID.Bytes)]
		if !exists {
			return nil, invalid("PDF field references an absent signing party")
		}
		if field.Type != "signature" {
			// The legacy single-signer fillable ceremony remains available.
			// Multiple parties may add signatures only: mutable visible values
			// need a separately approved content-freeze workflow first.
			if len(rows) != 1 || owner.Role != "signer" {
				return nil, invalid("named-party PDF ceremonies support signature fields only")
			}
			switch field.Type {
			case "text", "date", "checkbox", "dropdown", "initial":
			default:
				return nil, invalid("unsupported PDF field type")
			}
			continue
		}
		if !field.Required {
			return nil, invalid("every PDF signature field must be required")
		}
		seen[owner.Role] = true
	}
	roles := make([]string, 0, len(byRole))
	for role := range byRole {
		if !seen[role] {
			return nil, invalid("party %s has no required visible signature field", role)
		}
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

func ValidPlacement(field *generated.DocumentField, pageCount int) bool {
	if field == nil || field.Page < 1 || (pageCount > 0 && int(field.Page) > pageCount) {
		return false
	}
	x, xok := finitePercent(field.XPct)
	y, yok := finitePercent(field.YPct)
	w, wok := finitePercent(field.WPct)
	h, hok := finitePercent(field.HPct)
	return xok && yok && wok && hok && x >= 0 && y >= 0 && w > 0 && h > 0 && x < 100 && y < 100 && x+w <= 100 && y+h <= 100
}

func finitePercent(value pgtype.Numeric) (float64, bool) {
	if !value.Valid || value.Int == nil || value.NaN || value.InfinityModifier != pgtype.Finite {
		return 0, false
	}
	n, err := value.Float64Value()
	return n.Float64, err == nil && n.Valid && !math.IsNaN(n.Float64) && !math.IsInf(n.Float64, 0)
}

// ValidateSignatureRows prevents a stored status alone from authorizing an
// unsigned or foreign party's visible stamp. The signature must name the
// exact recipient and one of that recipient's required placed fields.
func ValidateSignatureRows(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, signatures []*generated.Signature, pageCount int) error {
	if _, err := RequiredRoles(doc, rows, fields, pageCount); err != nil {
		return err
	}
	owners := make(map[uuid.UUID]*generated.DocumentField)
	for _, field := range fields {
		if field.Type == "signature" {
			owners[field.ID] = field
		}
	}
	seen := make(map[uuid.UUID]bool)
	for _, signature := range signatures {
		if signature == nil || signature.DocumentID != doc.ID || seen[signature.RecipientID] {
			return invalid("duplicate or foreign PDF signature")
		}
		field := owners[signature.FieldID]
		if field == nil || uuid.UUID(field.RecipientID.Bytes) != signature.RecipientID {
			return invalid("PDF signature is not bound to its recipient's required field")
		}
		seen[signature.RecipientID] = true
	}
	for _, row := range rows {
		if row.Status != "signed" || !seen[row.ID] {
			return fmt.Errorf("%w: every PDF party must have a captured signature", ErrInvalid)
		}
	}
	return nil
}
