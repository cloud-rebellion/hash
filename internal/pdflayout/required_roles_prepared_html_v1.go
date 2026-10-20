// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdflayout

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"sort"
)

// RequiredRolesPreparedHTMLV1 reuses only an exact already-current-validated
// immutable HTML tuple. Every actual row, placement, ownership, required-role
// and field-option decision remains the original RequiredRoles policy. This
// pure function grants no native resources, page proof or mutation authority.
func RequiredRolesPreparedHTMLV1(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, pageCount int, prepared *htmlsource.RevisionValidationV1) ([]string, error) {
	if doc == nil || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.IsEnvelope {
		return nil, invalid("standalone signature-required PDF is required")
	}
	if prepared == nil || !prepared.MatchesDocumentV1(doc) {
		return nil, invalid("prepared HTML scope")
	}
	// Reviewed HTML contracts declare their intended parties independently of
	// the editable recipient and field lists. Removing both a party and its
	// placed field must not reduce the signatures needed for that contract.
	if err := prepared.ValidateContractPartiesV1(rows); err != nil {
		return nil, invalid("reviewed contract parties: %v", err)
	}
	if err := prepared.ValidateSigningFieldsV1(fields, pageCount); err != nil {
		return nil, invalid("reviewed signing page fields: %v", err)
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
