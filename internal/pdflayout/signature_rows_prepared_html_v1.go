// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdflayout

import (
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

// Same original signature/party/field checks over an already native-owned and
// validated exact HTML tuple; this helper grants no resource or mutation authority.
func ValidateSignatureRowsPreparedHTMLV1(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, signatures []*generated.Signature, pageCount int, prepared *htmlsource.RevisionValidationV1) error {
	if _, err := RequiredRolesPreparedHTMLV1(doc, rows, fields, pageCount, prepared); err != nil {
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
