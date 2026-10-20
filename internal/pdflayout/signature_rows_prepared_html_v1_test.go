// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdflayout

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"testing"
)

func TestPreparedSignatureRowsPreserveHistoricalPolicyV1(t *testing.T) {
	for _, name := range []string{"valid", "missing", "foreign", "other_field", "duplicate", "unsigned", "optional"} {
		t.Run(name, func(t *testing.T) {
			doc, rows, fields := lifecycleFixture()
			sigs := []*generated.Signature{{ID: uuid.New(), DocumentID: doc.ID, RecipientID: rows[0].ID, FieldID: fields[0].ID}, {ID: uuid.New(), DocumentID: doc.ID, RecipientID: rows[1].ID, FieldID: fields[1].ID}}
			switch name {
			case "missing":
				sigs = sigs[:1]
			case "foreign":
				sigs[1].DocumentID = uuid.New()
			case "other_field":
				sigs[1].FieldID = fields[0].ID
			case "duplicate":
				sigs[1].RecipientID = sigs[0].RecipientID
			case "unsigned":
				rows[1].Status = "pending"
			case "optional":
				fields[1].Required = false
			}
			prepared, err := htmlsource.NewRevisionValidationV1(doc)
			if err != nil {
				t.Fatal(err)
			}
			old := ValidateSignatureRows(doc, rows, fields, sigs, 1)
			got := ValidateSignatureRowsPreparedHTMLV1(doc, rows, fields, sigs, 1, prepared)
			if (old == nil) != (got == nil) || (old != nil && old.Error() != got.Error()) {
				t.Fatalf("historical signature policy changed: old=%v prepared=%v", old, got)
			}
		})
	}
	doc, rows, fields := lifecycleFixture()
	if err := ValidateSignatureRowsPreparedHTMLV1(doc, rows, fields, nil, 1, nil); err == nil {
		t.Fatal("missing exact prepared source accepted")
	}
}
