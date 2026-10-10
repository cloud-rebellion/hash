// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

func TestReviewedHTMLContractCannotLoseAnIntendedPartyAndItsField(t *testing.T) {
	_, doc, rows := testfixture.HTMLContract(t)
	fields := testfixture.ContractSignatureFields(doc, rows)
	roles, err := RequiredRoles(doc, rows, fields, 1)
	if err != nil || !reflect.DeepEqual(roles, []string{"customer", "provider"}) {
		t.Fatalf("complete contract roles=%v error=%v", roles, err)
	}
	for _, scenario := range []string{"deleted_provider_and_field", "deleted_customer_and_field", "replacement_uuid", "different_name", "different_email", "third_signer"} {
		t.Run(scenario, func(t *testing.T) {
			_, doc, rows := testfixture.HTMLContract(t)
			switch scenario {
			case "deleted_provider_and_field":
				rows = rows[1:]
			case "deleted_customer_and_field":
				rows = rows[:1]
			case "replacement_uuid":
				rows[0].ID = uuid.New()
			case "different_name":
				rows[0].Name = "Different representative"
			case "different_email":
				rows[0].Email = "different@example.test"
			case "third_signer":
				rows = append(rows, &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: "third", Name: "Third representative", Email: "third@example.test"})
			}
			// Every remaining row has a valid freshly assigned field: the independent
			// committed party set, rather than incidental field errors, must refuse it.
			fields := testfixture.ContractSignatureFields(doc, rows)
			if _, err := RequiredRoles(doc, rows, fields, 1); err == nil {
				t.Fatal("changed intended party set was accepted")
			}
		})
	}
}
