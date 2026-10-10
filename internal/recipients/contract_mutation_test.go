// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recipients

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

func TestReviewedContractGenericRecipientEditPreservesPrintedEmailCase(t *testing.T) {
	input, doc, rows := testfixture.HTMLContract(t)
	input.Values["provider_email"] = "Provider@Example.Test"
	variables, err := json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	doc.VariablesJson = variables
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	rows[0].Email = input.Values["provider_email"]
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		t.Fatal(err)
	}
	values := Values{Name: rows[0].Name, Email: rows[0].Email, Role: rows[0].Role, Locale: "sv", OrderIndex: 3}
	if err := validateContractRecipientUpdate(parties, rows[0], values); err != nil {
		t.Fatalf("unchanged printed mixed-case address refused: %v", err)
	}
}

func TestReviewedContractRecipientRoutingEditsPreservePrintedIdentity(t *testing.T) {
	_, doc, rows := testfixture.HTMLContract(t)
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		t.Fatal(err)
	}
	existing := rows[0]
	values := Values{Name: existing.Name, Email: existing.Email, Role: existing.Role, Locale: "sv", OrderIndex: 3}
	if err := validateContractRecipientUpdate(parties, existing, values); err != nil {
		t.Fatalf("routing-only edit refused: %v", err)
	}
	for _, scenario := range []string{"name", "email", "role", "substituted_id", "corrupt_current_identity"} {
		t.Run(scenario, func(t *testing.T) {
			current, changed := *existing, values
			switch scenario {
			case "name":
				changed.Name = "Different representative"
			case "email":
				changed.Email = "different@example.test"
			case "role":
				changed.Role = "signer"
			case "substituted_id":
				current.ID = uuid.New()
			case "corrupt_current_identity":
				current.Name = "Different existing representative"
			}
			err := validateContractRecipientUpdate(parties, &current, changed)
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Field != "contract_party" {
				t.Fatalf("unsafe edit = %v", err)
			}
		})
	}
}

func TestLegacyRecipientIdentityEditsRemainAvailable(t *testing.T) {
	if err := validateContractRecipientUpdate(nil, &generated.Recipient{ID: uuid.New()}, Values{Name: "Changed", Email: "changed@example.test", Role: "signer"}); err != nil {
		t.Fatalf("legacy edit = %v", err)
	}
}
