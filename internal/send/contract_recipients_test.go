// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"testing"

	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

func TestReviewedContractSendRequiresBothPinnedRepresentatives(t *testing.T) {
	_, doc, rows := testfixture.HTMLContract(t)
	if err := validateSendRecipients(doc, nil, rows); err != nil {
		t.Fatalf("valid reviewed representatives refused: %v", err)
	}
	for _, scenario := range []string{"missing_provider", "missing_customer", "substituted_uuid", "changed_name", "acknowledgement_downgrade"} {
		t.Run(scenario, func(t *testing.T) {
			_, doc, rows := testfixture.HTMLContract(t)
			switch scenario {
			case "missing_provider":
				rows = rows[1:]
			case "missing_customer":
				rows = rows[:1]
			case "substituted_uuid":
				rows[0].ID = uuid.New()
			case "changed_name":
				rows[0].Name = "Different provider representative"
			case "acknowledgement_downgrade":
				doc.RequiresSignature = false
			}
			if err := validateSendRecipients(doc, nil, rows); err == nil {
				t.Fatal("send admitted a changed or missing intended party")
			}
		})
	}
}
