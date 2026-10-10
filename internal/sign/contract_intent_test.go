// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"testing"

	"github.com/bright-interaction/hash/internal/testfixture"
)

func TestReviewedContractSigningIntentCannotBecomeAcknowledgement(t *testing.T) {
	_, doc, _ := testfixture.HTMLContract(t)
	if err := requireSESTypedSignature(doc); err != nil {
		t.Fatalf("signature intent refused: %v", err)
	}
	if err := validateFinalizationMode(doc, "signature"); err != nil {
		t.Fatalf("signature finalization refused: %v", err)
	}
	doc.RequiresSignature = false
	if err := requireSESTypedSignature(doc); err == nil {
		t.Fatal("sign/accept tier guard admitted downgraded contract intent")
	}
	if err := validateFinalizationMode(doc, "acknowledgement"); err == nil {
		t.Fatal("acknowledgement finalization admitted downgraded contract intent")
	}
}

func TestReviewedContractFinalizationIntentRetainsSourceAndCeremony(t *testing.T) {
	for _, scenario := range []string{"signature", "intent_acknowledgement", "document_acknowledgement", "printed_identity_drift"} {
		t.Run(scenario, func(t *testing.T) {
			_, doc, _ := testfixture.HTMLContract(t)
			timing, intent, _ := finalizationFixture(t)
			doc.Status = timing.Status
			doc.SentAt, doc.CompletionEffectiveAt = timing.SentAt, timing.CompletionEffectiveAt
			doc.CompletionEffectiveAtBound, doc.FinalizationRetainUntil = true, timing.FinalizationRetainUntil
			intent.DocumentID, intent.OrgID = doc.ID, doc.OrgID
			switch scenario {
			case "intent_acknowledgement":
				intent.Mode = "acknowledgement"
			case "document_acknowledgement":
				doc.RequiresSignature = false
			case "printed_identity_drift":
				doc.VariablesJson = []byte(`{"provider_name":"Different representative"}`)
			}
			err := validateFinalizationIntent(doc, intent)
			if scenario == "signature" && err != nil {
				t.Fatalf("complete signature intent refused: %v", err)
			}
			if scenario != "signature" && err == nil {
				t.Fatalf("changed contract intent accepted: %s", scenario)
			}
		})
	}
}
