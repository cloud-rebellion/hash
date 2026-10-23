// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendmentauthoring

import (
	"github.com/bright-interaction/hash/internal/amendments"
	"testing"
)

func TestLaterAmendmentResultCopyCannotOutliveItsActualConsumerV1(t *testing.T) {
	original := newResultV1()
	original.state.value = amendments.OutcomeV1{State: "unknown", ReconciliationRequired: true}
	if _, e := original.MarshalJSON(); e != nil {
		t.Fatal(e)
	}
	copy := *original
	copy.CloseConsumerV1()
	if _, e := original.MarshalJSON(); e == nil {
		t.Fatal("copied result released the actual consumer but original still serialized")
	}
	original.CloseConsumerV1()
}
