// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"bytes"
	"context"
	"testing"
)

// Invalid explicit selections stop before configuration/SQL. Real codec,
// measurement and native retirement acceptance belongs to the PG suite.
func TestCatalogMeasureRequiresOneExplicitSourceV1(t *testing.T) {
	for _, args := range [][]string{nil, {"-kind", "plan"}, {"-kind", "plan", "-id", "00000000-0000-0000-0000-000000000000"}, {"-kind", "plan", "-id", "11111111-1111-4111-8111-111111111111", "-org", "22222222-2222-4222-8222-222222222222"}, {"-kind", "eidas-rule", "-id", "11111111-1111-4111-8111-111111111111"}, {"-kind", "all", "-id", "11111111-1111-4111-8111-111111111111"}, {"-kind", "plan", "-id", "11111111-1111-4111-8111-111111111111", "extra"}} {
		var out bytes.Buffer
		if err := runCatalogMeasureV1(context.Background(), args, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid selection attempted or reported measurement", args)
		}
	}
}
