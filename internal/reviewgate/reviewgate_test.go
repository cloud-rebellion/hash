// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package reviewgate

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMessageFindsGateThroughWrappersAndNothingElse(t *testing.T) {
	gate := &pgconn.PgError{Code: "23514", Message: "Signing document requires a fresh human review before sending"}
	if m, ok := Message(fmt.Errorf("session: %w", fmt.Errorf("attach: %w", gate))); !ok || m == "" {
		t.Fatal("wrapped signing gate not classified")
	}
	if _, ok := Message(&pgconn.PgError{Code: "23514", Message: "Replaced PDF requires review before sending"}); !ok {
		t.Fatal("replaced PDF gate not classified")
	}
	for _, e := range []error{nil, fmt.Errorf("x"), &pgconn.PgError{Code: "23514", Message: "other check"}, &pgconn.PgError{Code: "40001", Message: "Signing document requires a fresh human review before sending"}} {
		if _, ok := Message(e); ok {
			t.Fatalf("misclassified %v", e)
		}
	}
}
