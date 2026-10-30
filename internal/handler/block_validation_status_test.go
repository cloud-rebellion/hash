// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"net/http"
	"testing"
)

func TestCanonicalBlockValidationReturnsClientError(t *testing.T) {
	cases := []*blocks.Tree{
		nil,
		{Version: blocks.SchemaVersion + 1},
		{Version: 1, Blocks: []blocks.Block{{ID: "duplicate", Type: blocks.TypeParagraph}, {ID: "duplicate", Type: blocks.TypeParagraph}}},
		{Version: 1, Blocks: []blocks.Block{{ID: "unknown", Type: "unknown"}}},
	}
	for _, tree := range cases {
		err := blocks.Validate(tree)
		if err == nil {
			t.Fatal("fixture did not fail canonical validation")
		}
		if got := mapMutationStatus(fmt.Errorf("append rejected: %w", err)); got != http.StatusBadRequest {
			t.Fatalf("%v mapped to %d", err, got)
		}
	}
	if got := mapMutationStatus(errors.New("database unavailable")); got != http.StatusInternalServerError {
		t.Fatal("internal failure hidden as invalid input")
	}
}

func TestBlockMutationUntaggedNativeFailureRemainsUnavailable(t *testing.T) {
	// A server/no-row cause alone does not prove a completed fixed write.
	// These errors must not jump ahead of the native availability boundary.
	for _, cause := range []error{pgx.ErrNoRows, &pgconn.PgError{Code: "P0001"}, pdfadmission.ErrApplicationSessionUnknownV1} {
		err := errors.Join(pdfadmission.ErrApplicationSessionV1, cause)
		if got := mapMutationStatus(err); got != http.StatusServiceUnavailable {
			t.Fatalf("untagged native failure mapped to%d, want503", got)
		}
	}
}
