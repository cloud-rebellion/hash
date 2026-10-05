// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
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
