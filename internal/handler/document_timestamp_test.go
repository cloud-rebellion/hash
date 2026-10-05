// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestDocumentResponsePreservesDistinctSubsecondUpdates(t *testing.T) {
	original := time.Date(2026, 10, 5, 10, 0, 0, 123456000, time.FixedZone("local", 2*60*60))
	first := toDocumentResponse(&generated.Document{UpdatedAt: pgtype.Timestamptz{Time: original, Valid: true}})
	second := toDocumentResponse(&generated.Document{UpdatedAt: pgtype.Timestamptz{Time: original.Add(time.Microsecond), Valid: true}})
	if first.UpdatedAt == second.UpdatedAt {
		t.Fatal("distinct database timestamps collapsed")
	}
	decoded, err := time.Parse(time.RFC3339Nano, first.UpdatedAt)
	if err != nil || !decoded.Equal(original) {
		t.Fatalf("timestamp changed: %q %v", first.UpdatedAt, err)
	}
	if first.UpdatedAt != "2026-10-05T08:00:00.123456Z" {
		t.Fatalf("timestamp not UTC/microsecond faithful: %q", first.UpdatedAt)
	}
}
