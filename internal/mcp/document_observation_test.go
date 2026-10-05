// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"testing"
	"time"
)

func TestDocumentObservationUsesPreciseMCPWireTimestamp(t *testing.T) {
	stamp := time.Date(2026, 10, 5, 10, 0, 0, 123456000, time.UTC)
	doc := &generated.Document{UpdatedAt: pgtype.Timestamptz{Time: stamp, Valid: true}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if err := checkDocumentObservation(doc, wire.UpdatedAt); err != nil {
		t.Fatalf("MCP timestamp not usable: %v", err)
	}
	for _, value := range []string{"", "invalid", stamp.Add(-time.Microsecond).Format(time.RFC3339Nano), stamp.Format(time.RFC3339)} {
		err := checkDocumentObservation(doc, value)
		if err == nil {
			t.Fatalf("missing/stale observation accepted %q", value)
		}
		if strings.Contains(err.Error(), value) && value != "" && value != "invalid" {
			t.Fatal("observation leaked in error")
		}
	}
}
