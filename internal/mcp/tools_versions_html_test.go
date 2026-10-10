// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHTMLMaterializationsCannotClaimAnEmptyBlockDiff(t *testing.T) {
	for _, doc := range []*generated.Document{
		{SourceKind: "pdf", HtmlSourceJson: json.RawMessage(`{"schema_version":1}`)},
		{SourceKind: "pdf", HtmlCurrentSourceJson: json.RawMessage(`{"schema_version":1}`)},
		{SourceKind: "pdf", HtmlCurrentMaterializationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}},
	} {
		if err := requireDocumentBlockDiff(doc); err == nil || !strings.Contains(err.Error(), "declared-source and exact-PDF history") {
			t.Fatal("HTML artifact was treated as an empty block diff")
		}
	}
	for _, sourceKind := range []string{"blocks", "pdf"} {
		if err := requireDocumentBlockDiff(&generated.Document{SourceKind: sourceKind}); err != nil {
			t.Fatalf("legacy %s diff behavior changed: %v", sourceKind, err)
		}
	}
	if requireDocumentBlockDiff(nil) == nil {
		t.Fatal("missing document was admitted to diff")
	}
}
