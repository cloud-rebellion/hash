// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestVersionProjectionPreservesPublicMetadataAndOmitsHTMLSource(t *testing.T) {
	id, docID, orgID, authorID, parentID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	at := time.Date(2026, time.October, 10, 9, 30, 12, 123000000, time.UTC)
	for _, fixture := range []struct {
		name       string
		sourceKind string
		blocks     json.RawMessage
		source     json.RawMessage
	}{
		{name: "blocks", sourceKind: "blocks", blocks: json.RawMessage(`{"version":1,"blocks":[{"id":"scope","type":"paragraph","text":"Saved scope"}]}`)},
		{name: "static PDF", sourceKind: "pdf"},
		{name: "HTML-derived PDF", sourceKind: "pdf", source: json.RawMessage(`{"master":{"html":"PRIVATE_MASTER","css":"PRIVATE_CSS","assets":[{"data_base64":"PRIVATE_ASSET"}]},"default_values":{"customer":"PRIVATE_DEFAULT"},"pdf_key":"PRIVATE_STORAGE_KEY","pdf_version_id":"PRIVATE_OBJECT_VERSION"}`)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			version := generated.DocumentVersion{
				ID: id, DocumentID: docID, OrgID: orgID, VersionNo: 3,
				Name: "Reviewed contract", SourceKind: fixture.sourceKind,
				BlockTreeJson: fixture.blocks, VariablesJson: json.RawMessage(`{"customer":"Printed AB"}`),
				CreatedBy: pgtype.UUID{Bytes: authorID, Valid: true}, CreatedVia: "human",
				CreatedAt: pgtype.Timestamptz{Time: at, Valid: true},
				ParentID:  pgtype.UUID{Bytes: parentID, Valid: true}, SchemaVersion: 1,
				Summary: "Customer reviewed scope", HtmlSourceJson: fixture.source,
				HtmlMaterializationID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
			}
			before, err := json.Marshal(version)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(toVersionDTO(&version))
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err := json.Unmarshal(wire, &actual); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"id": id.String(), "document_id": docID.String(), "version_no": float64(3),
				"name": "Reviewed contract", "source_kind": fixture.sourceKind,
				"variables_json": map[string]any{"customer": "Printed AB"},
				"created_by":     authorID.String(), "created_via": "human", "created_at": "2026-10-10T09:30:12.123Z",
				"parent_id": parentID.String(), "schema_version": float64(1), "summary": "Customer reviewed scope",
			}
			if len(fixture.blocks) != 0 {
				var blocks any
				if err := json.Unmarshal(fixture.blocks, &blocks); err != nil {
					t.Fatal(err)
				}
				want["blocks_json"] = blocks
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("public version fields changed: got %#v, want %#v", actual, want)
			}
			for _, private := range []string{"html_source_json", "PRIVATE_MASTER", "PRIVATE_CSS", "PRIVATE_ASSET", "PRIVATE_DEFAULT", "PRIVATE_STORAGE_KEY", "PRIVATE_OBJECT_VERSION"} {
				if bytes.Contains(wire, []byte(private)) {
					t.Fatalf("public version disclosed %s", private)
				}
			}
			after, err := json.Marshal(version)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("public projection changed the retained internal version")
			}
		})
	}
}

func TestVersionProjectionOmitsUnsetOptionalMetadata(t *testing.T) {
	version := generated.DocumentVersion{VariablesJson: json.RawMessage(`{}`), SourceKind: "pdf"}
	wire, err := json.Marshal(toVersionDTO(&version))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blocks_json", "created_by", "parent_id", "summary", "html_source_json"} {
		if _, present := fields[name]; present {
			t.Fatalf("unset %s was included in the public version", name)
		}
	}
}
