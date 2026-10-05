// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/malwarescan"

	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/google/uuid"
	"net/http/httptest"
	"testing"
)

func TestReplacementImportRejectsCapacityBeforeParsingArguments(t *testing.T) {
	org := uuid.New()
	release, err := importguard.Shared.Acquire(org)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	server := New(Deps{})
	ctx := context.WithValue(context.Background(), auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	req := httptest.NewRequest("POST", "/mcp", nil).WithContext(ctx)
	for _, name := range []string{"import_html", "import_markdown"} {
		if _, err := server.tools[name].Handler(req, []byte("invalid JSON")); !errors.Is(err, importguard.ErrBusy) {
			t.Fatalf("%s capacity gate: %v", name, err)
		}
	}
}

func TestReplacementImportScannerUnavailableBeforePersistence(t *testing.T) {
	ctx := context.Background()
	defer malwarescan.Configure(ctx, "", "development")
	if err := malwarescan.Configure(ctx, "", "production"); !errors.Is(err, malwarescan.ErrUnavailable) {
		t.Fatal(err)
	}
	org := uuid.New()
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	server := New(Deps{})
	req := httptest.NewRequest("POST", "/mcp", nil).WithContext(ctx)
	for _, input := range []struct{ name, key string }{{"import_html", "html"}, {"import_markdown", "markdown"}} {
		raw, err := json.Marshal(map[string]string{"document_id": uuid.New().String(), "expected_updated_at": "2026-10-05T00:00:00Z", input.key: "content"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.tools[input.name].Handler(req, raw); !errors.Is(err, malwarescan.ErrUnavailable) {
			t.Fatalf("%s scanner gate: %v", input.name, err)
		}
		release, err := importguard.Shared.Acquire(org)
		if err != nil {
			t.Fatal("rejection leaked admission", err)
		}
		release()
	}
}

func TestCanonicalTreeMutationSchemasRequireObservation(t *testing.T) {
	server := New(Deps{})
	for _, name := range []string{"set_document_blocks", "import_html", "import_markdown", "append_block", "update_block", "delete_block", "reorder_blocks", "add_signature_field"} {
		schema := server.tools[name].InputSchema
		raw, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, field := range wire.Required {
			if field == "expected_updated_at" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s schema permits unobserved mutation", name)
		}
	}
}
