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
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReplacementImportRejectsCapacityBeforeParsingArguments(t *testing.T) {
	org := uuid.New()
	release, err := importguard.Shared.Acquire(org)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	factory, coordinator, ctx := replacementImportInputFixtureV1(t, org)
	server := New(Deps{PDFCreationSessions: factory})
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	req := httptest.NewRequest("POST", "/mcp", nil).WithContext(ctx)
	for _, name := range []string{"import_html", "import_markdown"} {
		result, err := server.tools[name].Handler(req, []byte("invalid JSON"))
		func() {
			defer closeReplacementImportResultV1(t, result)
			if !errors.Is(err, importguard.ErrBusy) {
				t.Fatalf("%s capacity gate: %v", name, err)
			}
		}()
		assertReplacementImportInputDrainedV1(t, factory, coordinator, org)
	}
}

func TestReplacementImportScannerUnavailableBeforePersistence(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := base
	defer malwarescan.Configure(context.Background(), "", "development")
	if err := malwarescan.Configure(ctx, "", "production"); !errors.Is(err, malwarescan.ErrUnavailable) {
		t.Fatal(err)
	}
	org := uuid.New()
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	factory, coordinator, requestCtx := replacementImportInputFixtureV1(t, org)
	ctx = context.WithValue(requestCtx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	server := New(Deps{PDFCreationSessions: factory})
	req := httptest.NewRequest("POST", "/mcp", nil).WithContext(ctx)
	for _, input := range []struct{ name, key string }{{"import_html", "html"}, {"import_markdown", "markdown"}} {
		raw, err := json.Marshal(map[string]string{"document_id": uuid.New().String(), "expected_updated_at": "2026-10-05T00:00:00Z", input.key: "content"})
		if err != nil {
			t.Fatal(err)
		}
		result, err := server.tools[input.name].Handler(req, raw)
		func() {
			defer closeReplacementImportResultV1(t, result)
			if !errors.Is(err, malwarescan.ErrUnavailable) {
				t.Fatalf("%s scanner gate: %v", input.name, err)
			}
		}()
		release, err := importguard.Shared.Acquire(org)
		if err != nil {
			t.Fatal("rejection leaked admission", err)
		}
		release()
		assertReplacementImportInputDrainedV1(t, factory, coordinator, org)
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

// Genuine registered request-only factory: invalid/scanner-refused imports must
// never dispatch SQL, so the normal direct constructor's synthetic port9 config
// is intentionally never opened. No fake transaction/source/measurement exists.
func replacementImportInputFixtureV1(t *testing.T, org uuid.UUID) (*pdfadmission.ApplicationSessionFactoryV1, *workguard.CoordinatorV1, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	v := workguard.VectorV1{ParentBytes: 64 << 20}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	work, err := pdfadmission.NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig("postgres://synthetic:synthetic@127.0.0.1:9/synthetic?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	factory, err := pdfadmission.NewApplicationSessionFactoryV1(config, work, pdfadmission.ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		assertReplacementImportInputDrainedV1(t, factory, c, org)
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := factory.CloseV1(cleanup); err != nil {
			t.Error(err)
		}
	})
	return factory, c, ctx
}
func closeReplacementImportResultV1(t *testing.T, result any) {
	t.Helper()
	owner, ok := result.(interface{ CloseConsumerV1() })
	if !ok {
		t.Fatal("actual refused tool result lost its real input consumer")
	}
	owner.CloseConsumerV1()
	owner.CloseConsumerV1()
}
func assertReplacementImportInputDrainedV1(t *testing.T, f *pdfadmission.ApplicationSessionFactoryV1, c *workguard.CoordinatorV1, org uuid.UUID) {
	t.Helper()
	pending := f.PendingV1()
	if pending.HTMLInputProducers != 0 || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 0 || pending.HTMLAdmissions != 0 {
		t.Fatal("original import refusal leaked real producer or dispatched SQL", pending)
	}
	snapshot := c.SnapshotV1(org)
	if snapshot.Global != (workguard.VectorV1{}) || snapshot.Organisation != (workguard.VectorV1{}) || snapshot.GlobalGrants != 0 || snapshot.OrganisationGrants != 0 {
		t.Fatal("actual refused import source did not retire at result/error last use", snapshot)
	}
}
