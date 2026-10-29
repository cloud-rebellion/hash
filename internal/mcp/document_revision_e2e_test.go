// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestMCPReplacementRevisionEvidenceE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Native authoring creates immutable history. Own a complete disposable
	// database so teardown never deletes history or touches another package's
	// fixture rows in the supplied parent database.
	parent := cfg.ConnConfig.Copy()
	admin, err := pgx.ConnectConfig(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	database := "hash_mcp_revision_e2e_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil { //nolint:rawsql -- exact unique synthetic database
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		admin, err := pgx.ConnectConfig(cleanup, parent)
		if err != nil {
			t.Error("connect revision fixture teardown", err)
			return
		}
		defer admin.Close(cleanup)
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil { //nolint:rawsql -- exact database created above, after runtime and pool close
			t.Error("drop revision fixture database", err)
		}
	})
	cfg.ConnConfig.Database = database
	cfg.ConnConfig.RuntimeParams["application_name"] = "hash_mcp_revision_" + uuid.NewString()
	db := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { _ = db.Close() })
	if err := mdb.RunMigrationsContext(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "MCP revision", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@mcp.test", Name: "Owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, limits, int64(pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		err := runtime.CloseV1(cleanup)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.HTMLInputProducers != 0 || pending.HTMLCanonicalConsumers != 0 || pending.CatalogMaintenance != 0 || pending.ObserverSessions != observers {
			t.Errorf("revision runtime retained work: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("revision observer cleanup debt falsely resolved: %v", err)
		} else if observers == 0 && err != nil {
			t.Error(err)
		}
		snapshot, snapshotErr := runtime.SnapshotV1(org.ID)
		if snapshotErr != nil || snapshot.Global != (workguard.VectorV1{SQLSessions: int64(observers)}) || snapshot.GlobalGrants != int64(observers) {
			t.Errorf("revision work leaked or observer debt lost: %+v err=%v", snapshot, snapshotErr)
		}
	})
	// Explicitly prepare only the seeded operator plan through its real M95
	// producer. No fixture inserts or repairs measurement/authority rows.
	var plan uuid.UUID
	var serverVersion int32
	if err := pool.QueryRow(ctx, "SELECT id,current_setting('server_version_num')::integer FROM billing_plans WHERE slug='pro'").Scan(&plan, &serverVersion); err != nil {
		t.Fatal(err)
	}
	owner, err := runtime.SessionsV1().ControlledMeasurePlanSourceV1(ctx, plan)
	if owner != nil {
		t.Cleanup(func() {
			owner.CloseConsumerV1()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := owner.CloseV1(cleanup); err != nil {
				t.Error("revision plan source cleanup", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("actual revision plan preparation", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "plan" || receipt.SourceID != plan || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != serverVersion || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
		t.Fatal("actual revision plan measurement receipt", err)
	}
	owner.CloseConsumerV1()
	if err := owner.CloseV1(ctx); err != nil {
		t.Fatal("actual revision plan owner close", err)
	}
	deps := Deps{Pool: pool, Queries: q, Audit: audit.New(q, pool), Versions: versions.New(q), PDFCreationSessions: runtime.SessionsV1(), Billing: billing.NewOperator(q, []config.OperatorEntitlement{{OrgID: org.ID, PlanSlug: "pro", ReviewRef: "synthetic revision qualification"}})}
	server := New(deps)
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{OrgID: org.ID, UserID: user.ID, Name: "Revision fixture key", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:authoring"}}); err != nil {
		t.Fatal(err)
	}
	// Admit through genuine PgVerifier middleware. Public context identity is
	// insufficient for the original transaction receipt required by authoring.
	admitted := auth.RequireAPIKey(&auth.PgVerifier{Queries: q})(server.Handler())
	call := func(t *testing.T, name string, args map[string]any, wantError bool) json.RawMessage {
		t.Helper()
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body))).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mint.Plaintext)
		response := httptest.NewRecorder()
		admitted.ServeHTTP(response, req)
		var reply struct {
			Result struct {
				IsError bool                    `json:"isError"`
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reply) != nil || len(reply.Error) != 0 || reply.Result.IsError != wantError {
			t.Fatalf("tool %s status=%d wantError=%v %s", name, response.Code, wantError, response.Body.String())
		}
		if !wantError && len(reply.Result.Content) != 1 {
			t.Fatalf("tool %s returned no single actual result: %s", name, response.Body.String())
		}
		if wantError {
			return nil
		}
		return json.RawMessage(reply.Result.Content[0].Text)
	}
	tree := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	var doc generated.Document
	if err := json.Unmarshal(call(t, "create_document", map[string]any{"name": "MCP", "source_kind": "blocks", "blocks_json": tree, "variables_json": map[string]string{}}, false), &doc); err != nil || doc.ID == uuid.Nil {
		t.Fatal("actual native revision document creation", err)
	}
	targetVersion, err := q.GetLatestDocumentVersionNo(ctx, doc.ID)
	if err != nil || targetVersion != 1 {
		t.Fatal("actual native creation snapshot missing", err)
	}
	old := doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
	call(t, "set_variables", map[string]any{"document_id": doc.ID.String(), "expected_updated_at": old, "variables": map[string]string{"state": "new"}}, false)
	cases := map[string]map[string]any{
		"append_block":             {"block": map[string]string{"id": "q", "type": "paragraph", "text": "appended"}},
		"reorder_blocks":           {"block_ids": []string{"q", "p"}},
		"add_signature_field":      {"recipient_role": "client"},
		"delete_block":             {"block_id": "q"},
		"update_block":             {"block_id": "p", "block": map[string]string{"id": "p", "type": "paragraph", "text": "replacement"}},
		"set_document_blocks":      {"blocks_json": tree},
		"import_html":              {"html": "<p>Imported</p>"},
		"import_markdown":          {"markdown": "Imported"},
		"set_variables":            {"variables": map[string]string{"state": "replacement"}},
		"restore_document_version": {"target_version": targetVersion},
	}
	for _, name := range []string{"set_document_blocks", "import_html", "import_markdown", "set_variables", "restore_document_version", "update_block", "append_block", "reorder_blocks", "add_signature_field", "delete_block"} {
		args := cases[name]
		t.Run(name, func(t *testing.T) {
			current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
			if err != nil {
				t.Fatal(err)
			}
			counts := func() (int, int) {
				var v, e int
				if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
					t.Fatal(err)
				}
				return v, e
			}
			v, e := counts()
			args["document_id"] = doc.ID.String()
			args["expected_updated_at"] = old
			call(t, name, args, true)
			after, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
			if err != nil {
				t.Fatal(err)
			}
			av, ae := counts()
			if av != v || ae != e || string(after.BlocksJson) != string(current.BlocksJson) || string(after.VariablesJson) != string(current.VariablesJson) || !after.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
				t.Fatal("stale tool mutated content/evidence")
			}
			args["expected_updated_at"] = current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
			call(t, name, args, false)
			av, ae = counts()
			if av <= v || ae <= e {
				t.Fatal("fresh tool missing evidence")
			}
		})
	}
}
